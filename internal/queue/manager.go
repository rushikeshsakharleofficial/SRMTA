// Package queue implements the multi-spool queue architecture for SRMTA.
// Manages six spool tiers: incoming, active, deferred, retry, dead-letter, failed.
// Supports domain-based bucketing, priority delivery, queue sharding, and crash recovery.
package queue

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
	"github.com/srmta/srmta/internal/store"
)

// SpoolType represents the type of queue spool.
type SpoolType string

const (
	SpoolIncoming   SpoolType = "incoming"
	SpoolActive     SpoolType = "active"
	SpoolDeferred   SpoolType = "deferred"
	SpoolRetry      SpoolType = "retry"
	SpoolDeadLetter SpoolType = "dead-letter"
	SpoolFailed     SpoolType = "failed"
)

const shardDirFmt = "shard-%03d"

// Message represents a queued email message.
type Message struct {
	ID         string    `json:"id"`
	Sender     string    `json:"sender"`
	Recipients []string  `json:"recipients"`
	Domain     string    `json:"domain"` // Primary recipient domain
	Data       []byte    `json:"-"`      // Raw message data (stored in file)
	DataPath   string    `json:"data_path"`
	Size       int64     `json:"size"`
	Priority   int       `json:"priority"` // 1 = highest, 5 = lowest
	Spool      SpoolType `json:"spool"`
	RemoteAddr string    `json:"remote_addr"`
	RetryCount int       `json:"retry_count"`
	NextRetry  time.Time `json:"next_retry"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastError  string    `json:"last_error,omitempty"`
	ShardID    int       `json:"shard_id"`
}

// Manager orchestrates the multi-spool queue system.
type Manager struct {
	cfg        config.QueueConfig
	redis      *store.RedisStore
	db         store.Database
	logger     *logging.Logger
	retryIntvl []time.Duration
	spoolDirs  map[SpoolType]string
	msgChan    chan *Message // Channel for incoming messages to process
	depth      int64         // atomic: total queue depth
	mu         sync.RWMutex
}

// NewManager creates a new queue manager and initializes spool directories.
func NewManager(cfg config.QueueConfig, redis *store.RedisStore, db store.Database, logger *logging.Logger) (*Manager, error) {
	// Parse retry intervals
	intervals, err := cfg.ParseRetryIntervals()
	if err != nil {
		return nil, fmt.Errorf("invalid retry intervals: %w", err)
	}

	m := &Manager{
		cfg:        cfg,
		redis:      redis,
		db:         db,
		logger:     logger,
		retryIntvl: intervals,
		spoolDirs:  make(map[SpoolType]string),
		msgChan:    make(chan *Message, cfg.ProcessingWorkers*10),
	}

	// Initialize spool directories
	spools := []SpoolType{SpoolIncoming, SpoolActive, SpoolDeferred, SpoolRetry, SpoolDeadLetter, SpoolFailed}
	for _, spool := range spools {
		dir := filepath.Join(cfg.SpoolDir, string(spool))
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create spool dir %s: %w", dir, err)
		}
		m.spoolDirs[spool] = dir

		// Create shard subdirectories for high-volume deployments
		for i := 0; i < cfg.ShardCount; i++ {
			shardDir := filepath.Join(dir, fmt.Sprintf(shardDirFmt, i))
			if err := os.MkdirAll(shardDir, 0750); err != nil {
				return nil, fmt.Errorf("failed to create shard dir %s: %w", shardDir, err)
			}
		}
	}

	return m, nil
}

// Enqueue adds a new message to the incoming spool.
func (m *Manager) Enqueue(sender string, recipients []string, data []byte, remoteAddr string) (string, error) {
	if len(recipients) == 0 {
		return "", fmt.Errorf("at least one recipient is required")
	}

	// Check queue depth limit
	if atomic.LoadInt64(&m.depth) >= m.cfg.MaxQueueDepth {
		return "", fmt.Errorf("queue depth limit exceeded (%d)", m.cfg.MaxQueueDepth)
	}

	// Generate message ID
	msgID := m.generateMessageID()

	// Determine primary domain and shard
	domain := m.extractDomain(recipients[0])
	shardID := m.domainShard(domain)

	msg := &Message{
		ID:         msgID,
		Sender:     sender,
		Recipients: recipients,
		Domain:     domain,
		Data:       data,
		Size:       int64(len(data)),
		Priority:   3, // Default priority
		Spool:      SpoolIncoming,
		RemoteAddr: remoteAddr,
		RetryCount: 0,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(72 * time.Hour), // Default 3-day expiry
		ShardID:    shardID,
	}

	// Write message data to spool file
	if err := m.writeToSpool(msg); err != nil {
		return "", fmt.Errorf("failed to write to spool: %w", err)
	}

	// Write journal entry for crash recovery
	if m.cfg.JournalEnabled {
		m.writeJournal("enqueue", msg)
	}

	// Update Redis queue state
	if m.redis != nil {
		m.redis.EnqueueMessage(msg.ID, msg.Domain, msg.Priority)
	}

	atomic.AddInt64(&m.depth, 1)
	metrics.QueueDepth.WithLabelValues(string(SpoolIncoming)).Inc()
	metrics.QueueEnqueued.Inc()

	m.logger.Debug("Message enqueued",
		"id", msgID,
		"sender", logging.MaskEmail(sender),
		"recipients", len(recipients),
		"domain", domain,
		"shard", shardID,
		"size", len(data),
	)

	// Notify workers to process this message immediately
	select {
	case m.msgChan <- msg:
	default:
		m.logger.Warn("msgChan is full, message will be processed on next queue scan", "id", msgID)
	}

	return msgID, nil
}

// Start begins the queue processing loop.
func (m *Manager) Start(ctx context.Context) {
	m.logger.Info("Queue manager starting",
		"workers", m.cfg.ProcessingWorkers,
		"shards", m.cfg.ShardCount,
	)

	// Rehydrate queue from disk on startup
	m.rehydrate()

	// Start processing workers
	var wg sync.WaitGroup
	for i := 0; i < m.cfg.ProcessingWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			m.processLoop(ctx, workerID)
		}(i)
	}

	// Start retry scanner
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.retryScanLoop(ctx)
	}()

	// Start dead-letter scanner
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.deadLetterScanLoop(ctx)
	}()

	<-ctx.Done()
	close(m.msgChan)
	wg.Wait()
	m.logger.Info("Queue manager stopped")
}

// processLoop is the main worker loop that processes messages from the channel.
func (m *Manager) processLoop(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-m.msgChan:
			if !ok {
				return
			}
			// Move from incoming to active
			if err := m.moveSpool(msg, SpoolActive); err != nil {
				m.logger.Error("Failed to activate message", "id", msg.ID, "error", err)
				continue
			}
			metrics.QueueProcessing.Inc()

			// The delivery engine will pick up active messages
			m.logger.Debug("Message activated",
				"worker", workerID,
				"id", msg.ID,
				"domain", msg.Domain,
			)
		}
	}
}

// retryScanLoop periodically scans the retry spool for messages ready to be retried.
func (m *Manager) retryScanLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanRetryQueue()
		}
	}
}

// deadLetterScanLoop scans for expired messages to move to dead-letter.
func (m *Manager) deadLetterScanLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanForExpired()
		}
	}
}

// Defer moves a message to the deferred spool for retry.
func (m *Manager) Defer(msg *Message, reason string) error {
	msg.RetryCount++
	msg.LastError = reason
	msg.UpdatedAt = time.Now()

	// Calculate next retry time using exponential backoff
	if msg.RetryCount <= len(m.retryIntvl) {
		msg.NextRetry = time.Now().Add(m.retryIntvl[msg.RetryCount-1])
	} else {
		msg.NextRetry = time.Now().Add(m.retryIntvl[len(m.retryIntvl)-1])
	}

	// Check if max retries exceeded
	if msg.RetryCount > m.cfg.MaxRetries {
		return m.DeadLetter(msg, "max retries exceeded")
	}

	if err := m.moveSpool(msg, SpoolDeferred); err != nil {
		return err
	}
	metrics.QueueDeferred.Inc()

	m.logger.Info("Message deferred",
		"id", msg.ID,
		"retry", msg.RetryCount,
		"next_retry", msg.NextRetry,
		"reason", reason,
	)

	return nil
}

// DeadLetter moves a message to the dead-letter spool.
func (m *Manager) DeadLetter(msg *Message, reason string) error {
	msg.LastError = reason
	msg.UpdatedAt = time.Now()

	if err := m.moveSpool(msg, SpoolDeadLetter); err != nil {
		return err
	}
	metrics.QueueDeadLetter.Inc()

	m.logger.Warn("Message dead-lettered",
		"id", msg.ID,
		"sender", logging.MaskEmail(msg.Sender),
		"domain", msg.Domain,
		"retries", msg.RetryCount,
		"reason", reason,
	)

	return nil
}

// Fail moves a message to the failed spool (permanent failure).
func (m *Manager) Fail(msg *Message, reason string) error {
	msg.LastError = reason
	msg.UpdatedAt = time.Now()

	if err := m.moveSpool(msg, SpoolFailed); err != nil {
		return err
	}
	atomic.AddInt64(&m.depth, -1)
	metrics.QueueFailed.Inc()

	m.logger.Error("Message permanently failed",
		"id", msg.ID,
		"sender", logging.MaskEmail(msg.Sender),
		"domain", msg.Domain,
		"reason", reason,
	)

	return nil
}

// Complete marks a message as successfully delivered and removes it from the spool.
func (m *Manager) Complete(msg *Message) error {
	// Remove spool files
	if err := m.removeFromSpool(msg); err != nil {
		return err
	}
	atomic.AddInt64(&m.depth, -1)
	metrics.QueueCompleted.Inc()
	metrics.QueueDepth.WithLabelValues(string(msg.Spool)).Dec()

	if m.cfg.JournalEnabled {
		m.writeJournal("complete", msg)
	}

	return nil
}

// GetActiveMessages returns messages from the active spool for a given domain.
func (m *Manager) GetActiveMessages(domain string, limit int) ([]*Message, error) {
	shardID := m.domainShard(domain)
	dir := filepath.Join(m.spoolDirs[SpoolActive], fmt.Sprintf(shardDirFmt, shardID))

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var messages []*Message
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}

		msg, err := m.loadMessage(filepath.Join(dir, entry.Name()))
		if err != nil {
			m.logger.Error("Failed to load message", "file", entry.Name(), "error", err)
			continue
		}

		if domain == "" || msg.Domain == domain {
			messages = append(messages, msg)
			if len(messages) >= limit {
				break
			}
		}
	}

	return messages, nil
}

// QueueDepth returns the current total queue depth.
func (m *Manager) QueueDepth() int64 {
	return atomic.LoadInt64(&m.depth)
}

// ── Internal Methods ────────────────────────────────────────────────────────

// writeToSpool writes message data and metadata to the spool directory.
func (m *Manager) writeToSpool(msg *Message) error {
	shardDir := filepath.Join(m.spoolDirs[msg.Spool], fmt.Sprintf(shardDirFmt, msg.ShardID))
	dataPath := filepath.Join(shardDir, msg.ID+".msg")
	metaPath := filepath.Join(shardDir, msg.ID+".meta")

	// Write message data atomically (write to temp, then rename)
	tmpDataPath := dataPath + ".tmp"
	if err := os.WriteFile(tmpDataPath, msg.Data, 0640); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	if err := os.Rename(tmpDataPath, dataPath); err != nil {
		os.Remove(tmpDataPath)
		return fmt.Errorf("rename data: %w", err)
	}
	msg.DataPath = dataPath

	// Write metadata
	metaData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	tmpMetaPath := metaPath + ".tmp"
	if err := os.WriteFile(tmpMetaPath, metaData, 0640); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	if err := os.Rename(tmpMetaPath, metaPath); err != nil {
		os.Remove(tmpMetaPath)
		return fmt.Errorf("rename metadata: %w", err)
	}

	return nil
}

// moveSpool moves a message between spool tiers.
func (m *Manager) moveSpool(msg *Message, target SpoolType) error {
	oldSpool := msg.Spool

	// Move files
	oldDir := filepath.Join(m.spoolDirs[oldSpool], fmt.Sprintf(shardDirFmt, msg.ShardID))
	newDir := filepath.Join(m.spoolDirs[target], fmt.Sprintf(shardDirFmt, msg.ShardID))

	oldData := filepath.Join(oldDir, msg.ID+".msg")
	newData := filepath.Join(newDir, msg.ID+".msg")
	if err := os.Rename(oldData, newData); err != nil {
		return fmt.Errorf("move data spool file: %w", err)
	}
	msg.DataPath = newData

	// Update metadata in new location
	updated := *msg
	updated.Spool = target
	metaData, err := json.Marshal(&updated)
	if err != nil {
		_ = os.Rename(newData, oldData)
		return fmt.Errorf("marshal metadata: %w", err)
	}
	newMetaPath := filepath.Join(newDir, msg.ID+".meta")
	if err := os.WriteFile(newMetaPath, metaData, 0640); err != nil {
		_ = os.Rename(newData, oldData)
		return fmt.Errorf("write metadata: %w", err)
	}

	// Remove old metadata
	if err := os.Remove(filepath.Join(oldDir, msg.ID+".meta")); err != nil {
		_ = os.Remove(newMetaPath)
		_ = os.Rename(newData, oldData)
		return fmt.Errorf("remove old metadata: %w", err)
	}

	msg.Spool = target

	metrics.QueueDepth.WithLabelValues(string(oldSpool)).Dec()
	metrics.QueueDepth.WithLabelValues(string(target)).Inc()

	if m.cfg.JournalEnabled {
		m.writeJournal("move:"+string(target), msg)
	}

	return nil
}

// removeFromSpool removes message files from the spool.
func (m *Manager) removeFromSpool(msg *Message) error {
	dir := filepath.Join(m.spoolDirs[msg.Spool], fmt.Sprintf(shardDirFmt, msg.ShardID))
	if err := os.Remove(filepath.Join(dir, msg.ID+".msg")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove message data: %w", err)
	}
	if err := os.Remove(filepath.Join(dir, msg.ID+".meta")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove message metadata: %w", err)
	}
	return nil
}

// loadMessage reads a message metadata file and returns the Message.
func (m *Manager) loadMessage(metaPath string) (*Message, error) {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	msg := &Message{}
	if err := json.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// rehydrate scans all spool directories on startup to rebuild queue state.
func (m *Manager) rehydrate() {
	m.logger.Info("Rehydrating queue from disk spool")
	var count int64

	spools := []SpoolType{SpoolIncoming, SpoolActive, SpoolDeferred, SpoolRetry}
	for _, spool := range spools {
		for i := 0; i < m.cfg.ShardCount; i++ {
			dir := filepath.Join(m.spoolDirs[spool], fmt.Sprintf(shardDirFmt, i))
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".meta") {
					continue
				}
				count++
			}
		}
	}

	atomic.StoreInt64(&m.depth, count)
	m.logger.Info("Queue rehydrated", "messages", count)
}

// scanRetryQueue checks for messages in the retry spool that are ready to retry.
func (m *Manager) scanRetryQueue() {
	now := time.Now()
	for i := 0; i < m.cfg.ShardCount; i++ {
		dir := filepath.Join(m.spoolDirs[SpoolDeferred], fmt.Sprintf(shardDirFmt, i))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".meta") {
				continue
			}
			msg, err := m.loadMessage(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			if now.After(msg.NextRetry) {
				if err := m.moveSpool(msg, SpoolActive); err != nil {
					m.logger.Error("Failed to re-activate retry message", "id", msg.ID, "error", err)
					continue
				}
				m.logger.Debug("Message re-activated for retry", "id", msg.ID, "retry", msg.RetryCount)
			}
		}
	}
}

// scanForExpired moves expired messages to the dead-letter spool.
func (m *Manager) scanForExpired() {
	now := time.Now()
	activeSpool := []SpoolType{SpoolActive, SpoolDeferred, SpoolRetry}
	for _, spool := range activeSpool {
		for i := 0; i < m.cfg.ShardCount; i++ {
			m.expireShardMessages(spool, i, now)
		}
	}
}

// expireShardMessages checks one shard of one spool and dead-letters any expired messages.
func (m *Manager) expireShardMessages(spool SpoolType, shardIdx int, now time.Time) {
	dir := filepath.Join(m.spoolDirs[spool], fmt.Sprintf(shardDirFmt, shardIdx))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		msg, err := m.loadMessage(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if now.After(msg.ExpiresAt) {
			m.DeadLetter(msg, "message expired")
		}
	}
}

// generateMessageID creates a unique message ID with cryptographic randomness.
func (m *Manager) generateMessageID() string {
	now := time.Now()
	randBytes := make([]byte, 16)
	if _, err := crand.Read(randBytes); err != nil {
		// Fallback: use timestamp + sha256 (less secure but functional)
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", now.UnixNano(), now.UnixMicro())))
		return fmt.Sprintf("%s-%s", now.Format("20060102150405"), hex.EncodeToString(hash[:8]))
	}
	return fmt.Sprintf("%s-%s", now.Format("20060102150405"), hex.EncodeToString(randBytes))
}

// extractDomain returns the domain part of an email address.
func (m *Manager) extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "unknown"
	}
	return strings.ToLower(parts[1])
}

// domainShard returns the shard ID for a domain using consistent hashing.
func (m *Manager) domainShard(domain string) int {
	h := sha256.Sum256([]byte(domain))
	return int(h[0]) % m.cfg.ShardCount
}

// writeJournal writes a crash-recovery journal entry.
func (m *Manager) writeJournal(action string, msg *Message) {
	entry := JournalEntry{
		Timestamp: time.Now(),
		Action:    action,
		MessageID: msg.ID,
		Spool:     string(msg.Spool),
		Domain:    msg.Domain,
	}
	// Delegate to journal writer
	WriteJournalEntry(m.cfg.SpoolDir, entry)
}
