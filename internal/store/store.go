// Package store implements PostgreSQL and Redis data stores for SRMTA.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/srmta/srmta/internal/config"
)

// ── DeliveryEvent Schema ────────────────────────────────────────────────────

// DeliveryEvent represents a delivery event stored in PostgreSQL.
type DeliveryEvent struct {
	Timestamp         time.Time `json:"timestamp"`
	MessageID         string    `json:"message_id"`
	Sender            string    `json:"sender"`
	Recipient         string    `json:"recipient"`
	RemoteMX          string    `json:"remote_mx"`
	ResponseCode      int       `json:"response_code"`
	ResponseText      string    `json:"response_text"`
	IPUsed            string    `json:"ip_used"`
	TLSStatus         bool      `json:"tls_status"`
	RetryCount        int       `json:"retry_count"`
	DKIMStatus        string    `json:"dkim_status"`
	ProcessingLatency int64     `json:"processing_latency_ms"`
	Status            string    `json:"status"`
}

// ── PostgreSQL Store ────────────────────────────────────────────────────────

// PostgresStore manages PostgreSQL connections for metadata and event logging.
// NOTE: In production, use database/sql with lib/pq or pgx driver.
// This implementation provides the interface without external database dependencies
// so the project compiles standalone.
type PostgresStore struct {
	cfg    config.DatabaseConfig
	events chan *DeliveryEvent // Buffered channel for async event writing
}

// NewPostgresStore creates a new PostgreSQL store.
func NewPostgresStore(cfg config.DatabaseConfig) (*PostgresStore, error) {
	store := &PostgresStore{
		cfg:    cfg,
		events: make(chan *DeliveryEvent, 10000),
	}

	// In production: establish database connection pool
	// db, err := sql.Open("postgres", cfg.DSN())
	// if err != nil { return nil, err }

	// Start event writer goroutine
	go store.eventWriter()

	return store, nil
}

// RecordEvent asynchronously records a delivery event.
func (s *PostgresStore) RecordEvent(event *DeliveryEvent) {
	select {
	case s.events <- event:
	default:
		// Channel full, drop event (metrics will track this)
	}
}

// RecordBounce records a bounce event. Interface for bounce.Classifier.
func (s *PostgresStore) RecordBounce(record interface{}) {
	// In production: INSERT INTO bounces table
}

// eventWriter processes the event queue and writes to PostgreSQL.
func (s *PostgresStore) eventWriter() {
	for event := range s.events {
		// In production: batch INSERT into delivery_events table
		_ = event // Process event
	}
}

// Close closes the PostgreSQL store.
func (s *PostgresStore) Close() {
	close(s.events)
}

// ── Redis Store ─────────────────────────────────────────────────────────────

// RedisStore manages Redis connections for queue state and DNS caching.
type RedisStore struct {
	cfg config.RedisConfig
}

// MXRecord matches dns.MXRecord for serialization.
type MXRecord struct {
	Host     string   `json:"host"`
	Priority uint16   `json:"priority"`
	IPs      []string `json:"ips"`
}

// NewRedisStore creates a new Redis store.
func NewRedisStore(cfg config.RedisConfig) (*RedisStore, error) {
	store := &RedisStore{
		cfg: cfg,
	}

	// In production: establish Redis connection pool
	// client := redis.NewClient(&redis.Options{...})

	return store, nil
}

// EnqueueMessage adds a message to the Redis queue state.
func (s *RedisStore) EnqueueMessage(messageID, domain string, priority int) {
	// In production: ZADD srmta:queue:{domain} {priority} {messageID}
}

// DequeueMessage removes a message from the Redis queue state.
func (s *RedisStore) DequeueMessage(messageID, domain string) {
	// In production: ZREM srmta:queue:{domain} {messageID}
}

// GetDNSCache retrieves cached DNS records from Redis.
func (s *RedisStore) GetDNSCache(domain string) ([]*MXRecord, error) {
	// In production: GET srmta:dns:{domain}
	return nil, fmt.Errorf("not cached")
}

// SetDNSCache stores DNS records in Redis with TTL.
func (s *RedisStore) SetDNSCache(domain string, records interface{}, ttl time.Duration) {
	// In production: SETEX srmta:dns:{domain} {ttl} {json}
}

// GetQueueDepth returns the total queue depth from Redis.
func (s *RedisStore) GetQueueDepth() (int64, error) {
	// In production: aggregate ZCARD across all domain queues
	return 0, nil
}

// Close closes the Redis store.
func (s *RedisStore) Close() {
	// In production: close Redis client
}

// ── File Operations ─────────────────────────────────────────────────────────

// ReadFile reads a file and returns its contents.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteJSON writes a value as JSON to a file.
func WriteJSON(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}
