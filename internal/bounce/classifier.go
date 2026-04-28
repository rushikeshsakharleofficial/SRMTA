// Package bounce implements bounce classification and auto-suppression for SRMTA.
package bounce

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/store"
)

// BounceType classifies the type of bounce.
type BounceType string

const (
	BounceHard    BounceType = "hard"         // Permanent: user doesn't exist
	BounceSoft    BounceType = "soft"         // Temporary: try again later
	BounceBlock   BounceType = "block"        // Blocked by policy
	BouncePolicy  BounceType = "policy"       // DMARC/SPF/policy rejection
	BounceMailbox BounceType = "mailbox_full" // Mailbox full
)

// BounceRecord represents a classified bounce event.
type BounceRecord struct {
	MessageID    string     `json:"message_id"`
	Sender       string     `json:"sender"`
	Recipient    string     `json:"recipient"`
	Type         BounceType `json:"type"`
	ResponseCode int        `json:"response_code"`
	ResponseText string     `json:"response_text"`
	Timestamp    time.Time  `json:"timestamp"`
}

// Classifier classifies SMTP bounce responses and manages suppression.
type Classifier struct {
	cfg         config.BounceConfig
	db          store.Database
	logger      *logging.Logger
	suppressed  map[string]time.Time // email -> suppression time
	senderStats map[string]*SenderStats
	mu          sync.RWMutex
}

// SenderStats tracks bounce/complaint rates per sender.
type SenderStats struct {
	TotalSent     int64
	HardBounces   int64
	SoftBounces   int64
	Complaints    int64
	BounceRate    float64
	ComplaintRate float64
	Paused        bool
	PausedAt      time.Time
}

// NewClassifier creates a new bounce classifier.
func NewClassifier(cfg config.BounceConfig, db store.Database, logger *logging.Logger) *Classifier {
	return &Classifier{
		cfg:         cfg,
		db:          db,
		logger:      logger,
		suppressed:  make(map[string]time.Time),
		senderStats: make(map[string]*SenderStats),
	}
}

// ClassifyAndRecord classifies an SMTP response and records the bounce.
func (c *Classifier) ClassifyAndRecord(messageID, sender, recipient string, code int, text string) *BounceRecord {
	bounceType := c.classify(code, text)

	record := &BounceRecord{
		MessageID:    messageID,
		Sender:       sender,
		Recipient:    recipient,
		Type:         bounceType,
		ResponseCode: code,
		ResponseText: text,
		Timestamp:    time.Now(),
	}

	// Handle suppression
	if bounceType == BounceHard {
		c.suppress(recipient)
	}

	// Update sender stats
	c.updateSenderStats(sender, bounceType)

	// Persist to database
	if c.db != nil {
		c.db.RecordBounce(record)
	}

	c.logger.Info("Bounce classified",
		"message_id", messageID,
		"recipient", recipient,
		"type", bounceType,
		"code", code,
	)

	return record
}

// classify determines the bounce type from an SMTP response.
func (c *Classifier) classify(code int, text string) BounceType {
	textLower := strings.ToLower(text)

	switch {
	case code == 550:
		return classify550(textLower)
	case code == 551:
		return BounceHard
	case code == 552:
		return classify552(textLower)
	case code == 553:
		return BounceHard
	case code == 554:
		return classify554(textLower)
	case code >= 400 && code < 500:
		return BounceSoft
	default:
		return c.patternClassify(textLower)
	}
}

// classify550 classifies a 550 response based on the response text.
// Order matters: the first-match wins (e.g. "rejected" → BounceHard before
// "rejected for policy" → BounceBlock is even tested).
func classify550(textLower string) BounceType {
	if containsAny(textLower, []string{"does not exist", "no such user", "unknown user",
		"invalid recipient", "rejected", "user unknown", "mailbox not found"}) {
		return BounceHard
	}
	if containsAny(textLower, []string{"blocked", "blacklist", "denied", "spam",
		"rejected for policy"}) {
		return BounceBlock
	}
	return BounceHard
}

// classify552 classifies a 552 response based on the response text.
func classify552(textLower string) BounceType {
	if containsAny(textLower, []string{"mailbox full", "over quota", "quota exceeded", "storage", "disk full"}) {
		return BounceMailbox
	}
	return BounceSoft
}

// classify554 classifies a 554 response based on the response text.
func classify554(textLower string) BounceType {
	if containsAny(textLower, []string{"dmarc", "spf", "dkim", "policy"}) {
		return BouncePolicy
	}
	if containsAny(textLower, []string{"spam", "blocked", "blacklist"}) {
		return BounceBlock
	}
	return BounceHard
}

// Enhanced pattern rules for bounce classification
var bouncePatterns = []struct {
	Pattern *regexp.Regexp
	Type    BounceType
}{
	{regexp.MustCompile(`(?i)user.*(unknown|not found|doesn't exist)`), BounceHard},
	{regexp.MustCompile(`(?i)mailbox.*(full|over|quota)`), BounceMailbox},
	{regexp.MustCompile(`(?i)(blacklist|blocklist|block.?list)`), BounceBlock},
	{regexp.MustCompile(`(?i)(dmarc|spf|dkim).*(fail|reject)`), BouncePolicy},
	{regexp.MustCompile(`(?i)(temporarily|try.*(again|later))`), BounceSoft},
	{regexp.MustCompile(`(?i)(spam|junk|unsolicited)`), BounceBlock},
}

// patternClassify uses regex patterns for classification when code is ambiguous.
func (c *Classifier) patternClassify(text string) BounceType {
	for _, p := range bouncePatterns {
		if p.Pattern.MatchString(text) {
			return p.Type
		}
	}
	return BounceSoft // Default to soft bounce
}

// suppress adds a recipient to the suppression list.
func (c *Classifier) suppress(email string) {
	if !c.cfg.SuppressionListEnabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	email = strings.ToLower(email)
	c.suppressed[email] = time.Now()

	c.logger.Info("Recipient suppressed", "email", email)
}

// IsSuppressed checks if a recipient is on the suppression list.
func (c *Classifier) IsSuppressed(email string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.suppressed[strings.ToLower(email)]
	return exists
}

// updateSenderStats updates bounce statistics for a sender.
func (c *Classifier) updateSenderStats(sender string, bounceType BounceType) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats, exists := c.senderStats[sender]
	if !exists {
		stats = &SenderStats{}
		c.senderStats[sender] = stats
	}

	switch bounceType {
	case BounceHard:
		stats.HardBounces++
	case BounceSoft, BounceMailbox:
		stats.SoftBounces++
	}

	// Recalculate rates
	if stats.TotalSent > 0 {
		stats.BounceRate = float64(stats.HardBounces+stats.SoftBounces) / float64(stats.TotalSent)
		stats.ComplaintRate = float64(stats.Complaints) / float64(stats.TotalSent)
	}

	// Auto-pause sender if thresholds exceeded
	if c.cfg.SenderPauseEnabled {
		if stats.BounceRate > c.cfg.HardBounceThreshold {
			stats.Paused = true
			stats.PausedAt = time.Now()
			c.logger.Warn("Sender auto-paused: bounce rate exceeded",
				"sender", sender,
				"bounce_rate", stats.BounceRate,
				"threshold", c.cfg.HardBounceThreshold,
			)
		}
		if stats.ComplaintRate > c.cfg.ComplaintThreshold {
			stats.Paused = true
			stats.PausedAt = time.Now()
			c.logger.Warn("Sender auto-paused: complaint rate exceeded",
				"sender", sender,
				"complaint_rate", stats.ComplaintRate,
				"threshold", c.cfg.ComplaintThreshold,
			)
		}
	}
}

// RecordSend increments the send count for sender stats.
func (c *Classifier) RecordSend(sender string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats, exists := c.senderStats[sender]
	if !exists {
		stats = &SenderStats{}
		c.senderStats[sender] = stats
	}
	stats.TotalSent++
}

// IsSenderPaused checks if a sender is paused due to high bounce/complaint rate.
func (c *Classifier) IsSenderPaused(sender string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats, exists := c.senderStats[sender]
	return exists && stats.Paused
}

// GetSenderStats returns stats for a sender.
func (c *Classifier) GetSenderStats(sender string) *SenderStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats, exists := c.senderStats[sender]
	if !exists {
		return &SenderStats{}
	}
	return stats
}

// containsAny checks if the text contains any of the substrings.
func containsAny(text string, substrings []string) bool {
	for _, s := range substrings {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}
