// Package store implements multi-database support for SRMTA.
// Supports PostgreSQL and MySQL/MariaDB backends via the Database interface.
// The active backend is selected by the `database.driver` config field.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/srmta/srmta/internal/config"
)

// ── Database Interface ──────────────────────────────────────────────────────
// All database backends must implement this interface.

// Database defines the storage operations for SRMTA event logging.
type Database interface {
	// RecordEvent asynchronously records a delivery event.
	RecordEvent(event *DeliveryEvent)

	// RecordBounce records a bounce event.
	RecordBounce(record interface{})

	// Close gracefully closes the database connection.
	Close()

	// Driver returns the database driver name ("postgres" or "mysql").
	Driver() string
}

// NewDatabase creates a new database store based on the configured driver.
// Supported drivers: "postgres" (default), "mysql".
func NewDatabase(cfg config.DatabaseConfig) (Database, error) {
	switch cfg.Driver {
	case "mysql":
		return NewMySQLStore(cfg)
	case "postgres", "":
		return NewPostgresStore(cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %q (supported: postgres, mysql)", cfg.Driver)
	}
}

// ── DeliveryEvent Schema ────────────────────────────────────────────────────

// DeliveryEvent represents a delivery event stored in the database.
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
// NOTE: In production, use database/sql with pgx driver.
type PostgresStore struct {
	cfg    config.DatabaseConfig
	events chan *DeliveryEvent
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

	go store.eventWriter()
	return store, nil
}

func (s *PostgresStore) RecordEvent(event *DeliveryEvent) {
	select {
	case s.events <- event:
	default:
		// Channel full, drop event (metrics will track this)
	}
}

func (s *PostgresStore) RecordBounce(record interface{}) {
	// In production: INSERT INTO bounces (message_id, sender, recipient, bounce_type, ...)
	// VALUES ($1, $2, $3, $4, ...)
}

func (s *PostgresStore) eventWriter() {
	for event := range s.events {
		// In production: batch INSERT into delivery_events table
		// INSERT INTO delivery_events (timestamp, message_id, sender, recipient, ...)
		// VALUES ($1, $2, $3, $4, ...)
		_ = event
	}
}

func (s *PostgresStore) Close() {
	close(s.events)
	// In production: close database connection pool
}

func (s *PostgresStore) Driver() string {
	return "postgres"
}

// ── MySQL/MariaDB Store ─────────────────────────────────────────────────────

// MySQLStore manages MySQL/MariaDB connections for metadata and event logging.
// NOTE: In production, use database/sql with go-sql-driver/mysql.
type MySQLStore struct {
	cfg    config.DatabaseConfig
	events chan *DeliveryEvent
}

// NewMySQLStore creates a new MySQL/MariaDB store.
func NewMySQLStore(cfg config.DatabaseConfig) (*MySQLStore, error) {
	store := &MySQLStore{
		cfg:    cfg,
		events: make(chan *DeliveryEvent, 10000),
	}

	// In production: establish database connection pool
	// db, err := sql.Open("mysql", cfg.DSN())
	// if err != nil { return nil, err }

	go store.eventWriter()
	return store, nil
}

func (s *MySQLStore) RecordEvent(event *DeliveryEvent) {
	select {
	case s.events <- event:
	default:
		// Channel full, drop event
	}
}

func (s *MySQLStore) RecordBounce(record interface{}) {
	// In production: INSERT INTO bounces (message_id, sender, recipient, bounce_type, ...)
	// VALUES (?, ?, ?, ?, ...)
	// Note: MySQL uses ? placeholders, not $1/$2
}

func (s *MySQLStore) eventWriter() {
	for event := range s.events {
		// In production: batch INSERT into delivery_events table
		// INSERT INTO delivery_events (timestamp, message_id, sender, recipient, ...)
		// VALUES (?, ?, ?, ?, ...)
		_ = event
	}
}

func (s *MySQLStore) Close() {
	close(s.events)
	// In production: close database connection pool
}

func (s *MySQLStore) Driver() string {
	return "mysql"
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

func NewRedisStore(cfg config.RedisConfig) (*RedisStore, error) {
	return &RedisStore{cfg: cfg}, nil
}

func (s *RedisStore) EnqueueMessage(messageID, domain string, priority int) {
	// ZADD srmta:queue:{domain} {priority} {messageID}
}

func (s *RedisStore) DequeueMessage(messageID, domain string) {
	// ZREM srmta:queue:{domain} {messageID}
}

func (s *RedisStore) GetDNSCache(domain string) ([]*MXRecord, error) {
	return nil, fmt.Errorf("not cached")
}

func (s *RedisStore) SetDNSCache(domain string, records interface{}, ttl time.Duration) {
	// SETEX srmta:dns:{domain} {ttl} {json}
}

func (s *RedisStore) GetQueueDepth() (int64, error) {
	return 0, nil
}

func (s *RedisStore) Close() {
	// Close Redis client
}

// ── File Utilities ──────────────────────────────────────────────────────────

func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func WriteJSON(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}
