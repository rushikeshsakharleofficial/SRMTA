// Package store implements PostgreSQL persistence for SRMTA event logging.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/srmta/srmta/internal/config"
)

// Database defines the storage operations for SRMTA event logging.
type Database interface {
	RecordEvent(event *DeliveryEvent)
	RecordBounce(event BounceEvent)
	Close()
	Driver() string
}

// NewDatabase creates a new Postgres database store. Returns nil if host is unconfigured.
func NewDatabase(cfg config.DatabaseConfig) (Database, error) {
	if cfg.Host == "" {
		return nil, nil
	}
	if cfg.Driver != "" && cfg.Driver != "postgres" {
		return nil, fmt.Errorf("unsupported database driver: %q (only postgres is supported)", cfg.Driver)
	}
	return NewPostgresStore(cfg)
}

// DeliveryEvent represents a delivery event stored in the database.
type DeliveryEvent struct {
	Timestamp         time.Time
	MessageID         string
	Sender            string
	Recipient         string
	RemoteMX          string
	ResponseCode      int
	ResponseText      string
	IPUsed            string
	TLSStatus         bool
	RetryCount        int
	DKIMStatus        string
	ProcessingLatency int64
	Status            string
}

// BounceEvent holds the data recorded for a bounce.
type BounceEvent struct {
	MessageID  string
	Sender     string
	Recipient  string
	BounceType string
	Code       int
	Text       string
	Timestamp  time.Time
}

// PostgresStore writes delivery events and bounces to PostgreSQL.
type PostgresStore struct {
	db     *sql.DB
	events chan *DeliveryEvent
	done   chan struct{}
}

func NewPostgresStore(cfg config.DatabaseConfig) (*PostgresStore, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PostgresStore{
		db:     db,
		events: make(chan *DeliveryEvent, 10000),
		done:   make(chan struct{}),
	}
	go s.eventWriter()
	return s, nil
}

func (s *PostgresStore) RecordEvent(event *DeliveryEvent) {
	select {
	case s.events <- event:
	default:
		// channel full — drop; upstream metrics track delivery counts
	}
}

func (s *PostgresStore) RecordBounce(event BounceEvent) {
	s.db.Exec(
		`INSERT INTO bounces
		 (message_id, sender, recipient, bounce_type, response_code, response_text, timestamp)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		event.MessageID, event.Sender, event.Recipient, event.BounceType,
		event.Code, event.Text, event.Timestamp,
	)
}

func (s *PostgresStore) eventWriter() {
	defer close(s.done)
	for event := range s.events {
		s.db.Exec(
			`INSERT INTO delivery_events
			 (timestamp, message_id, sender, recipient, remote_mx, response_code, response_text,
			  ip_used, tls_status, retry_count, dkim_status, processing_latency_ms, status)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			event.Timestamp, event.MessageID, event.Sender, event.Recipient,
			event.RemoteMX, event.ResponseCode, event.ResponseText, event.IPUsed,
			event.TLSStatus, event.RetryCount, event.DKIMStatus, event.ProcessingLatency, event.Status,
		)
	}
}

func (s *PostgresStore) Close() {
	close(s.events)
	<-s.done
	s.db.Close()
}

func (s *PostgresStore) Driver() string { return "postgres" }

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
