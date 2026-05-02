// Package logging provides structured JSON logging for SRMTA with delivery event schema.
// Supports separate log files for error, access, and transaction logs:
//
//	Error log        → /var/log/srmta/error.log       (JSON, warn+error only)
//	Access log       → /var/log/srmta/access.log      (JSON, SMTP session events)
//	Transaction log  → /var/log/srmta/transaction.csv  (CSV, delivery events)
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
)

// Level represents a log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the string representation of a log level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// Logger is the structured JSON logger for SRMTA with multi-file support.
type Logger struct {
	level       Level
	output      io.Writer    // General log (all levels)
	errorOut    io.Writer    // Error log (warn + error only)
	accessOut   io.Writer    // Access log (SMTP session events)
	txnExporter *CSVExporter // Transaction CSV exporter
	closers     []io.Closer
	mu          sync.Mutex
}

// LogEntry represents a structured log entry.
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// NewLogger creates a new structured logger from configuration.
func NewLogger(cfg config.LoggingConfig) *Logger {
	level := LevelInfo
	switch cfg.Level {
	case "debug":
		level = LevelDebug
	case "warn":
		level = LevelWarn
	case "error":
		level = LevelError
	}

	l := &Logger{
		level: level,
	}

	// ── General output ──────────────────────────────────────────────────
	switch cfg.Output {
	case "file":
		if cfg.FilePath != "" {
			l.output = l.openLogFile(cfg.FilePath)
		} else {
			l.output = os.Stdout
		}
	default:
		l.output = os.Stdout
	}

	// ── Error log (warn + error only) ───────────────────────────────────
	if cfg.ErrorFile != "" {
		l.errorOut = l.openLogFile(cfg.ErrorFile)
	}

	// ── Access log (SMTP session events) ────────────────────────────────
	if cfg.AccessFile != "" {
		l.accessOut = l.openLogFile(cfg.AccessFile)
	}

	// ── Transaction CSV log (delivery events) ───────────────────────────
	if cfg.TransactionFile != "" {
		w := l.openLogFile(cfg.TransactionFile)
		if w != nil {
			l.txnExporter = NewCSVExporter(w)
			// Write CSV header if file is new/empty
			if fi, err := os.Stat(cfg.TransactionFile); err == nil && fi.Size() == 0 {
				l.txnExporter.WriteHeader()
			}
		}
	}

	return l
}

// openLogFile opens a log file for writing, creating parent directories as needed.
// Returns os.Stdout on failure with a warning to stderr.
func (l *Logger) openLogFile(path string) io.Writer {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: failed to create log directory %s: %v\n", dir, err)
		return os.Stdout
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: failed to open log file %s: %v, falling back to stdout\n", path, err)
		return os.Stdout
	}

	l.closers = append(l.closers, f)
	return f
}

// Close closes all open log file handles.
func (l *Logger) Close() {
	for _, c := range l.closers {
		c.Close()
	}
}

// ── Standard Log Methods ────────────────────────────────────────────────────

// Debug logs a debug-level message.
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.log(LevelDebug, msg, keysAndValues...)
}

// Info logs an info-level message.
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.log(LevelInfo, msg, keysAndValues...)
}

// Warn logs a warning-level message.
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.log(LevelWarn, msg, keysAndValues...)
}

// Error logs an error-level message.
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.log(LevelError, msg, keysAndValues...)
}

// ── Access Log ──────────────────────────────────────────────────────────────

// Access logs an access event (SMTP session activity) to the access log file.
// Always written regardless of log level.
func (l *Logger) Access(msg string, keysAndValues ...interface{}) {
	if l.accessOut == nil {
		// Fall through to general log as info
		l.log(LevelInfo, msg, keysAndValues...)
		return
	}

	entry := l.buildEntry(LevelInfo, msg, keysAndValues...)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.accessOut.Write(append(data, '\n'))
}

// ── Transaction Log ─────────────────────────────────────────────────────────

// Transaction logs a delivery event to the transaction CSV file.
func (l *Logger) Transaction(evt *DeliveryEvent) {
	if l.txnExporter == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.txnExporter.WriteEvent(evt)
}

// ── Internal ────────────────────────────────────────────────────────────────

// log writes a structured JSON log entry to the general output and optionally
// to the error log file for warn/error levels.
func (l *Logger) log(level Level, msg string, keysAndValues ...interface{}) {
	if level < l.level {
		return
	}

	entry := l.buildEntry(level, msg, keysAndValues...)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	line := append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to general output
	l.output.Write(line)

	// Also write warn/error to the dedicated error log
	if l.errorOut != nil && (level == LevelWarn || level == LevelError) {
		l.errorOut.Write(line)
	}
}

// buildEntry creates a LogEntry from the message and key-value pairs.
func (l *Logger) buildEntry(level Level, msg string, keysAndValues ...interface{}) LogEntry {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Message:   msg,
	}

	if len(keysAndValues) > 0 {
		entry.Fields = make(map[string]interface{})
		for i := 0; i < len(keysAndValues)-1; i += 2 {
			key, ok := keysAndValues[i].(string)
			if !ok {
				key = fmt.Sprintf("%v", keysAndValues[i])
			}
			entry.Fields[key] = keysAndValues[i+1]
		}
	}

	return entry
}

// ── DeliveryEvent Schema ────────────────────────────────────────────────────

// DeliveryEvent represents the full delivery event schema for audit logging.
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
	Status            string    `json:"status"` // delivered, deferred, bounced, failed
}

// ── CSV Exporter ────────────────────────────────────────────────────────────

// CSVExporter exports delivery events to CSV format.
type CSVExporter struct {
	writer io.Writer
}

// NewCSVExporter creates a CSV exporter.
func NewCSVExporter(w io.Writer) *CSVExporter {
	return &CSVExporter{writer: w}
}

// WriteHeader writes the CSV header row.
func (e *CSVExporter) WriteHeader() {
	fmt.Fprintln(e.writer, "timestamp,message_id,sender,recipient,remote_mx,response_code,response_text,ip_used,tls_status,retry_count,dkim_status,processing_latency_ms,status")
}

// WriteEvent writes a single delivery event as a CSV row.
func (e *CSVExporter) WriteEvent(evt *DeliveryEvent) {
	fmt.Fprintf(e.writer, "%s,%s,%s,%s,%s,%d,%q,%s,%t,%d,%s,%d,%s\n",
		evt.Timestamp.Format(time.RFC3339),
		evt.MessageID,
		evt.Sender,
		evt.Recipient,
		evt.RemoteMX,
		evt.ResponseCode,
		evt.ResponseText,
		evt.IPUsed,
		evt.TLSStatus,
		evt.RetryCount,
		evt.DKIMStatus,
		evt.ProcessingLatency,
		evt.Status,
	)
}

// MaskEmail redacts an email address or username for privacy compliance in logs.
// Format: user@domain.com -> u***r@domain.com
func MaskEmail(email string) string {
	if email == "" || !strings.Contains(email, "@") {
		if len(email) <= 2 {
			return email
		}
		return string(email[0]) + "***" + string(email[len(email)-1])
	}
	parts := strings.SplitN(email, "@", 2)
	user := parts[0]
	domain := parts[1]

	if len(user) <= 1 {
		return "*" + "@" + domain
	}
	if len(user) == 2 {
		return string(user[0]) + "*" + "@" + domain
	}
	return string(user[0]) + "***" + string(user[len(user)-1]) + "@" + domain
}
