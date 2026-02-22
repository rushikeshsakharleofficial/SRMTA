// Package logging provides structured JSON logging for SRMTA with delivery event schema.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// Logger is the structured JSON logger for SRMTA.
type Logger struct {
	level  Level
	output io.Writer
	mu     sync.Mutex
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

	var output io.Writer
	switch cfg.Output {
	case "file":
		if cfg.FilePath != "" {
			f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v, falling back to stdout\n", cfg.FilePath, err)
				output = os.Stdout
			} else {
				output = f
			}
		} else {
			output = os.Stdout
		}
	default:
		output = os.Stdout
	}

	return &Logger{
		level:  level,
		output: output,
	}
}

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

// log writes a structured JSON log entry.
func (l *Logger) log(level Level, msg string, keysAndValues ...interface{}) {
	if level < l.level {
		return
	}

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

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.output.Write(append(data, '\n'))
}

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
