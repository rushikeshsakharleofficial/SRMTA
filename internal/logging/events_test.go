package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srmta/srmta/internal/config"
)

func TestNewLogger_Stdout(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:  "info",
		Output: "stdout",
	}
	l := NewLogger(cfg)
	defer l.Close()

	if l.output != os.Stdout {
		t.Error("expected stdout output")
	}
}

func TestNewLogger_Levels(t *testing.T) {
	tests := []struct {
		level    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarn},
		{"error", LevelError},
		{"", LevelInfo}, // default
	}

	for _, tt := range tests {
		cfg := config.LoggingConfig{Level: tt.level}
		l := NewLogger(cfg)
		defer l.Close()

		if l.level != tt.expected {
			t.Errorf("level %q → %d, want %d", tt.level, l.level, tt.expected)
		}
	}
}

func TestLogger_ErrorFile(t *testing.T) {
	tmpDir := t.TempDir()
	errorFile := filepath.Join(tmpDir, "error.log")

	cfg := config.LoggingConfig{
		Level:     "debug",
		Output:    "stdout",
		ErrorFile: errorFile,
	}
	l := NewLogger(cfg)

	// Info should NOT appear in error log
	l.Info("info message")
	// Error SHOULD appear in error log
	l.Error("something failed", "code", 500)
	// Warn SHOULD appear in error log
	l.Warn("something fishy")
	l.Close()

	data, err := os.ReadFile(errorFile)
	if err != nil {
		t.Fatalf("failed to read error log: %v", err)
	}

	content := string(data)
	if strings.Contains(content, "info message") {
		t.Error("error log should NOT contain info messages")
	}
	if !strings.Contains(content, "something failed") {
		t.Error("error log should contain error messages")
	}
	if !strings.Contains(content, "something fishy") {
		t.Error("error log should contain warn messages")
	}
}

func TestLogger_AccessFile(t *testing.T) {
	tmpDir := t.TempDir()
	accessFile := filepath.Join(tmpDir, "access.log")

	cfg := config.LoggingConfig{
		Level:      "info",
		Output:     "stdout",
		AccessFile: accessFile,
	}
	l := NewLogger(cfg)

	l.Access("SMTP connection opened",
		"remote", "1.2.3.4", "action", "connect")
	l.Access("SMTP connection closed",
		"remote", "1.2.3.4", "action", "disconnect")
	l.Close()

	data, err := os.ReadFile(accessFile)
	if err != nil {
		t.Fatalf("failed to read access log: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "SMTP connection opened") {
		t.Error("access log should contain connection events")
	}
	if !strings.Contains(content, "disconnect") {
		t.Error("access log should contain disconnect events")
	}
}

func TestLogger_TransactionCSV(t *testing.T) {
	tmpDir := t.TempDir()
	txnFile := filepath.Join(tmpDir, "transaction.csv")

	cfg := config.LoggingConfig{
		Level:           "info",
		Output:          "stdout",
		TransactionFile: txnFile,
	}
	l := NewLogger(cfg)

	l.Transaction(&DeliveryEvent{
		Timestamp:    time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC),
		MessageID:    "msg-001",
		Sender:       "sender@example.com",
		Recipient:    "rcpt@example.com",
		RemoteMX:     "mx.example.com",
		ResponseCode: 250,
		ResponseText: "OK",
		IPUsed:       "10.0.0.1",
		TLSStatus:    true,
		RetryCount:   0,
		DKIMStatus:   "pass",
		Status:       "delivered",
	})
	l.Close()

	data, err := os.ReadFile(txnFile)
	if err != nil {
		t.Fatalf("failed to read transaction log: %v", err)
	}

	content := string(data)
	// Should have CSV header
	if !strings.Contains(content, "timestamp,message_id,sender") {
		t.Error("transaction log should contain CSV header")
	}
	// Should have data row
	if !strings.Contains(content, "msg-001") {
		t.Error("transaction log should contain event data")
	}
	if !strings.Contains(content, "sender@example.com") {
		t.Error("transaction log should contain sender")
	}
	if !strings.Contains(content, "delivered") {
		t.Error("transaction log should contain status")
	}
}

func TestLogger_AccessFallbackToGeneral(t *testing.T) {
	// When no access file is configured, Access() should write to general log
	cfg := config.LoggingConfig{
		Level:  "info",
		Output: "stdout",
		// No AccessFile - should fall through to general log
	}
	l := NewLogger(cfg)
	defer l.Close()

	// Should not panic
	l.Access("session event", "remote", "1.2.3.4")
}

func TestLogger_TransactionNoFile(t *testing.T) {
	// When no transaction file, Transaction() should be a no-op
	cfg := config.LoggingConfig{
		Level:  "info",
		Output: "stdout",
	}
	l := NewLogger(cfg)
	defer l.Close()

	// Should not panic
	l.Transaction(&DeliveryEvent{MessageID: "test"})
}

func TestLogger_CreatesDirs(t *testing.T) {
	tmpDir := t.TempDir()
	nested := filepath.Join(tmpDir, "deep", "sub", "dir", "error.log")

	cfg := config.LoggingConfig{
		Level:     "error",
		ErrorFile: nested,
	}
	l := NewLogger(cfg)
	l.Error("test")
	l.Close()

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Error("logger should auto-create parent directories")
	}
}

func TestCSVExporter_WriteEvent(t *testing.T) {
	var buf bytes.Buffer
	exp := NewCSVExporter(&buf)
	exp.WriteHeader()
	exp.WriteEvent(&DeliveryEvent{
		Timestamp:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		MessageID:    "test-id",
		Sender:       "a@b.com",
		Recipient:    "c@d.com",
		ResponseCode: 250,
		Status:       "delivered",
	})

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + data), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "timestamp,message_id") {
		t.Error("first line should be CSV header")
	}
	if !strings.Contains(lines[1], "test-id") {
		t.Error("second line should contain event data")
	}
}

func TestBuildEntry(t *testing.T) {
	cfg := config.LoggingConfig{Level: "info"}
	l := NewLogger(cfg)
	defer l.Close()

	entry := l.buildEntry(LevelError, "test message", "key1", "val1", "key2", 42)

	if entry.Level != "error" {
		t.Errorf("expected level=error, got %s", entry.Level)
	}
	if entry.Message != "test message" {
		t.Errorf("expected message='test message', got %s", entry.Message)
	}
	if entry.Fields["key1"] != "val1" {
		t.Errorf("expected key1=val1, got %v", entry.Fields["key1"])
	}
}
