package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.Server.MaxWorkers != 100 {
		t.Errorf("expected MaxWorkers=100, got %d", cfg.Server.MaxWorkers)
	}
	if cfg.Server.ShutdownGrace != 30*time.Second {
		t.Errorf("expected ShutdownGrace=30s, got %v", cfg.Server.ShutdownGrace)
	}
	if cfg.SMTP.InboundAddr != ":25" {
		t.Errorf("expected InboundAddr=:25, got %s", cfg.SMTP.InboundAddr)
	}
	if cfg.SMTP.MaxConnections != 1000 {
		t.Errorf("expected MaxConnections=1000, got %d", cfg.SMTP.MaxConnections)
	}
	if cfg.SMTP.MaxMessageSize != 50*1024*1024 {
		t.Errorf("expected MaxMessageSize=50MB, got %d", cfg.SMTP.MaxMessageSize)
	}
	if cfg.Queue.MaxRetries != 10 {
		t.Errorf("expected MaxRetries=10, got %d", cfg.Queue.MaxRetries)
	}
	if cfg.Queue.ShardCount != 16 {
		t.Errorf("expected ShardCount=16, got %d", cfg.Queue.ShardCount)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected json logging, got %s", cfg.Logging.Format)
	}
	if cfg.TLS.MinVersion != "1.2" {
		t.Errorf("expected TLS min version 1.2, got %s", cfg.TLS.MinVersion)
	}
}

func TestValidate_MissingHostname(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Server.Hostname = "" // Force empty

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing hostname")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Server.Hostname = "test.example.com"

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidate_InvalidTLS(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Server.Hostname = "test.example.com"
	cfg.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.TLS.KeyFile = "/nonexistent/key.pem"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for nonexistent TLS files")
	}
}

func TestValidate_TLSPartialConfig(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Server.Hostname = "test.example.com"
	cfg.TLS.CertFile = "/tmp/cert.pem"
	cfg.TLS.KeyFile = "" // Only cert set

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for partial TLS config")
	}
}

func TestValidate_BadTLSVersion(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Server.Hostname = "test.example.com"
	cfg.TLS.MinVersion = "1.0" // Bad version

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for bad TLS version")
	}
}

func TestLoad_WithValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
server:
  hostname: "test.example.com"
  max_workers: 50
smtp:
  max_connections: 500
`)
	if err := os.WriteFile(configPath, yaml, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Hostname != "test.example.com" {
		t.Errorf("expected hostname test.example.com, got %s", cfg.Server.Hostname)
	}
	if cfg.Server.MaxWorkers != 50 {
		t.Errorf("expected MaxWorkers=50, got %d", cfg.Server.MaxWorkers)
	}
	if cfg.SMTP.MaxConnections != 500 {
		t.Errorf("expected MaxConnections=500, got %d", cfg.SMTP.MaxConnections)
	}
	// Defaults should be applied
	if cfg.SMTP.MaxMessageSize != 50*1024*1024 {
		t.Errorf("expected default MaxMessageSize, got %d", cfg.SMTP.MaxMessageSize)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestParseRetryIntervals_Default(t *testing.T) {
	q := &QueueConfig{}
	intervals, err := q.ParseRetryIntervals()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(intervals) != 9 {
		t.Errorf("expected 9 default intervals, got %d", len(intervals))
	}
	if intervals[0] != 5*time.Minute {
		t.Errorf("expected first interval 5m, got %v", intervals[0])
	}
}

func TestParseRetryIntervals_Custom(t *testing.T) {
	q := &QueueConfig{
		RetryIntervals: []string{"1m", "5m", "30m"},
	}
	intervals, err := q.ParseRetryIntervals()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(intervals) != 3 {
		t.Errorf("expected 3 intervals, got %d", len(intervals))
	}
}

func TestParseRetryIntervals_Invalid(t *testing.T) {
	q := &QueueConfig{
		RetryIntervals: []string{"1m", "invalid"},
	}
	_, err := q.ParseRetryIntervals()
	if err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestMergeConfig(t *testing.T) {
	dst := &Config{}
	src := &Config{}
	src.Server.Hostname = "override.example.com"
	src.SMTP.MaxConnections = 2000

	mergeConfig(dst, src)

	if dst.Server.Hostname != "override.example.com" {
		t.Errorf("expected hostname override, got %s", dst.Server.Hostname)
	}
	if dst.SMTP.MaxConnections != 2000 {
		t.Errorf("expected MaxConnections=2000, got %d", dst.SMTP.MaxConnections)
	}
}

func TestDSN(t *testing.T) {
	d := &DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "srmta",
		Password: "secret",
		DBName:   "srmta",
		SSLMode:  "disable",
	}
	dsn := d.DSN()
	if dsn == "" {
		t.Fatal("DSN should not be empty")
	}
	if !contains(dsn, "host=localhost") || !contains(dsn, "port=5432") {
		t.Errorf("DSN missing expected fields: %s", dsn)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsStr(s, sub)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
