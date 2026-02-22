// Package config provides YAML-based configuration loading for the SRMTA mail transfer platform.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for SRMTA.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	SMTP      SMTPConfig      `yaml:"smtp"`
	Queue     QueueConfig     `yaml:"queue"`
	Delivery  DeliveryConfig  `yaml:"delivery"`
	DNS       DNSConfig       `yaml:"dns"`
	IPPool    IPPoolConfig    `yaml:"ip_pool"`
	DKIM      DKIMConfig      `yaml:"dkim"`
	Bounce    BounceConfig    `yaml:"bounce"`
	Logging   LoggingConfig   `yaml:"logging"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	TLS       TLSConfig       `yaml:"tls"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// ServerConfig holds general server settings.
type ServerConfig struct {
	Hostname      string        `yaml:"hostname"`
	ListenAddr    string        `yaml:"listen_addr"`
	MaxWorkers    int           `yaml:"max_workers"`
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`
}

// SMTPConfig holds inbound SMTP server settings.
type SMTPConfig struct {
	ListenAddr       string        `yaml:"listen_addr"`
	MaxConnections   int           `yaml:"max_connections"`
	MaxMessageSize   int64         `yaml:"max_message_size"`
	ReadTimeout      time.Duration `yaml:"read_timeout"`
	WriteTimeout     time.Duration `yaml:"write_timeout"`
	MaxRecipients    int           `yaml:"max_recipients"`
	RequireAuth      bool          `yaml:"require_auth"`
	RequireTLS       bool          `yaml:"require_tls"`
	BannerHostname   string        `yaml:"banner_hostname"`
	AllowedDomains   []string      `yaml:"allowed_domains"`
	EnablePipelining bool          `yaml:"enable_pipelining"`
}

// QueueConfig holds queue management settings.
type QueueConfig struct {
	SpoolDir          string        `yaml:"spool_dir"`
	MaxQueueDepth     int64         `yaml:"max_queue_depth"`
	MaxRetries        int           `yaml:"max_retries"`
	RetryIntervals    []string      `yaml:"retry_intervals"`
	DeadLetterAfter   time.Duration `yaml:"dead_letter_after"`
	JournalEnabled    bool          `yaml:"journal_enabled"`
	ShardCount        int           `yaml:"shard_count"`
	DomainBuckets     int           `yaml:"domain_buckets"`
	ProcessingWorkers int           `yaml:"processing_workers"`
}

// DeliveryConfig holds outbound delivery settings.
type DeliveryConfig struct {
	MaxConcurrent        int           `yaml:"max_concurrent"`
	PerDomainConcurrency int           `yaml:"per_domain_concurrency"`
	ConnectionTimeout    time.Duration `yaml:"connection_timeout"`
	DialTimeout          time.Duration `yaml:"dial_timeout"`
	EHLOTimeout          time.Duration `yaml:"ehlo_timeout"`
	MailTimeout          time.Duration `yaml:"mail_timeout"`
	RcptTimeout          time.Duration `yaml:"rcpt_timeout"`
	DataTimeout          time.Duration `yaml:"data_timeout"`
	PoolSize             int           `yaml:"pool_size"`
	PoolIdleTimeout      time.Duration `yaml:"pool_idle_timeout"`
}

// DNSConfig holds DNS resolver settings.
type DNSConfig struct {
	Servers       []string      `yaml:"servers"`
	CacheTTL      time.Duration `yaml:"cache_ttl"`
	CacheSize     int           `yaml:"cache_size"`
	Timeout       time.Duration `yaml:"timeout"`
	PoolSize      int           `yaml:"pool_size"`
	UseRedisCache bool          `yaml:"use_redis_cache"`
	EnableDNSSEC  bool          `yaml:"enable_dnssec"`
}

// IPPoolConfig holds IP pool and health scoring settings.
type IPPoolConfig struct {
	IPs              []IPConfig `yaml:"ips"`
	HealthWindow     time.Duration `yaml:"health_window"`
	DisableThreshold float64       `yaml:"disable_threshold"`
	RecoveryTime     time.Duration `yaml:"recovery_time"`
}

// IPConfig defines a single IP in the pool.
type IPConfig struct {
	Address  string `yaml:"address"`
	Version  int    `yaml:"version"` // 4 or 6
	Weight   int    `yaml:"weight"`
	WarmUp   bool   `yaml:"warm_up"`
	MaxRate  int    `yaml:"max_rate"` // emails/hour during warm-up
	Disabled bool   `yaml:"disabled"`
}

// DKIMConfig holds DKIM signing settings.
type DKIMConfig struct {
	Enabled    bool         `yaml:"enabled"`
	Keys       []DKIMKey    `yaml:"keys"`
	DefaultKey string       `yaml:"default_key"`
}

// DKIMKey defines a DKIM signing key.
type DKIMKey struct {
	Selector   string `yaml:"selector"`
	Domain     string `yaml:"domain"`
	PrivateKey string `yaml:"private_key_path"`
	Algorithm  string `yaml:"algorithm"` // rsa-sha256, ed25519-sha256
}

// BounceConfig holds bounce processing settings.
type BounceConfig struct {
	HardBounceThreshold    float64 `yaml:"hard_bounce_threshold"`
	SoftBounceThreshold    float64 `yaml:"soft_bounce_threshold"`
	ComplaintThreshold     float64 `yaml:"complaint_threshold"`
	SenderPauseEnabled     bool    `yaml:"sender_pause_enabled"`
	SuppressionListEnabled bool    `yaml:"suppression_list_enabled"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level       string `yaml:"level"` // debug, info, warn, error
	Format      string `yaml:"format"` // json, text
	Output      string `yaml:"output"` // stdout, file
	FilePath    string `yaml:"file_path"`
	MaxSizeMB   int    `yaml:"max_size_mb"`
	MaxBackups  int    `yaml:"max_backups"`
	MaxAgeDays  int    `yaml:"max_age_days"`
	Compress    bool   `yaml:"compress"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	DBName       string `yaml:"dbname"`
	SSLMode      string `yaml:"ssl_mode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"pool_size"`
}

// TLSConfig holds TLS settings.
type TLSConfig struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	MinVersion string `yaml:"min_version"` // 1.2, 1.3
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	GlobalRate    int `yaml:"global_rate"`    // emails/sec
	PerDomainRate int `yaml:"per_domain_rate"` // emails/sec per domain
	PerSenderRate int `yaml:"per_sender_rate"` // emails/sec per sender
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Expand environment variables in config
	expanded := os.ExpandEnv(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	applyDefaults(cfg)
	return cfg, nil
}

// applyDefaults sets sensible defaults for unset configuration values.
func applyDefaults(cfg *Config) {
	if cfg.Server.Hostname == "" {
		hostname, _ := os.Hostname()
		cfg.Server.Hostname = hostname
	}
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.MaxWorkers == 0 {
		cfg.Server.MaxWorkers = 100
	}
	if cfg.Server.ShutdownGrace == 0 {
		cfg.Server.ShutdownGrace = 30 * time.Second
	}
	if cfg.SMTP.ListenAddr == "" {
		cfg.SMTP.ListenAddr = ":2525"
	}
	if cfg.SMTP.MaxConnections == 0 {
		cfg.SMTP.MaxConnections = 1000
	}
	if cfg.SMTP.MaxMessageSize == 0 {
		cfg.SMTP.MaxMessageSize = 50 * 1024 * 1024 // 50MB
	}
	if cfg.SMTP.ReadTimeout == 0 {
		cfg.SMTP.ReadTimeout = 60 * time.Second
	}
	if cfg.SMTP.WriteTimeout == 0 {
		cfg.SMTP.WriteTimeout = 60 * time.Second
	}
	if cfg.SMTP.MaxRecipients == 0 {
		cfg.SMTP.MaxRecipients = 100
	}
	if cfg.Queue.SpoolDir == "" {
		cfg.Queue.SpoolDir = "/var/spool/srmta"
	}
	if cfg.Queue.MaxQueueDepth == 0 {
		cfg.Queue.MaxQueueDepth = 500000
	}
	if cfg.Queue.MaxRetries == 0 {
		cfg.Queue.MaxRetries = 10
	}
	if cfg.Queue.ProcessingWorkers == 0 {
		cfg.Queue.ProcessingWorkers = 50
	}
	if cfg.Queue.ShardCount == 0 {
		cfg.Queue.ShardCount = 16
	}
	if cfg.Queue.DomainBuckets == 0 {
		cfg.Queue.DomainBuckets = 256
	}
	if cfg.Delivery.MaxConcurrent == 0 {
		cfg.Delivery.MaxConcurrent = 500
	}
	if cfg.Delivery.PerDomainConcurrency == 0 {
		cfg.Delivery.PerDomainConcurrency = 20
	}
	if cfg.Delivery.DialTimeout == 0 {
		cfg.Delivery.DialTimeout = 30 * time.Second
	}
	if cfg.Delivery.ConnectionTimeout == 0 {
		cfg.Delivery.ConnectionTimeout = 300 * time.Second
	}
	if cfg.DNS.CacheTTL == 0 {
		cfg.DNS.CacheTTL = 300 * time.Second
	}
	if cfg.DNS.CacheSize == 0 {
		cfg.DNS.CacheSize = 10000
	}
	if cfg.DNS.Timeout == 0 {
		cfg.DNS.Timeout = 5 * time.Second
	}
	if cfg.DNS.PoolSize == 0 {
		cfg.DNS.PoolSize = 10
	}
	if cfg.Metrics.ListenAddr == "" {
		cfg.Metrics.ListenAddr = ":9090"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 5432
	}
	if cfg.Database.SSLMode == "" {
		cfg.Database.SSLMode = "prefer"
	}
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 25
	}
	if cfg.Database.MaxIdleConns == 0 {
		cfg.Database.MaxIdleConns = 5
	}
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "localhost:6379"
	}
	if cfg.Redis.PoolSize == 0 {
		cfg.Redis.PoolSize = 10
	}
	if cfg.TLS.MinVersion == "" {
		cfg.TLS.MinVersion = "1.2"
	}
}

// DSN returns the PostgreSQL connection string.
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode,
	)
}

// ParseRetryIntervals converts string durations to time.Duration slices.
func (q *QueueConfig) ParseRetryIntervals() ([]time.Duration, error) {
	if len(q.RetryIntervals) == 0 {
		// Default retry schedule: exponential backoff
		return []time.Duration{
			5 * time.Minute,
			15 * time.Minute,
			30 * time.Minute,
			1 * time.Hour,
			2 * time.Hour,
			4 * time.Hour,
			8 * time.Hour,
			16 * time.Hour,
			24 * time.Hour,
		}, nil
	}
	intervals := make([]time.Duration, len(q.RetryIntervals))
	for i, s := range q.RetryIntervals {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid retry interval %q: %w", s, err)
		}
		intervals[i] = d
	}
	return intervals, nil
}
