// Package config provides YAML-based configuration loading for the SRMTA mail transfer platform.
// Supports a centralized config file with optional sub-configs in config.d/*.yaml.
//
// Loading order:
//  1. Main config file (e.g. /etc/srmta/config.yaml)
//  2. All *.yaml files in config.d/ directory (sorted alphabetically)
//
// Sub-configs are deep-merged on top of the main config, allowing operators to
// split concerns (SMTP settings, DKIM keys, IP pool, etc.) into separate files.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	TLS       TLSConfig       `yaml:"tls"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Throttle  ThrottleConfig  `yaml:"throttle"`
	Routing   RoutingConfig   `yaml:"routing"`
	ConfigDir string          `yaml:"config_dir"`
}

// ServerConfig holds general server settings.
type ServerConfig struct {
	Hostname      string        `yaml:"hostname"`
	ListenAddr    string        `yaml:"listen_addr"`
	MaxWorkers    int           `yaml:"max_workers"`
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`
}

// SMTPConfig holds SMTP server settings for inbound and outbound traffic.
type SMTPConfig struct {
	ListenAddr         string        `yaml:"listen_addr"`     // Deprecated: use inbound_addr instead
	InboundAddr        string        `yaml:"inbound_addr"`    // Inbound (receiving) listen address, e.g. ":25"
	OutboundPort       int           `yaml:"outbound_port"`   // Outbound (sending) port, e.g. 587
	SubmissionAddr     string        `yaml:"submission_addr"` // MSA submission listen address, e.g. ":587"
	MaxConnections     int           `yaml:"max_connections"`
	MaxMessageSize     int64         `yaml:"max_message_size"`
	ReadTimeout        time.Duration `yaml:"read_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout"`
	MaxRecipients      int           `yaml:"max_recipients"`
	RequireAuth        bool          `yaml:"require_auth"`
	RequireTLS         bool          `yaml:"require_tls"`
	BannerHostname     string        `yaml:"banner_hostname"`
	AllowedDomains     []string      `yaml:"allowed_domains"`
	AllowedDomainsFile string        `yaml:"allowed_domains_file"` // Path to allowed_domains.ini
	AllowedIPsFile     string        `yaml:"allowed_ips_file"`     // Path to allowed_ips.ini
	EnablePipelining   bool          `yaml:"enable_pipelining"`
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
	Servers      []string      `yaml:"servers"`
	CacheTTL     time.Duration `yaml:"cache_ttl"`
	CacheSize    int           `yaml:"cache_size"`
	Timeout      time.Duration `yaml:"timeout"`
	PoolSize     int           `yaml:"pool_size"`
	EnableDNSSEC bool          `yaml:"enable_dnssec"`
}

// IPPoolConfig holds IP pool and health scoring settings.
type IPPoolConfig struct {
	IPs              []IPConfig    `yaml:"ips"`
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
	Enabled    bool      `yaml:"enabled"`
	Keys       []DKIMKey `yaml:"keys"`
	DefaultKey string    `yaml:"default_key"`
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
	Level           string `yaml:"level"`            // debug, info, warn, error
	Format          string `yaml:"format"`           // json, text
	Output          string `yaml:"output"`           // stdout, file
	FilePath        string `yaml:"file_path"`        // General log file (all levels)
	ErrorFile       string `yaml:"error_file"`       // Error log: /var/log/srmta/error.log
	AccessFile      string `yaml:"access_file"`      // Access log: /var/log/srmta/access.log
	TransactionFile string `yaml:"transaction_file"` // Transaction CSV: /var/log/srmta/transaction.csv
	MaxSizeMB       int    `yaml:"max_size_mb"`
	MaxBackups      int    `yaml:"max_backups"`
	MaxAgeDays      int    `yaml:"max_age_days"`
	Compress        bool   `yaml:"compress"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Path       string `yaml:"path"`
}

// DatabaseConfig holds connection settings for PostgreSQL or MySQL/MariaDB.
type DatabaseConfig struct {
	Driver       string `yaml:"driver"` // "postgres" or "mysql" (default: postgres)
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	DBName       string `yaml:"dbname"`
	SSLMode      string `yaml:"ssl_mode"` // postgres: disable/require/verify-full; mysql: true/false/skip-verify
	Charset      string `yaml:"charset"`  // MySQL charset (default: utf8mb4)
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
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
	GlobalRate    int `yaml:"global_rate"`     // emails/sec
	PerDomainRate int `yaml:"per_domain_rate"` // emails/sec per domain
	PerSenderRate int `yaml:"per_sender_rate"` // emails/sec per sender
}

// ThrottleConfig holds per-provider speed management settings.
type ThrottleConfig struct {
	Defaults  ThrottleProviderRule   `yaml:"defaults"`
	Providers []ThrottleProviderRule `yaml:"providers"`
}

// ThrottleProviderRule defines speed limits for a specific provider.
type ThrottleProviderRule struct {
	Name              string        `yaml:"name"`
	MXPatterns        []string      `yaml:"mx_patterns"`
	DomainPatterns    []string      `yaml:"domain_patterns"`
	MaxConnections    int           `yaml:"max_connections"`
	MaxPerSecond      int           `yaml:"max_per_second"`
	MaxPerMinute      int           `yaml:"max_per_minute"`
	MaxPerHour        int           `yaml:"max_per_hour"`
	MaxRecipientsConn int           `yaml:"max_recipients_conn"`
	ConnectionDelay   time.Duration `yaml:"connection_delay"`
	MessageDelay      time.Duration `yaml:"message_delay"`
	BackoffMultiplier float64       `yaml:"backoff_multiplier"`
	MaxBackoff        time.Duration `yaml:"max_backoff"`
}

// RoutingConfig holds MX-based IP routing settings.
type RoutingConfig struct {
	Routes       []ProviderRoute    `yaml:"routes"`
	FallbackIPs  []string           `yaml:"fallback_ips"`
	SenderRoutes []SenderRouteEntry `yaml:"sender_routes"` // Sender domain → IP/subnet binding
}

// SenderRouteEntry binds a sender (FROM) domain to specific IPs or subnets.
type SenderRouteEntry struct {
	Domain     string   `yaml:"domain"`      // Sender domain (e.g., "example.com") or wildcard "*.example.com"
	IPs        []string `yaml:"ips"`         // Specific IPs to use for this sender domain
	Subnets    []string `yaml:"subnets"`     // CIDR subnets to select IPs from (e.g., "10.0.1.0/24")
	BackupIPs  []string `yaml:"backup_ips"`  // Backup IPs if primaries are unhealthy
}

// ProviderRoute maps a provider to dedicated IPs with fallback.
type ProviderRoute struct {
	Name           string   `yaml:"name"`
	MXPatterns     []string `yaml:"mx_patterns"`
	DomainPatterns []string `yaml:"domain_patterns"`
	PrimaryIPs     []string `yaml:"primary_ips"`
	BackupIPs      []string `yaml:"backup_ips"`
}

// Load reads the main YAML configuration file and merges any sub-configs
// found in the config.d/ directory. Sub-configs are loaded in alphabetical
// order and deep-merged on top of the main config, so later files override
// earlier ones for scalar values, and extend slices/maps.
//
// The config.d directory is resolved as follows:
//  1. If config_dir is set in the main config, use that path
//  2. Otherwise, look for a config.d/ directory next to the main config file
//
// Each sub-config file can contain any subset of the full Config schema.
// Example layout:
//
//	/etc/srmta/config.yaml           ← main config (server, smtp, queue, etc.)
//	/etc/srmta/config.d/10-smtp.yaml ← SMTP overrides
//	/etc/srmta/config.d/20-dkim.yaml ← DKIM key config
//	/etc/srmta/config.d/30-ips.yaml  ← IP pool config
//	/etc/srmta/config.d/40-db.yaml   ← Database credentials
func Load(path string) (*Config, error) {
	// ── Step 1: Load the main config file ────────────────────────────
	cfg, err := loadSingleFile(path)
	if err != nil {
		return nil, fmt.Errorf("main config: %w", err)
	}

	// ── Step 2: Resolve config.d directory ───────────────────────────
	configDir := cfg.ConfigDir
	if configDir == "" {
		// Default: config.d/ next to the main config file
		configDir = filepath.Join(filepath.Dir(path), "config.d")
	}

	// ── Step 3: Load and merge sub-configs ───────────────────────────
	if err := mergeConfigDir(cfg, configDir); err != nil {
		// config.d not existing is not an error — it's optional
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config.d merge: %w", err)
		}
	}

	applyDefaults(cfg)
	return cfg, nil
}

// loadSingleFile reads, env-expands, and unmarshals a single YAML file.
func loadSingleFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	expanded := os.ExpandEnv(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return cfg, nil
}

// mergeConfigDir loads all *.yaml and *.yml files from dir (sorted)
// and deep-merges each one on top of the provided config.
func mergeConfigDir(cfg *Config, dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// Glob both .yaml and .yml extensions
	var files []string
	for _, ext := range []string{"*.yaml", "*.yml"} {
		matches, err := filepath.Glob(filepath.Join(dir, ext))
		if err != nil {
			return fmt.Errorf("glob %s/%s: %w", dir, ext, err)
		}
		files = append(files, matches...)
	}

	// Sort alphabetically for deterministic merge order
	// Use numeric prefixes (10-smtp.yaml, 20-dkim.yaml) to control order
	sort.Strings(files)

	for _, file := range files {
		override, err := loadSingleFile(file)
		if err != nil {
			return fmt.Errorf("sub-config %s: %w", filepath.Base(file), err)
		}
		mergeConfig(cfg, override)
	}

	return nil
}

// mergeConfig deep-merges src into dst. Non-zero values in src override dst.
// For slices, src replaces dst entirely (if non-empty). For structs, each
// field is merged independently so partial overrides work.
func mergeConfig(dst, src *Config) {
	mergeServer(dst, src)
	mergeSMTP(dst, src)
	mergeQueue(dst, src)
	mergeDelivery(dst, src)
	mergeDNS(dst, src)
	mergeIPPool(dst, src)
	mergeDKIM(dst, src)
	mergeBounce(dst, src)
	mergeLogging(dst, src)
	mergeMetrics(dst, src)
	mergeDatabase(dst, src)
	mergeTLS(dst, src)
	mergeRateLimit(dst, src)
	mergeThrottle(dst, src)
	mergeRouting(dst, src)
}

func mergeServer(dst, src *Config) {
	if src.Server.Hostname != "" {
		dst.Server.Hostname = src.Server.Hostname
	}
	if src.Server.ListenAddr != "" {
		dst.Server.ListenAddr = src.Server.ListenAddr
	}
	if src.Server.MaxWorkers != 0 {
		dst.Server.MaxWorkers = src.Server.MaxWorkers
	}
	if src.Server.ShutdownGrace != 0 {
		dst.Server.ShutdownGrace = src.Server.ShutdownGrace
	}
}

func mergeSMTP(dst, src *Config) {
	if src.SMTP.ListenAddr != "" {
		dst.SMTP.ListenAddr = src.SMTP.ListenAddr
	}
	if src.SMTP.InboundAddr != "" {
		dst.SMTP.InboundAddr = src.SMTP.InboundAddr
	}
	if src.SMTP.OutboundPort != 0 {
		dst.SMTP.OutboundPort = src.SMTP.OutboundPort
	}
	if src.SMTP.SubmissionAddr != "" {
		dst.SMTP.SubmissionAddr = src.SMTP.SubmissionAddr
	}
	if src.SMTP.MaxConnections != 0 {
		dst.SMTP.MaxConnections = src.SMTP.MaxConnections
	}
	if src.SMTP.MaxMessageSize != 0 {
		dst.SMTP.MaxMessageSize = src.SMTP.MaxMessageSize
	}
	if src.SMTP.ReadTimeout != 0 {
		dst.SMTP.ReadTimeout = src.SMTP.ReadTimeout
	}
	if src.SMTP.WriteTimeout != 0 {
		dst.SMTP.WriteTimeout = src.SMTP.WriteTimeout
	}
	if src.SMTP.MaxRecipients != 0 {
		dst.SMTP.MaxRecipients = src.SMTP.MaxRecipients
	}
	if src.SMTP.RequireAuth {
		dst.SMTP.RequireAuth = true
	}
	if src.SMTP.RequireTLS {
		dst.SMTP.RequireTLS = true
	}
	if src.SMTP.BannerHostname != "" {
		dst.SMTP.BannerHostname = src.SMTP.BannerHostname
	}
	mergeAllowedFiles(dst, src)
	if src.SMTP.EnablePipelining {
		dst.SMTP.EnablePipelining = true
	}
}

// mergeAllowedFiles merges the access-control list fields (allowed domains/IPs) from src into dst.
func mergeAllowedFiles(dst, src *Config) {
	if len(src.SMTP.AllowedDomains) > 0 {
		dst.SMTP.AllowedDomains = src.SMTP.AllowedDomains
	}
	if src.SMTP.AllowedDomainsFile != "" {
		dst.SMTP.AllowedDomainsFile = src.SMTP.AllowedDomainsFile
	}
	if src.SMTP.AllowedIPsFile != "" {
		dst.SMTP.AllowedIPsFile = src.SMTP.AllowedIPsFile
	}
}

func mergeQueue(dst, src *Config) {
	if src.Queue.SpoolDir != "" {
		dst.Queue.SpoolDir = src.Queue.SpoolDir
	}
	if src.Queue.MaxQueueDepth != 0 {
		dst.Queue.MaxQueueDepth = src.Queue.MaxQueueDepth
	}
	if src.Queue.MaxRetries != 0 {
		dst.Queue.MaxRetries = src.Queue.MaxRetries
	}
	if len(src.Queue.RetryIntervals) > 0 {
		dst.Queue.RetryIntervals = src.Queue.RetryIntervals
	}
	if src.Queue.DeadLetterAfter != 0 {
		dst.Queue.DeadLetterAfter = src.Queue.DeadLetterAfter
	}
	if src.Queue.JournalEnabled {
		dst.Queue.JournalEnabled = true
	}
	if src.Queue.ShardCount != 0 {
		dst.Queue.ShardCount = src.Queue.ShardCount
	}
	if src.Queue.DomainBuckets != 0 {
		dst.Queue.DomainBuckets = src.Queue.DomainBuckets
	}
	if src.Queue.ProcessingWorkers != 0 {
		dst.Queue.ProcessingWorkers = src.Queue.ProcessingWorkers
	}
}

func mergeDelivery(dst, src *Config) {
	if src.Delivery.MaxConcurrent != 0 {
		dst.Delivery.MaxConcurrent = src.Delivery.MaxConcurrent
	}
	if src.Delivery.PerDomainConcurrency != 0 {
		dst.Delivery.PerDomainConcurrency = src.Delivery.PerDomainConcurrency
	}
	if src.Delivery.ConnectionTimeout != 0 {
		dst.Delivery.ConnectionTimeout = src.Delivery.ConnectionTimeout
	}
	if src.Delivery.DialTimeout != 0 {
		dst.Delivery.DialTimeout = src.Delivery.DialTimeout
	}
	if src.Delivery.EHLOTimeout != 0 {
		dst.Delivery.EHLOTimeout = src.Delivery.EHLOTimeout
	}
	if src.Delivery.MailTimeout != 0 {
		dst.Delivery.MailTimeout = src.Delivery.MailTimeout
	}
	if src.Delivery.RcptTimeout != 0 {
		dst.Delivery.RcptTimeout = src.Delivery.RcptTimeout
	}
	if src.Delivery.DataTimeout != 0 {
		dst.Delivery.DataTimeout = src.Delivery.DataTimeout
	}
	if src.Delivery.PoolSize != 0 {
		dst.Delivery.PoolSize = src.Delivery.PoolSize
	}
	if src.Delivery.PoolIdleTimeout != 0 {
		dst.Delivery.PoolIdleTimeout = src.Delivery.PoolIdleTimeout
	}
}

func mergeDNS(dst, src *Config) {
	if len(src.DNS.Servers) > 0 {
		dst.DNS.Servers = src.DNS.Servers
	}
	if src.DNS.CacheTTL != 0 {
		dst.DNS.CacheTTL = src.DNS.CacheTTL
	}
	if src.DNS.CacheSize != 0 {
		dst.DNS.CacheSize = src.DNS.CacheSize
	}
	if src.DNS.Timeout != 0 {
		dst.DNS.Timeout = src.DNS.Timeout
	}
	if src.DNS.PoolSize != 0 {
		dst.DNS.PoolSize = src.DNS.PoolSize
	}
	if src.DNS.EnableDNSSEC {
		dst.DNS.EnableDNSSEC = true
	}
}

func mergeIPPool(dst, src *Config) {
	if len(src.IPPool.IPs) > 0 {
		dst.IPPool.IPs = src.IPPool.IPs
	}
	if src.IPPool.HealthWindow != 0 {
		dst.IPPool.HealthWindow = src.IPPool.HealthWindow
	}
	if src.IPPool.DisableThreshold != 0 {
		dst.IPPool.DisableThreshold = src.IPPool.DisableThreshold
	}
	if src.IPPool.RecoveryTime != 0 {
		dst.IPPool.RecoveryTime = src.IPPool.RecoveryTime
	}
}

func mergeDKIM(dst, src *Config) {
	if src.DKIM.Enabled {
		dst.DKIM.Enabled = true
	}
	// DKIM keys are appended (not replaced) so keys from multiple sub-configs accumulate.
	if len(src.DKIM.Keys) > 0 {
		dst.DKIM.Keys = append(dst.DKIM.Keys, src.DKIM.Keys...)
	}
	if src.DKIM.DefaultKey != "" {
		dst.DKIM.DefaultKey = src.DKIM.DefaultKey
	}
}

func mergeBounce(dst, src *Config) {
	if src.Bounce.HardBounceThreshold != 0 {
		dst.Bounce.HardBounceThreshold = src.Bounce.HardBounceThreshold
	}
	if src.Bounce.SoftBounceThreshold != 0 {
		dst.Bounce.SoftBounceThreshold = src.Bounce.SoftBounceThreshold
	}
	if src.Bounce.ComplaintThreshold != 0 {
		dst.Bounce.ComplaintThreshold = src.Bounce.ComplaintThreshold
	}
	if src.Bounce.SenderPauseEnabled {
		dst.Bounce.SenderPauseEnabled = true
	}
	if src.Bounce.SuppressionListEnabled {
		dst.Bounce.SuppressionListEnabled = true
	}
}

func mergeLogging(dst, src *Config) {
	if src.Logging.Level != "" {
		dst.Logging.Level = src.Logging.Level
	}
	if src.Logging.Format != "" {
		dst.Logging.Format = src.Logging.Format
	}
	if src.Logging.Output != "" {
		dst.Logging.Output = src.Logging.Output
	}
	if src.Logging.FilePath != "" {
		dst.Logging.FilePath = src.Logging.FilePath
	}
	if src.Logging.MaxSizeMB != 0 {
		dst.Logging.MaxSizeMB = src.Logging.MaxSizeMB
	}
	if src.Logging.MaxBackups != 0 {
		dst.Logging.MaxBackups = src.Logging.MaxBackups
	}
	if src.Logging.MaxAgeDays != 0 {
		dst.Logging.MaxAgeDays = src.Logging.MaxAgeDays
	}
	if src.Logging.Compress {
		dst.Logging.Compress = true
	}
}

func mergeMetrics(dst, src *Config) {
	if src.Metrics.Enabled {
		dst.Metrics.Enabled = true
	}
	if src.Metrics.ListenAddr != "" {
		dst.Metrics.ListenAddr = src.Metrics.ListenAddr
	}
	if src.Metrics.Path != "" {
		dst.Metrics.Path = src.Metrics.Path
	}
}

func mergeDatabase(dst, src *Config) {
	if src.Database.Host != "" {
		dst.Database.Host = src.Database.Host
	}
	if src.Database.Port != 0 {
		dst.Database.Port = src.Database.Port
	}
	if src.Database.User != "" {
		dst.Database.User = src.Database.User
	}
	if src.Database.Password != "" {
		dst.Database.Password = src.Database.Password
	}
	if src.Database.DBName != "" {
		dst.Database.DBName = src.Database.DBName
	}
	if src.Database.SSLMode != "" {
		dst.Database.SSLMode = src.Database.SSLMode
	}
	if src.Database.MaxOpenConns != 0 {
		dst.Database.MaxOpenConns = src.Database.MaxOpenConns
	}
	if src.Database.MaxIdleConns != 0 {
		dst.Database.MaxIdleConns = src.Database.MaxIdleConns
	}
}

func mergeTLS(dst, src *Config) {
	if src.TLS.CertFile != "" {
		dst.TLS.CertFile = src.TLS.CertFile
	}
	if src.TLS.KeyFile != "" {
		dst.TLS.KeyFile = src.TLS.KeyFile
	}
	if src.TLS.CAFile != "" {
		dst.TLS.CAFile = src.TLS.CAFile
	}
	if src.TLS.MinVersion != "" {
		dst.TLS.MinVersion = src.TLS.MinVersion
	}
}

func mergeRateLimit(dst, src *Config) {
	if src.RateLimit.GlobalRate != 0 {
		dst.RateLimit.GlobalRate = src.RateLimit.GlobalRate
	}
	if src.RateLimit.PerDomainRate != 0 {
		dst.RateLimit.PerDomainRate = src.RateLimit.PerDomainRate
	}
	if src.RateLimit.PerSenderRate != 0 {
		dst.RateLimit.PerSenderRate = src.RateLimit.PerSenderRate
	}
}

func mergeThrottle(dst, src *Config) {
	// Providers replace entirely if set.
	if len(src.Throttle.Providers) > 0 {
		dst.Throttle.Providers = src.Throttle.Providers
	}
	// Defaults struct is replaced when MaxConnections is non-zero.
	if src.Throttle.Defaults.MaxConnections != 0 {
		dst.Throttle.Defaults = src.Throttle.Defaults
	}
}

func mergeRouting(dst, src *Config) {
	// Routes, FallbackIPs, and SenderRoutes replace entirely if set.
	if len(src.Routing.Routes) > 0 {
		dst.Routing.Routes = src.Routing.Routes
	}
	if len(src.Routing.FallbackIPs) > 0 {
		dst.Routing.FallbackIPs = src.Routing.FallbackIPs
	}
	if len(src.Routing.SenderRoutes) > 0 {
		dst.Routing.SenderRoutes = src.Routing.SenderRoutes
	}
}

// applyDefaults sets sensible defaults for unset configuration values.
func applyDefaults(cfg *Config) {
	applyServerDefaults(cfg)
	applySMTPDefaults(cfg)
	applyQueueDefaults(cfg)
	applyDeliveryDefaults(cfg)
	applyDNSDefaults(cfg)
	applyLoggingDefaults(cfg)
	applyMetricsDefaults(cfg)
	applyDatabaseDefaults(cfg)
	applyTLSDefaults(cfg)
}

func applyServerDefaults(cfg *Config) {
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
}

func applySMTPDefaults(cfg *Config) {
	// Backward compat: if listen_addr is set but inbound_addr is not, use listen_addr.
	if cfg.SMTP.InboundAddr == "" {
		if cfg.SMTP.ListenAddr != "" {
			cfg.SMTP.InboundAddr = cfg.SMTP.ListenAddr
		} else {
			cfg.SMTP.InboundAddr = ":25"
		}
	}
	if cfg.SMTP.OutboundPort == 0 {
		cfg.SMTP.OutboundPort = 25
	}
	if cfg.SMTP.SubmissionAddr == "" {
		cfg.SMTP.SubmissionAddr = ":587"
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
}

func applyQueueDefaults(cfg *Config) {
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
}

func applyDeliveryDefaults(cfg *Config) {
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
}

func applyDNSDefaults(cfg *Config) {
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
}

func applyLoggingDefaults(cfg *Config) {
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
}

func applyMetricsDefaults(cfg *Config) {
	if cfg.Metrics.ListenAddr == "" {
		cfg.Metrics.ListenAddr = ":9090"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
}

func applyDatabaseDefaults(cfg *Config) {
	if cfg.Database.Port == 0 {
		cfg.Database.Port = 5432
	}
	if cfg.Database.SSLMode == "" {
		cfg.Database.SSLMode = "require"
	}
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 25
	}
	if cfg.Database.MaxIdleConns == 0 {
		cfg.Database.MaxIdleConns = 5
	}
}

func applyTLSDefaults(cfg *Config) {
	if cfg.TLS.MinVersion == "" {
		cfg.TLS.MinVersion = "1.2"
	}
}

// DSN returns the database connection string for the configured driver.
func (d *DatabaseConfig) DSN() string {
	switch d.Driver {
	case "mysql":
		return d.mysqlDSN()
	default: // postgres
		return d.postgresDSN()
	}
}

// postgresDSN returns a PostgreSQL connection string.
func (d *DatabaseConfig) postgresDSN() string {
	sslMode := d.SSLMode
	if sslMode == "" {
		sslMode = "prefer"
	}
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, sslMode,
	)
}

// mysqlDSN returns a MySQL/MariaDB connection string.
// Format: user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=True&loc=UTC
func (d *DatabaseConfig) mysqlDSN() string {
	charset := d.Charset
	if charset == "" {
		charset = "utf8mb4"
	}
	tlsParam := ""
	if d.SSLMode != "" && d.SSLMode != "disable" && d.SSLMode != "false" {
		tlsParam = "&tls=" + d.SSLMode
	}
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=UTC&timeout=10s&readTimeout=30s&writeTimeout=30s%s",
		d.User, d.Password, d.Host, d.Port, d.DBName, charset, tlsParam,
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

// Validate checks the configuration for errors and returns a descriptive error
// if any required values are missing or invalid. Called automatically by Load().
func (c *Config) Validate() error {
	var errs []string
	errs = append(errs, validateServer(&c.Server)...)
	errs = append(errs, validateSMTP(&c.SMTP)...)
	errs = append(errs, validateTLS(&c.TLS)...)
	errs = append(errs, validateQueue(&c.Queue)...)
	errs = append(errs, validateRateLimit(&c.RateLimit)...)
	errs = append(errs, validateDelivery(&c.Delivery)...)
	errs = append(errs, validateDatabase(&c.Database)...)
	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", joinStrings(errs, "\n  - "))
	}
	return nil
}

func validateServer(s *ServerConfig) []string {
	var errs []string
	if s.Hostname == "" {
		errs = append(errs, "server.hostname must not be empty")
	}
	if s.MaxWorkers < 1 {
		errs = append(errs, "server.max_workers must be >= 1")
	}
	if s.ShutdownGrace < time.Second {
		errs = append(errs, "server.shutdown_grace must be >= 1s")
	}
	return errs
}

func validateSMTP(s *SMTPConfig) []string {
	var errs []string
	if s.MaxConnections < 1 {
		errs = append(errs, "smtp.max_connections must be >= 1")
	}
	if s.MaxMessageSize < 1024 {
		errs = append(errs, "smtp.max_message_size must be >= 1024 bytes")
	}
	if s.MaxRecipients < 1 {
		errs = append(errs, "smtp.max_recipients must be >= 1")
	}
	return errs
}

func validateTLS(t *TLSConfig) []string {
	var errs []string
	// cert and key must both be set, or both empty
	if (t.CertFile == "") != (t.KeyFile == "") {
		errs = append(errs, "tls.cert_file and tls.key_file must both be set or both empty")
	}
	if t.CertFile != "" {
		if _, err := os.Stat(t.CertFile); err != nil {
			errs = append(errs, fmt.Sprintf("tls.cert_file not found: %s", t.CertFile))
		}
	}
	if t.KeyFile != "" {
		if _, err := os.Stat(t.KeyFile); err != nil {
			errs = append(errs, fmt.Sprintf("tls.key_file not found: %s", t.KeyFile))
		}
	}
	if t.MinVersion != "" && t.MinVersion != "1.2" && t.MinVersion != "1.3" {
		errs = append(errs, "tls.min_version must be '1.2' or '1.3'")
	}
	return errs
}

func validateQueue(q *QueueConfig) []string {
	var errs []string
	if q.MaxRetries < 0 {
		errs = append(errs, "queue.max_retries must be >= 0")
	}
	if q.ShardCount < 1 {
		errs = append(errs, "queue.shard_count must be >= 1")
	}
	if len(q.RetryIntervals) > 0 {
		if _, err := q.ParseRetryIntervals(); err != nil {
			errs = append(errs, fmt.Sprintf("queue.retry_intervals: %v", err))
		}
	}
	return errs
}

func validateRateLimit(r *RateLimitConfig) []string {
	var errs []string
	if r.GlobalRate < 0 {
		errs = append(errs, "rate_limit.global_rate must be >= 0")
	}
	if r.PerDomainRate < 0 {
		errs = append(errs, "rate_limit.per_domain_rate must be >= 0")
	}
	if r.PerSenderRate < 0 {
		errs = append(errs, "rate_limit.per_sender_rate must be >= 0")
	}
	return errs
}

func validateDelivery(d *DeliveryConfig) []string {
	var errs []string
	if d.MaxConcurrent < 1 {
		errs = append(errs, "delivery.max_concurrent must be >= 1")
	}
	if d.PerDomainConcurrency < 1 {
		errs = append(errs, "delivery.per_domain_concurrency must be >= 1")
	}
	return errs
}

func validateDatabase(d *DatabaseConfig) []string {
	var errs []string
	// If host is set, user and dbname are also required.
	if d.Host != "" {
		if d.User == "" {
			errs = append(errs, "database.user required when database.host is set")
		}
		if d.DBName == "" {
			errs = append(errs, "database.dbname required when database.host is set")
		}
	}
	return errs
}

// joinStrings joins a slice of strings with a separator.
func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
