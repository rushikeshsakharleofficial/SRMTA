// Package throttle provides smart per-destination speed management for outbound
// delivery. Each major email provider (Outlook, Google, Yahoo, etc.) has
// different rate acceptance thresholds. This module enforces per-provider
// concurrency limits, messages-per-second caps, connection cooldowns, and
// adaptive backoff when 4xx throttling responses are detected.
//
// Throttle rules are loaded from config and can be adjusted at runtime.
package throttle

import (
	"strings"
	"sync"
	"time"
)

// ProviderRule defines speed limits for a specific email provider or MX group.
type ProviderRule struct {
	Name              string        `yaml:"name"`                // Human-readable name (e.g., "Microsoft/Outlook")
	MXPatterns        []string      `yaml:"mx_patterns"`         // MX hostname patterns (e.g., "*.outlook.com")
	DomainPatterns    []string      `yaml:"domain_patterns"`     // Recipient domain patterns (e.g., "outlook.com", "hotmail.com")
	MaxConnections    int           `yaml:"max_connections"`     // Max simultaneous TCP connections
	MaxPerSecond      int           `yaml:"max_per_second"`      // Max messages/sec to this provider
	MaxPerMinute      int           `yaml:"max_per_minute"`      // Max messages/min (soft cap)
	MaxPerHour        int           `yaml:"max_per_hour"`        // Max messages/hour
	MaxRecipientsConn int           `yaml:"max_recipients_conn"` // Max RCPT TO per connection
	ConnectionDelay   time.Duration `yaml:"connection_delay"`    // Delay between new connections
	MessageDelay      time.Duration `yaml:"message_delay"`       // Delay between messages on same connection
	BackoffMultiplier float64       `yaml:"backoff_multiplier"`  // Multiply delays on 4xx responses
	MaxBackoff        time.Duration `yaml:"max_backoff"`         // Maximum backoff duration
}

// Manager tracks per-provider throttle state and enforces speed limits.
type Manager struct {
	mu       sync.RWMutex
	rules    []ProviderRule
	state    map[string]*providerState // keyed by provider name
	defaults ProviderRule              // fallback for unknown providers
}

// providerState tracks live counters for a provider.
type providerState struct {
	mu             sync.Mutex
	activeConns    int
	sentThisSecond int
	sentThisMinute int
	sentThisHour   int
	lastSend       time.Time
	lastConnection time.Time
	currentBackoff time.Duration
	secondReset    time.Time
	minuteReset    time.Time
	hourReset      time.Time
	consecutive4xx int
}

// NewManager creates a speed manager with the given provider rules.
func NewManager(rules []ProviderRule, defaults ProviderRule) *Manager {
	m := &Manager{
		rules:    rules,
		state:    make(map[string]*providerState),
		defaults: defaults,
	}

	// Apply sensible defaults to the fallback rule
	if m.defaults.MaxConnections == 0 {
		m.defaults.MaxConnections = 10
	}
	if m.defaults.MaxPerSecond == 0 {
		m.defaults.MaxPerSecond = 20
	}
	if m.defaults.MaxPerMinute == 0 {
		m.defaults.MaxPerMinute = 500
	}
	if m.defaults.MaxPerHour == 0 {
		m.defaults.MaxPerHour = 10000
	}
	if m.defaults.MaxRecipientsConn == 0 {
		m.defaults.MaxRecipientsConn = 100
	}
	if m.defaults.BackoffMultiplier == 0 {
		m.defaults.BackoffMultiplier = 2.0
	}
	if m.defaults.MaxBackoff == 0 {
		m.defaults.MaxBackoff = 5 * time.Minute
	}

	return m
}

// MatchProvider finds the provider rule matching the given MX hostname or
// recipient domain. Returns the rule and provider name.
func (m *Manager) MatchProvider(mxHost, recipientDomain string) (ProviderRule, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mxHost = strings.ToLower(mxHost)
	recipientDomain = strings.ToLower(recipientDomain)

	for _, rule := range m.rules {
		// Check MX patterns first
		for _, pattern := range rule.MXPatterns {
			if matchPattern(mxHost, strings.ToLower(pattern)) {
				return rule, rule.Name
			}
		}
		// Check domain patterns
		for _, pattern := range rule.DomainPatterns {
			if matchPattern(recipientDomain, strings.ToLower(pattern)) {
				return rule, rule.Name
			}
		}
	}

	return m.defaults, "default"
}

// Acquire requests permission to send a message to the given provider.
// Returns the wait duration before sending, or blocks until a slot is available.
// Returns (delay, true) if allowed, (0, false) if the provider is over capacity.
func (m *Manager) Acquire(providerName string, rule ProviderRule) (time.Duration, bool) {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()

	// Reset rolling windows
	if now.After(state.secondReset) {
		state.sentThisSecond = 0
		state.secondReset = now.Add(time.Second)
	}
	if now.After(state.minuteReset) {
		state.sentThisMinute = 0
		state.minuteReset = now.Add(time.Minute)
	}
	if now.After(state.hourReset) {
		state.sentThisHour = 0
		state.hourReset = now.Add(time.Hour)
	}

	// Check rate limits
	if rule.MaxPerSecond > 0 && state.sentThisSecond >= rule.MaxPerSecond {
		return state.secondReset.Sub(now), false
	}
	if rule.MaxPerMinute > 0 && state.sentThisMinute >= rule.MaxPerMinute {
		return state.minuteReset.Sub(now), false
	}
	if rule.MaxPerHour > 0 && state.sentThisHour >= rule.MaxPerHour {
		return state.hourReset.Sub(now), false
	}

	// Calculate delay based on backoff
	var delay time.Duration
	if rule.MessageDelay > 0 {
		nextAllowed := state.lastSend.Add(rule.MessageDelay)
		if now.Before(nextAllowed) {
			delay = nextAllowed.Sub(now)
		}
	}

	// Apply backoff if we've seen 4xx responses
	if state.currentBackoff > 0 {
		delay += state.currentBackoff
	}

	// Record the send
	state.sentThisSecond++
	state.sentThisMinute++
	state.sentThisHour++
	state.lastSend = now

	return delay, true
}

// AcquireConnection requests permission to open a new TCP connection.
// Returns true if under the max connections limit.
func (m *Manager) AcquireConnection(providerName string, rule ProviderRule) bool {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	if rule.MaxConnections > 0 && state.activeConns >= rule.MaxConnections {
		return false
	}

	state.activeConns++
	state.lastConnection = time.Now()
	return true
}

// ReleaseConnection decrements the active connection count for a provider.
func (m *Manager) ReleaseConnection(providerName string) {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.activeConns > 0 {
		state.activeConns--
	}
}

// RecordThrottle records a 4xx throttling response and increases backoff.
func (m *Manager) RecordThrottle(providerName string, rule ProviderRule) {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.consecutive4xx++

	if state.currentBackoff == 0 {
		state.currentBackoff = 1 * time.Second
	} else {
		state.currentBackoff = time.Duration(float64(state.currentBackoff) * rule.BackoffMultiplier)
	}

	if rule.MaxBackoff > 0 && state.currentBackoff > rule.MaxBackoff {
		state.currentBackoff = rule.MaxBackoff
	}
}

// RecordSuccess records a successful delivery and resets backoff.
func (m *Manager) RecordSuccess(providerName string) {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.consecutive4xx = 0
	state.currentBackoff = 0
}

// Stats returns current throttle stats for a provider.
func (m *Manager) Stats(providerName string) ThrottleStats {
	state := m.getState(providerName)
	state.mu.Lock()
	defer state.mu.Unlock()

	return ThrottleStats{
		ActiveConnections: state.activeConns,
		SentThisSecond:    state.sentThisSecond,
		SentThisMinute:    state.sentThisMinute,
		SentThisHour:      state.sentThisHour,
		CurrentBackoff:    state.currentBackoff,
		Consecutive4xx:    state.consecutive4xx,
	}
}

// ThrottleStats holds the current state for a provider.
type ThrottleStats struct {
	ActiveConnections int
	SentThisSecond    int
	SentThisMinute    int
	SentThisHour      int
	CurrentBackoff    time.Duration
	Consecutive4xx    int
}

func (m *Manager) getState(name string) *providerState {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.state[name]; ok {
		return s
	}

	s := &providerState{
		secondReset: time.Now().Add(time.Second),
		minuteReset: time.Now().Add(time.Minute),
		hourReset:   time.Now().Add(time.Hour),
	}
	m.state[name] = s
	return s
}

// matchPattern matches a hostname against a glob pattern.
// Supports * as wildcard for a single segment and ** not supported.
// Examples: "*.outlook.com" matches "mx1.outlook.com"
func matchPattern(host, pattern string) bool {
	if pattern == host {
		return true
	}

	// Handle *.domain.com pattern
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".domain.com"
		return strings.HasSuffix(host, suffix)
	}

	return false
}
