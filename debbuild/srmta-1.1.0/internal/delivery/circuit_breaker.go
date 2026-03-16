// Package delivery — circuit_breaker.go implements the circuit breaker pattern
// for failing MX hosts. When a host consistently fails, the circuit opens to
// avoid wasting resources on delivery attempts that will fail.
//
// States:
//   - Closed:    Normal operation, requests go through
//   - Open:      Host is failing, requests are blocked
//   - HalfOpen:  Recovery probe — one request allowed to test if host recovered
package delivery

import (
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // Normal operation
	CircuitOpen                         // Host failing, blocked
	CircuitHalfOpen                     // Recovery probe
)

// String returns the string representation of a circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker tracks failures for a single MX host.
type CircuitBreaker struct {
	state            CircuitState
	failures         int
	successes        int
	failureThreshold int
	recoveryTimeout  time.Duration
	lastFailure      time.Time
	lastStateChange  time.Time
	mu               sync.Mutex
}

// CircuitBreakerManager manages circuit breakers for all MX hosts.
type CircuitBreakerManager struct {
	breakers         map[string]*CircuitBreaker
	failureThreshold int
	recoveryTimeout  time.Duration
	mu               sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager.
// failureThreshold: number of consecutive failures before opening circuit.
// recoveryTimeout: how long to wait before trying half-open.
func NewCircuitBreakerManager(failureThreshold int, recoveryTimeout time.Duration) *CircuitBreakerManager {
	if failureThreshold < 1 {
		failureThreshold = 5
	}
	if recoveryTimeout < 10*time.Millisecond {
		recoveryTimeout = 30 * time.Second
	}
	return &CircuitBreakerManager{
		breakers:         make(map[string]*CircuitBreaker),
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
	}
}

// AllowRequest checks if a request to the given host should be allowed.
func (m *CircuitBreakerManager) AllowRequest(host string) bool {
	m.mu.RLock()
	cb, exists := m.breakers[host]
	m.mu.RUnlock()

	if !exists {
		return true // No breaker = allow
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if recovery timeout has elapsed
		if time.Since(cb.lastFailure) >= cb.recoveryTimeout {
			cb.state = CircuitHalfOpen
			cb.lastStateChange = time.Now()
			return true // Allow one probe request
		}
		return false

	case CircuitHalfOpen:
		// Only one request allowed in half-open state
		return false
	}

	return true
}

// RecordSuccess records a successful request to a host.
func (m *CircuitBreakerManager) RecordSuccess(host string) {
	m.mu.Lock()
	cb, exists := m.breakers[host]
	if !exists {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.successes++
	cb.failures = 0

	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
		cb.lastStateChange = time.Now()
	}
}

// RecordFailure records a failed request to a host.
func (m *CircuitBreakerManager) RecordFailure(host string) {
	m.mu.Lock()
	cb, exists := m.breakers[host]
	if !exists {
		cb = &CircuitBreaker{
			state:            CircuitClosed,
			failureThreshold: m.failureThreshold,
			recoveryTimeout:  m.recoveryTimeout,
		}
		m.breakers[host] = cb
	}
	m.mu.Unlock()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	// Transition to open if threshold exceeded
	if cb.failures >= cb.failureThreshold && cb.state == CircuitClosed {
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
	}

	// Half-open failure: re-open the circuit
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
	}
}

// GetState returns the current state of the circuit breaker for a host.
func (m *CircuitBreakerManager) GetState(host string) CircuitState {
	m.mu.RLock()
	cb, exists := m.breakers[host]
	m.mu.RUnlock()

	if !exists {
		return CircuitClosed
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Stats returns circuit breaker statistics for all hosts.
func (m *CircuitBreakerManager) Stats() map[string]CircuitBreakerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CircuitBreakerStats)
	for host, cb := range m.breakers {
		cb.mu.Lock()
		stats[host] = CircuitBreakerStats{
			State:       cb.state.String(),
			Failures:    cb.failures,
			Successes:   cb.successes,
			LastFailure: cb.lastFailure,
		}
		cb.mu.Unlock()
	}
	return stats
}

// CircuitBreakerStats holds statistics for a single circuit breaker.
type CircuitBreakerStats struct {
	State       string    `json:"state"`
	Failures    int       `json:"failures"`
	Successes   int       `json:"successes"`
	LastFailure time.Time `json:"last_failure"`
}
