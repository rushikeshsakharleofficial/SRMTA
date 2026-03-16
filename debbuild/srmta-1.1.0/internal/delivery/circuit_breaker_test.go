package delivery

import (
	"testing"
	"time"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	mgr := NewCircuitBreakerManager(5, 30*time.Second)

	state := mgr.GetState("mx.example.com")
	if state != CircuitClosed {
		t.Errorf("expected closed state for unknown host, got %s", state.String())
	}
}

func TestCircuitBreaker_AllowInClosed(t *testing.T) {
	mgr := NewCircuitBreakerManager(5, 30*time.Second)

	if !mgr.AllowRequest("mx.example.com") {
		t.Error("should allow request in closed state")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	mgr := NewCircuitBreakerManager(3, 100*time.Millisecond)

	// Record 3 failures (threshold)
	for i := 0; i < 3; i++ {
		mgr.RecordFailure("mx.example.com")
	}

	state := mgr.GetState("mx.example.com")
	if state != CircuitOpen {
		t.Errorf("expected open state after %d failures, got %s", 3, state.String())
	}

	// Should block requests now
	if mgr.AllowRequest("mx.example.com") {
		t.Error("should block request in open state")
	}
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	mgr := NewCircuitBreakerManager(2, 50*time.Millisecond) // Short timeout for tests

	// Open the circuit
	mgr.RecordFailure("mx.example.com")
	mgr.RecordFailure("mx.example.com")

	if mgr.GetState("mx.example.com") != CircuitOpen {
		t.Fatal("expected open state")
	}

	// Wait well past recovery timeout
	time.Sleep(100 * time.Millisecond)

	// Should transition to half-open and allow one probe
	if !mgr.AllowRequest("mx.example.com") {
		t.Error("should allow probe request after recovery timeout")
	}

	state := mgr.GetState("mx.example.com")
	if state != CircuitHalfOpen {
		t.Errorf("expected half-open state, got %s", state.String())
	}
}

func TestCircuitBreaker_RecoverFromHalfOpen(t *testing.T) {
	mgr := NewCircuitBreakerManager(2, 50*time.Millisecond) // Short timeout

	// Open the circuit
	mgr.RecordFailure("mx.example.com")
	mgr.RecordFailure("mx.example.com")

	// Wait for recovery
	time.Sleep(100 * time.Millisecond)
	mgr.AllowRequest("mx.example.com") // Transition to half-open

	// Record success — should close the circuit
	mgr.RecordSuccess("mx.example.com")

	state := mgr.GetState("mx.example.com")
	if state != CircuitClosed {
		t.Errorf("expected closed state after recovery, got %s", state.String())
	}
}

func TestCircuitBreaker_FailInHalfOpen(t *testing.T) {
	mgr := NewCircuitBreakerManager(2, 50*time.Millisecond) // Short timeout

	// Open the circuit
	mgr.RecordFailure("mx.example.com")
	mgr.RecordFailure("mx.example.com")

	// Wait for recovery
	time.Sleep(100 * time.Millisecond)
	mgr.AllowRequest("mx.example.com") // Transition to half-open

	// Record failure in half-open — should go back to open
	mgr.RecordFailure("mx.example.com")

	state := mgr.GetState("mx.example.com")
	if state != CircuitOpen {
		t.Errorf("expected open state after half-open failure, got %s", state.String())
	}
}

func TestCircuitBreaker_DifferentHosts(t *testing.T) {
	mgr := NewCircuitBreakerManager(2, 30*time.Second)

	// Fail one host
	mgr.RecordFailure("bad.example.com")
	mgr.RecordFailure("bad.example.com")

	// Good host should still be accessible
	if !mgr.AllowRequest("good.example.com") {
		t.Error("different host should not be affected")
	}

	if mgr.AllowRequest("bad.example.com") {
		t.Error("failed host should be blocked")
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	mgr := NewCircuitBreakerManager(5, 30*time.Second)

	// Record failures for host - this creates the breaker entry
	mgr.RecordFailure("mx1.example.com")
	mgr.RecordFailure("mx1.example.com")

	// RecordSuccess only updates existing entries, so we need to create mx2 first
	mgr.RecordFailure("mx2.example.com")
	mgr.RecordSuccess("mx2.example.com")

	stats := mgr.Stats()
	if len(stats) != 2 {
		t.Errorf("expected 2 hosts in stats, got %d", len(stats))
	}

	s1, ok := stats["mx1.example.com"]
	if !ok {
		t.Fatal("mx1 should be in stats")
	}
	if s1.Failures != 2 {
		t.Errorf("expected 2 failures for mx1, got %d", s1.Failures)
	}
}

func TestCircuitState_String(t *testing.T) {
	if CircuitClosed.String() != "closed" {
		t.Errorf("expected 'closed', got %s", CircuitClosed.String())
	}
	if CircuitOpen.String() != "open" {
		t.Errorf("expected 'open', got %s", CircuitOpen.String())
	}
	if CircuitHalfOpen.String() != "half-open" {
		t.Errorf("expected 'half-open', got %s", CircuitHalfOpen.String())
	}
}
