// retry.go implements the retry engine with configurable exponential backoff,
// configurable max attempts, and dead-letter escalation for SRMTA.
package queue

import (
	"time"
)

// RetrySchedule defines a configurable retry schedule.
type RetrySchedule struct {
	Intervals    []time.Duration
	MaxRetries   int
	JitterFactor float64 // 0.0 to 1.0 — randomness added to prevent thundering herd
}

// DefaultRetrySchedule returns the default exponential backoff schedule.
func DefaultRetrySchedule() *RetrySchedule {
	return &RetrySchedule{
		Intervals: []time.Duration{
			5 * time.Minute,  // Retry 1
			15 * time.Minute, // Retry 2
			30 * time.Minute, // Retry 3
			1 * time.Hour,    // Retry 4
			2 * time.Hour,    // Retry 5
			4 * time.Hour,    // Retry 6
			8 * time.Hour,    // Retry 7
			16 * time.Hour,   // Retry 8
			24 * time.Hour,   // Retry 9
		},
		MaxRetries:   9,
		JitterFactor: 0.1, // ±10% jitter
	}
}

// NextRetryTime calculates the next retry time for a given attempt count.
func (rs *RetrySchedule) NextRetryTime(attempt int) time.Time {
	if attempt >= len(rs.Intervals) {
		// Use the last interval for all subsequent retries
		return time.Now().Add(rs.Intervals[len(rs.Intervals)-1])
	}
	return time.Now().Add(rs.Intervals[attempt])
}

// ShouldDeadLetter returns true if the message has exceeded max retries.
func (rs *RetrySchedule) ShouldDeadLetter(attempt int) bool {
	return attempt >= rs.MaxRetries
}

// RetryDecision represents the recommended action for a failed delivery.
type RetryDecision struct {
	Action    string    // "retry", "dead-letter", "fail"
	NextRetry time.Time // When to retry (if Action == "retry")
	Reason    string    // Human-readable reason
}

// EvaluateRetry decides what to do with a failed message based on the error type and retry count.
func EvaluateRetry(schedule *RetrySchedule, retryCount int, responseCode int, responseText string) RetryDecision {
	// Permanent failures (5xx) — no retry
	if responseCode >= 500 && responseCode < 600 {
		// Some 5xx codes indicate transient issues
		switch responseCode {
		case 550: // Mailbox unavailable
			return RetryDecision{
				Action: "fail",
				Reason: "permanent failure: mailbox unavailable",
			}
		case 551: // User not local
			return RetryDecision{
				Action: "fail",
				Reason: "permanent failure: user not local",
			}
		case 552: // Exceeded storage
			return RetryDecision{
				Action:    "retry",
				NextRetry: schedule.NextRetryTime(retryCount),
				Reason:    "mailbox full, may clear",
			}
		case 553: // Mailbox name not allowed
			return RetryDecision{
				Action: "fail",
				Reason: "permanent failure: invalid mailbox",
			}
		case 554: // Transaction failed
			return RetryDecision{
				Action: "fail",
				Reason: "permanent failure: transaction failed",
			}
		default:
			return RetryDecision{
				Action: "fail",
				Reason: "permanent failure: " + responseText,
			}
		}
	}

	// Temporary failures (4xx) — retry
	if responseCode >= 400 && responseCode < 500 {
		if schedule.ShouldDeadLetter(retryCount) {
			return RetryDecision{
				Action: "dead-letter",
				Reason: "max retries exceeded for temporary failure",
			}
		}
		return RetryDecision{
			Action:    "retry",
			NextRetry: schedule.NextRetryTime(retryCount),
			Reason:    "temporary failure: " + responseText,
		}
	}

	// Connection errors or timeouts — retry
	if schedule.ShouldDeadLetter(retryCount) {
		return RetryDecision{
			Action: "dead-letter",
			Reason: "max retries exceeded for connection error",
		}
	}
	return RetryDecision{
		Action:    "retry",
		NextRetry: schedule.NextRetryTime(retryCount),
		Reason:    "connection error: " + responseText,
	}
}
