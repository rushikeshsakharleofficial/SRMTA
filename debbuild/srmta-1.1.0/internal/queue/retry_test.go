package queue

import (
	"testing"
)

func TestEvaluateRetry_PermanentFailure550(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 550, "mailbox not found")

	if decision.Action != "fail" {
		t.Errorf("expected action=fail for 550, got %s", decision.Action)
	}
}

func TestEvaluateRetry_PermanentFailure551(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 551, "user not local")

	if decision.Action != "fail" {
		t.Errorf("expected action=fail for 551, got %s", decision.Action)
	}
}

func TestEvaluateRetry_PermanentFailure553(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 553, "invalid mailbox")

	if decision.Action != "fail" {
		t.Errorf("expected action=fail for 553, got %s", decision.Action)
	}
}

func TestEvaluateRetry_PermanentFailure554(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 554, "transaction failed")

	if decision.Action != "fail" {
		t.Errorf("expected action=fail for 554, got %s", decision.Action)
	}
}

func TestEvaluateRetry_MailboxFull552_Retries(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 552, "mailbox full")

	if decision.Action != "retry" {
		t.Errorf("expected action=retry for 552/mailbox full, got %s", decision.Action)
	}
}

func TestEvaluateRetry_TemporaryFailure4xx(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 421, "try again later")

	if decision.Action != "retry" {
		t.Errorf("expected action=retry for 421, got %s", decision.Action)
	}
	if decision.NextRetry.IsZero() {
		t.Error("NextRetry should not be zero for retry action")
	}
}

func TestEvaluateRetry_MaxRetriesDeadLetter(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 10, 450, "temporary failure") // 10 > MaxRetries=9

	if decision.Action != "dead-letter" {
		t.Errorf("expected action=dead-letter when max retries exceeded, got %s", decision.Action)
	}
}

func TestEvaluateRetry_ConnectionError(t *testing.T) {
	schedule := DefaultRetrySchedule()
	decision := EvaluateRetry(schedule, 0, 0, "connection timeout")

	if decision.Action != "retry" {
		t.Errorf("expected action=retry for connection error, got %s", decision.Action)
	}
}

func TestDefaultRetrySchedule(t *testing.T) {
	schedule := DefaultRetrySchedule()

	if schedule.MaxRetries != 9 {
		t.Errorf("expected MaxRetries=9, got %d", schedule.MaxRetries)
	}
	if len(schedule.Intervals) != 9 {
		t.Errorf("expected 9 intervals, got %d", len(schedule.Intervals))
	}
	if schedule.JitterFactor != 0.1 {
		t.Errorf("expected JitterFactor=0.1, got %f", schedule.JitterFactor)
	}
}

func TestRetrySchedule_NextRetryTime(t *testing.T) {
	schedule := DefaultRetrySchedule()

	t1 := schedule.NextRetryTime(0)
	t2 := schedule.NextRetryTime(1)

	if t2.Before(t1) {
		t.Error("later retry should have later next time")
	}

	// Beyond max intervals should use last interval
	tBeyond := schedule.NextRetryTime(100)
	if tBeyond.IsZero() {
		t.Error("beyond-max retry time should not be zero")
	}
}

func TestRetrySchedule_ShouldDeadLetter(t *testing.T) {
	schedule := DefaultRetrySchedule()

	if schedule.ShouldDeadLetter(0) {
		t.Error("should not dead-letter on first attempt")
	}
	if schedule.ShouldDeadLetter(8) {
		t.Error("should not dead-letter at attempt 8")
	}
	if !schedule.ShouldDeadLetter(9) {
		t.Error("should dead-letter at attempt 9 (MaxRetries)")
	}
	if !schedule.ShouldDeadLetter(100) {
		t.Error("should dead-letter at attempt 100")
	}
}
