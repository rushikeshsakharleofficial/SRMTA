package bounce

import (
	"testing"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
)

func newTestClassifier(cfg config.BounceConfig) *Classifier {
	logger := logging.NewLogger(config.LoggingConfig{
		Level:  "error",
		Output: "stdout",
	})
	return NewClassifier(cfg, nil, logger)
}

func TestClassify_HardBounce550(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{})

	result := c.classify(550, "user unknown")
	if result != BounceHard {
		t.Errorf("expected BounceHard for 550/user unknown, got %s", result)
	}
}

func TestClassify_Block550(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{})

	result := c.classify(550, "blocked by spam filter")
	if result != BounceBlock {
		t.Errorf("expected BounceBlock for 550/blocked, got %s", result)
	}
}

func TestClassify_MailboxFull552(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{})

	result := c.classify(552, "mailbox full quota exceeded")
	if result != BounceMailbox {
		t.Errorf("expected BounceMailbox for 552/mailbox full, got %s", result)
	}
}

func TestClassify_Policy554(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{})

	result := c.classify(554, "DMARC policy violation")
	if result != BouncePolicy {
		t.Errorf("expected BouncePolicy for 554/DMARC, got %s", result)
	}
}

func TestClassify_SoftBounce4xx(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{})

	tests := []struct {
		code int
		text string
	}{
		{421, "try again later"},
		{450, "temporary failure"},
		{451, "rate limited"},
	}

	for _, tt := range tests {
		result := c.classify(tt.code, tt.text)
		if result != BounceSoft {
			t.Errorf("expected BounceSoft for %d/%s, got %s", tt.code, tt.text, result)
		}
	}
}

func TestSuppression(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{
		SuppressionListEnabled: true,
	})

	email := "test@example.com"

	if c.IsSuppressed(email) {
		t.Error("email should not be suppressed initially")
	}

	c.suppress(email)

	if !c.IsSuppressed(email) {
		t.Error("email should be suppressed after suppress()")
	}
	if !c.IsSuppressed("TEST@EXAMPLE.COM") {
		t.Error("suppression should be case-insensitive")
	}
}

func TestSenderPause(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{
		SenderPauseEnabled:  true,
		HardBounceThreshold: 0.05,
	})

	sender := "sender@example.com"

	// Simulate sends
	for i := 0; i < 100; i++ {
		c.RecordSend(sender)
	}

	// Simulate bounces exceeding threshold
	for i := 0; i < 10; i++ {
		c.updateSenderStats(sender, BounceHard)
	}

	if !c.IsSenderPaused(sender) {
		t.Error("sender should be paused after exceeding bounce threshold")
	}
}

func TestSenderNotPausedBelow(t *testing.T) {
	c := newTestClassifier(config.BounceConfig{
		SenderPauseEnabled:  true,
		HardBounceThreshold: 0.50, // Very high threshold
	})

	sender := "good@example.com"

	for i := 0; i < 100; i++ {
		c.RecordSend(sender)
	}
	c.updateSenderStats(sender, BounceHard) // 1 bounce out of 100

	if c.IsSenderPaused(sender) {
		t.Error("sender should not be paused below threshold")
	}
}
