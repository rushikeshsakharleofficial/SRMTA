package smtp

import (
	"testing"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
)

func newTestLogger() *logging.Logger {
	return logging.NewLogger(config.LoggingConfig{
		Level:  "error",
		Output: "stdout",
	})
}

func TestExtractAddress_Valid(t *testing.T) {
	s := &Session{logger: newTestLogger()}

	tests := []struct {
		input    string
		expected string
	}{
		{"<user@example.com>", "user@example.com"},
		{"user@example.com", "user@example.com"},
		{"<USER@Example.COM>", "user@example.com"},
		{"<user@example.com> SIZE=1234", "user@example.com"},
		{"<>", ""},
	}

	for _, tt := range tests {
		result := s.extractAddress(tt.input)
		if result != tt.expected {
			t.Errorf("extractAddress(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractAddress_Invalid(t *testing.T) {
	s := &Session{logger: newTestLogger()}

	tests := []struct {
		input string
		desc  string
	}{
		{"nodomainemail", "no @ sign"},
		{"<invalid>", "no @ in brackets"},
	}

	for _, tt := range tests {
		result := s.extractAddress(tt.input)
		if result != "" {
			t.Errorf("extractAddress(%q) should be empty for %s, got %q", tt.input, tt.desc, result)
		}
	}
}

func TestExtractAddress_CRLFInjection(t *testing.T) {
	s := &Session{logger: newTestLogger()}

	// These should all return empty due to CRLF injection prevention
	injections := []string{
		"<user@example.com>\r\nDATA",
		"user@example.com\r\n",
		"<user@example.com\nINJECTED>",
		"user\r@example.com",
		"user@example.com\x00INJECTED",
	}

	for _, input := range injections {
		result := s.extractAddress(input)
		if result != "" {
			t.Errorf("extractAddress should reject CRLF injection %q, got %q", input, result)
		}
	}
}

func TestContainsControlChars(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"normal.hostname.com", false},
		{"tab\there", false}, // tabs are allowed
		{"with\nnewline", true},
		{"with\rreturn", true},
		{"with\x00null", true},
		{"", false},
	}

	for _, tt := range tests {
		result := containsControlChars(tt.input)
		if result != tt.expected {
			t.Errorf("containsControlChars(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseCommand(t *testing.T) {
	s := &Session{}

	tests := []struct {
		line string
		cmd  string
		args string
	}{
		{"EHLO example.com", "EHLO", "example.com"},
		{"MAIL FROM:<user@example.com>", "MAIL", "FROM:<user@example.com>"},
		{"QUIT", "QUIT", ""},
		{"DATA", "DATA", ""},
		{"noop", "NOOP", ""},
	}

	for _, tt := range tests {
		cmd, args := s.parseCommand(tt.line)
		if cmd != tt.cmd {
			t.Errorf("parseCommand(%q) cmd = %q, want %q", tt.line, cmd, tt.cmd)
		}
		if args != tt.args {
			t.Errorf("parseCommand(%q) args = %q, want %q", tt.line, args, tt.args)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	s := &Session{}

	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"USER@Example.COM", "example.com"},
		{"nodomain", ""},
	}

	for _, tt := range tests {
		result := s.extractDomain(tt.email)
		if result != tt.expected {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.email, result, tt.expected)
		}
	}
}

func TestIsDomainAllowed(t *testing.T) {
	s := &Session{
		cfg: config.SMTPConfig{
			AllowedDomains: []string{"example.com", "mail.example.com"},
		},
	}

	if !s.isDomainAllowed("example.com") {
		t.Error("example.com should be allowed")
	}
	if !s.isDomainAllowed("EXAMPLE.COM") {
		t.Error("EXAMPLE.COM should be allowed (case insensitive)")
	}
	if s.isDomainAllowed("evil.com") {
		t.Error("evil.com should not be allowed")
	}
}

func TestComputeCRAMMD5(t *testing.T) {
	challenge := "<12345@example.com>"
	password := "tanstraafl"

	digest := ComputeCRAMMD5(challenge, password)
	if digest == "" {
		t.Fatal("CRAM-MD5 digest should not be empty")
	}
	// Verify deterministic
	digest2 := ComputeCRAMMD5(challenge, password)
	if digest != digest2 {
		t.Error("CRAM-MD5 should produce same digest for same inputs")
	}
	// Different password should produce different digest
	digest3 := ComputeCRAMMD5(challenge, "different")
	if digest == digest3 {
		t.Error("Different password should produce different digest")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Second)

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th should be denied
	if rl.Allow("1.2.3.4") {
		t.Error("4th request should be denied")
	}

	// Different IP should still be allowed
	if !rl.Allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}

	// Wait for window to reset
	time.Sleep(1100 * time.Millisecond)
	if !rl.Allow("1.2.3.4") {
		t.Error("should be allowed after window reset")
	}
}

func TestGenerateCorrelationID(t *testing.T) {
	id1 := generateCorrelationID()
	id2 := generateCorrelationID()

	if id1 == "" || id2 == "" {
		t.Fatal("correlation IDs should not be empty")
	}
	if id1 == id2 {
		t.Error("correlation IDs should be unique")
	}
}
