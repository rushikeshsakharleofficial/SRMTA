package compliance

import (
	"net"
	"testing"
)

func TestSPFChecker_MatchIP_SingleIP(t *testing.T) {
	checker := NewSPFChecker(0)

	tests := []struct {
		cidr     string
		ip       string
		expected bool
	}{
		{"203.0.113.10", "203.0.113.10", true},
		{"203.0.113.10", "203.0.113.11", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result := checker.matchIP(ip, tt.cidr)
		if result != tt.expected {
			t.Errorf("matchIP(%s, %s) = %v, want %v", tt.ip, tt.cidr, result, tt.expected)
		}
	}
}

func TestSPFChecker_MatchIP_CIDR(t *testing.T) {
	checker := NewSPFChecker(0)

	tests := []struct {
		cidr     string
		ip       string
		expected bool
	}{
		{"203.0.113.0/24", "203.0.113.10", true},
		{"203.0.113.0/24", "203.0.113.255", true},
		{"203.0.113.0/24", "203.0.114.1", false},
		{"10.0.0.0/8", "10.255.255.255", true},
		{"10.0.0.0/8", "11.0.0.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result := checker.matchIP(ip, tt.cidr)
		if result != tt.expected {
			t.Errorf("matchIP(%s, %s) = %v, want %v", tt.ip, tt.cidr, result, tt.expected)
		}
	}
}

func TestSPFResult_Constants(t *testing.T) {
	if SPFPass != "pass" {
		t.Errorf("SPFPass = %q, want 'pass'", SPFPass)
	}
	if SPFFail != "fail" {
		t.Errorf("SPFFail = %q, want 'fail'", SPFFail)
	}
	if SPFSoftFail != "softfail" {
		t.Errorf("SPFSoftFail = %q, want 'softfail'", SPFSoftFail)
	}
	if SPFNone != "none" {
		t.Errorf("SPFNone = %q, want 'none'", SPFNone)
	}
}

func TestDMARCChecker_Alignment(t *testing.T) {
	checker := NewDMARCChecker(nil)

	// SPF aligned
	result := checker.CheckAlignment("example.com", "example.com", "")
	if !result.Aligned {
		t.Error("exact SPF match should be aligned")
	}
	if result.SPFResult != "pass" {
		t.Errorf("expected SPF pass, got %s", result.SPFResult)
	}

	// DKIM aligned
	result = checker.CheckAlignment("example.com", "", "example.com")
	if !result.Aligned {
		t.Error("exact DKIM match should be aligned")
	}

	// Subdomain alignment
	result = checker.CheckAlignment("example.com", "mail.example.com", "")
	if !result.Aligned {
		t.Error("subdomain SPF should be aligned (relaxed)")
	}

	// No alignment
	result = checker.CheckAlignment("example.com", "evil.com", "evil.com")
	if result.Aligned {
		t.Error("different domain should not be aligned")
	}
}

func TestIsSubdomain(t *testing.T) {
	tests := []struct {
		child, parent string
		expected      bool
	}{
		{"mail.example.com", "example.com", true},
		{"sub.mail.example.com", "example.com", true},
		{"example.com", "example.com", false}, // Same, not subdomain
		{"evil.com", "example.com", false},
	}

	for _, tt := range tests {
		result := isSubdomain(tt.child, tt.parent)
		if result != tt.expected {
			t.Errorf("isSubdomain(%q, %q) = %v, want %v", tt.child, tt.parent, result, tt.expected)
		}
	}
}

func TestSPFChecker_CheckHost_InvalidIP(t *testing.T) {
	checker := NewSPFChecker(0)

	result, _ := checker.CheckHost("not-an-ip", "example.com")
	if result != SPFPermError {
		t.Errorf("expected permerror for invalid IP, got %s", result)
	}
}
