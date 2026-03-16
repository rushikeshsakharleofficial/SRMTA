// Package compliance — spf.go implements SPF (Sender Policy Framework) validation
// for incoming mail per RFC 7208. Validates that the connecting IP is authorized
// to send mail for the sender's domain.
package compliance

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// SPFResult represents the result of an SPF validation check.
type SPFResult string

const (
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftFail  SPFResult = "softfail"
	SPFNeutral   SPFResult = "neutral"
	SPFNone      SPFResult = "none"
	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// SPFChecker validates SPF records for incoming mail.
type SPFChecker struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewSPFChecker creates a new SPF checker.
func NewSPFChecker(timeout time.Duration) *SPFChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &SPFChecker{
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}
}

// CheckHost validates if senderIP is authorized to send for the given domain.
// Implements a subset of RFC 7208 SPF checking.
func (s *SPFChecker) CheckHost(senderIP, domain string) (SPFResult, string) {
	ip := net.ParseIP(senderIP)
	if ip == nil {
		return SPFPermError, "invalid sender IP"
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Look up SPF TXT record
	records, err := s.resolver.LookupTXT(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return SPFNone, "no SPF record found"
		}
		return SPFTempError, fmt.Sprintf("DNS lookup failed: %v", err)
	}

	// Find the SPF record
	spfRecord := ""
	for _, txt := range records {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return SPFNone, "no SPF record found"
	}

	// Parse and evaluate SPF mechanisms
	return s.evaluate(ctx, ip, domain, spfRecord)
}

// evaluate processes SPF mechanisms in order.
func (s *SPFChecker) evaluate(ctx context.Context, ip net.IP, domain, record string) (SPFResult, string) {
	mechanisms := strings.Fields(record)

	for _, mech := range mechanisms[1:] { // Skip "v=spf1"
		qualifier := SPFPass

		// Check for qualifier prefix
		switch {
		case strings.HasPrefix(mech, "+"):
			qualifier = SPFPass
			mech = mech[1:]
		case strings.HasPrefix(mech, "-"):
			qualifier = SPFFail
			mech = mech[1:]
		case strings.HasPrefix(mech, "~"):
			qualifier = SPFSoftFail
			mech = mech[1:]
		case strings.HasPrefix(mech, "?"):
			qualifier = SPFNeutral
			mech = mech[1:]
		}

		mechLower := strings.ToLower(mech)

		switch {
		case mechLower == "all":
			return qualifier, "matched: all"

		case strings.HasPrefix(mechLower, "ip4:"):
			cidr := mech[4:]
			if s.matchIP(ip, cidr) {
				return qualifier, fmt.Sprintf("matched: ip4:%s", cidr)
			}

		case strings.HasPrefix(mechLower, "ip6:"):
			cidr := mech[4:]
			if s.matchIP(ip, cidr) {
				return qualifier, fmt.Sprintf("matched: ip6:%s", cidr)
			}

		case strings.HasPrefix(mechLower, "a"):
			targetDomain := domain
			if strings.HasPrefix(mechLower, "a:") {
				targetDomain = mech[2:]
			}
			if s.matchA(ctx, ip, targetDomain) {
				return qualifier, fmt.Sprintf("matched: a:%s", targetDomain)
			}

		case strings.HasPrefix(mechLower, "mx"):
			targetDomain := domain
			if strings.HasPrefix(mechLower, "mx:") {
				targetDomain = mech[3:]
			}
			if s.matchMX(ctx, ip, targetDomain) {
				return qualifier, fmt.Sprintf("matched: mx:%s", targetDomain)
			}

		case strings.HasPrefix(mechLower, "include:"):
			includeDomain := mech[8:]
			result, reason := s.CheckHost(ip.String(), includeDomain)
			if result == SPFPass {
				return qualifier, fmt.Sprintf("matched: include:%s (%s)", includeDomain, reason)
			}
		}
	}

	return SPFNeutral, "no mechanism matched"
}

// matchIP checks if the IP matches a CIDR notation or single IP.
func (s *SPFChecker) matchIP(ip net.IP, cidr string) bool {
	if !strings.Contains(cidr, "/") {
		// Single IP comparison
		targetIP := net.ParseIP(cidr)
		return targetIP != nil && targetIP.Equal(ip)
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// matchA checks if IP matches any A/AAAA record for the domain.
func (s *SPFChecker) matchA(ctx context.Context, ip net.IP, domain string) bool {
	addrs, err := s.resolver.LookupHost(ctx, domain)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if net.ParseIP(addr).Equal(ip) {
			return true
		}
	}
	return false
}

// matchMX checks if IP matches any A/AAAA record for MX hosts of the domain.
func (s *SPFChecker) matchMX(ctx context.Context, ip net.IP, domain string) bool {
	mxRecords, err := s.resolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		if s.matchA(ctx, ip, host) {
			return true
		}
	}
	return false
}
