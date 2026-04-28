// Package access provides INI-based access control list loading for allowed
// IPs and domains. Files use standard INI format with [sections] and one
// entry per line.
//
// Example allowed_domains.ini:
//
//	[domains]
//	example.com
//	.example.com    ; wildcard
//
// Example allowed_ips.ini:
//
//	[ipv4]
//	203.0.113.10
//	203.0.113.0/24
//
//	[ipv6]
//	2001:db8::1
//	2001:db8::/32
//
//	[relay]
//	10.0.0.0/8
package access

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// AccessList holds parsed allowed domains and IP ranges.
type AccessList struct {
	Domains  []string     // Allowed sending/relay domains
	IPv4     []string     // Raw IPv4 entries
	IPv6     []string     // Raw IPv6 entries
	Relay    []string     // Trusted relay entries
	Networks []*net.IPNet // Parsed CIDR networks for matching
	Singles  []net.IP     // Individual IPs (no CIDR)
}

// LoadDomainsINI reads an INI file and returns entries under the [domains] section.
func LoadDomainsINI(path string) ([]string, error) {
	sections, err := parseINI(path)
	if err != nil {
		return nil, fmt.Errorf("load domains INI %s: %w", path, err)
	}

	domains, ok := sections["domains"]
	if !ok {
		return nil, fmt.Errorf("missing [domains] section in %s", path)
	}

	for _, d := range domains {
		if !isValidDomain(d) {
			return nil, fmt.Errorf("invalid domain entry in %s: %q", path, d)
		}
	}

	return domains, nil
}

// LoadIPsINI reads an INI file and returns an AccessList with parsed IPs
// from [ipv4], [ipv6], and [relay] sections.
func LoadIPsINI(path string) (*AccessList, error) {
	sections, err := parseINI(path)
	if err != nil {
		return nil, fmt.Errorf("load IPs INI %s: %w", path, err)
	}

	acl := &AccessList{}

	if err := acl.loadIPSection(sections, "ipv4", &acl.IPv4, path); err != nil {
		return nil, err
	}
	if err := acl.loadIPSection(sections, "ipv6", &acl.IPv6, path); err != nil {
		return nil, err
	}
	if err := acl.loadIPSection(sections, "relay", &acl.Relay, path); err != nil {
		return nil, err
	}

	if len(acl.IPv4) == 0 && len(acl.IPv6) == 0 && len(acl.Relay) == 0 {
		return nil, fmt.Errorf("no [ipv4], [ipv6], or [relay] sections found in %s", path)
	}

	return acl, nil
}

// loadIPSection reads entries for one INI section into dest and parses them into the access list.
func (a *AccessList) loadIPSection(sections map[string][]string, key string, dest *[]string, path string) error {
	entries, ok := sections[key]
	if !ok {
		return nil
	}
	*dest = entries
	for _, entry := range entries {
		if err := a.addEntry(entry, path); err != nil {
			return err
		}
	}
	return nil
}

// addEntry parses a single IP or CIDR entry and adds it to the access list.
func (a *AccessList) addEntry(entry, file string) error {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid CIDR in %s: %q: %w", file, entry, err)
		}
		a.Networks = append(a.Networks, network)
	} else {
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("invalid IP in %s: %q", file, entry)
		}
		a.Singles = append(a.Singles, ip)
	}
	return nil
}

// ContainsIP checks if the given IP string is allowed by this access list.
func (a *AccessList) ContainsIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, allowed := range a.Singles {
		if allowed.Equal(ip) {
			return true
		}
	}

	for _, network := range a.Networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// ContainsDomain checks if the given domain is in the allowed list.
// Supports exact match and wildcard parent domain matching.
func ContainsDomain(allowed []string, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, d := range allowed {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == domain {
			return true
		}
		if strings.HasPrefix(d, ".") && strings.HasSuffix(domain, d) {
			return true
		}
	}
	return false
}

// parseINI reads an INI file and returns entries grouped by section name.
func parseINI(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sections := make(map[string][]string)
	currentSection := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		currentSection = processINILine(line, currentSection, sections)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return sections, nil
}

// processINILine handles one parsed INI line, updating sections and returning the (possibly new) section name.
func processINILine(line, currentSection string, sections map[string][]string) string {
	// Skip blank lines and comment-only lines
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return currentSection
	}

	// Section header: [name]
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		name := strings.ToLower(line[1 : len(line)-1])
		if _, exists := sections[name]; !exists {
			sections[name] = []string{}
		}
		return name
	}

	// No active section yet — ignore the line
	if currentSection == "" {
		return currentSection
	}

	// Strip inline comments
	if idx := strings.IndexAny(line, "#;"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	if line != "" {
		sections[currentSection] = append(sections[currentSection], line)
	}
	return currentSection
}

// isValidDomain performs a basic domain name validation.
func isValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	d = strings.TrimPrefix(d, ".")
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}
