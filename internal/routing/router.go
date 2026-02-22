// Package routing provides MX-based IP segregation for outbound delivery.
// Different email providers (Google, Microsoft, Yahoo, etc.) should receive
// mail from dedicated IP addresses to isolate reputation. This module maps
// MX hostnames and recipient domains to specific IP pools with fallback chains.
//
// Configuration is via YAML with provider→IP mappings. Each provider can have:
//   - Primary IPs: Used first for delivery
//   - Backup IPs:  Used when primary IPs are unhealthy or exhausted
//   - Fallback:    Global fallback IPs for unmatched providers
package routing

import (
	"fmt"
	"strings"
	"sync"
)

// ProviderRoute maps a provider to its dedicated IP pool.
type ProviderRoute struct {
	Name           string   `yaml:"name"`            // Provider name (e.g., "google", "microsoft")
	MXPatterns     []string `yaml:"mx_patterns"`     // MX hostname patterns
	DomainPatterns []string `yaml:"domain_patterns"` // Recipient domain patterns
	PrimaryIPs     []string `yaml:"primary_ips"`     // Primary sending IPs for this provider
	BackupIPs      []string `yaml:"backup_ips"`      // Backup IPs when primaries are down
}

// RouterConfig holds the full routing configuration.
type RouterConfig struct {
	Routes      []ProviderRoute `yaml:"routes"`
	FallbackIPs []string        `yaml:"fallback_ips"` // Global fallback for unmatched providers
}

// Router resolves which IPs to use for a given MX host or recipient domain.
type Router struct {
	mu       sync.RWMutex
	routes   []ProviderRoute
	fallback []string
	health   IPHealthChecker // Interface to check IP health
}

// IPHealthChecker is an interface for checking if an IP is healthy.
// Implement this with your ip.Pool's health scoring.
type IPHealthChecker interface {
	IsHealthy(ip string) bool
}

// defaultHealthChecker always returns true (all IPs healthy).
type defaultHealthChecker struct{}

func (d *defaultHealthChecker) IsHealthy(ip string) bool { return true }

// NewRouter creates a new MX-based IP router.
func NewRouter(config RouterConfig, health IPHealthChecker) *Router {
	if health == nil {
		health = &defaultHealthChecker{}
	}
	return &Router{
		routes:   config.Routes,
		fallback: config.FallbackIPs,
		health:   health,
	}
}

// RouteResult contains the resolved IPs for a delivery target.
type RouteResult struct {
	ProviderName string   // Matched provider name
	PrimaryIPs   []string // Healthy primary IPs
	BackupIPs    []string // Healthy backup IPs
	FallbackIPs  []string // Global fallback IPs
}

// AllIPs returns all available IPs in priority order: primary → backup → fallback.
func (r *RouteResult) AllIPs() []string {
	seen := make(map[string]bool)
	var result []string

	for _, lists := range [][]string{r.PrimaryIPs, r.BackupIPs, r.FallbackIPs} {
		for _, ip := range lists {
			if !seen[ip] {
				seen[ip] = true
				result = append(result, ip)
			}
		}
	}
	return result
}

// BestIP returns the first healthy IP in priority order, or empty string if none.
func (r *RouteResult) BestIP() string {
	ips := r.AllIPs()
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// Resolve finds the provider route for the given MX host and recipient domain,
// returning healthy IPs in priority order (primary → backup → fallback).
func (r *Router) Resolve(mxHost, recipientDomain string) *RouteResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mxHost = strings.ToLower(mxHost)
	recipientDomain = strings.ToLower(recipientDomain)

	result := &RouteResult{
		ProviderName: "default",
		FallbackIPs:  r.filterHealthy(r.fallback),
	}

	// Find matching provider
	for _, route := range r.routes {
		if r.matchRoute(route, mxHost, recipientDomain) {
			result.ProviderName = route.Name
			result.PrimaryIPs = r.filterHealthy(route.PrimaryIPs)
			result.BackupIPs = r.filterHealthy(route.BackupIPs)
			return result
		}
	}

	// No match: all fallback IPs become primary
	result.PrimaryIPs = result.FallbackIPs
	return result
}

// ResolveWithRotation returns the next IP to use for a provider using
// round-robin across healthy IPs.
func (r *Router) ResolveWithRotation(mxHost, recipientDomain string, attempt int) (string, *RouteResult) {
	result := r.Resolve(mxHost, recipientDomain)
	allIPs := result.AllIPs()

	if len(allIPs) == 0 {
		return "", result
	}

	// Round-robin based on attempt number
	idx := attempt % len(allIPs)
	return allIPs[idx], result
}

// UpdateRoutes hot-reloads routing rules without restart.
func (r *Router) UpdateRoutes(config RouterConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.routes = config.Routes
	r.fallback = config.FallbackIPs
}

// ProviderNames returns all configured provider names.
func (r *Router) ProviderNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.routes))
	for i, route := range r.routes {
		names[i] = route.Name
	}
	return names
}

// RouteInfo returns routing info for display/debugging.
func (r *Router) RouteInfo() []RouteDebug {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var info []RouteDebug
	for _, route := range r.routes {
		info = append(info, RouteDebug{
			Name:           route.Name,
			MXPatterns:     route.MXPatterns,
			DomainPatterns: route.DomainPatterns,
			PrimaryIPs:     route.PrimaryIPs,
			BackupIPs:      route.BackupIPs,
			HealthyPrimary: len(r.filterHealthy(route.PrimaryIPs)),
			HealthyBackup:  len(r.filterHealthy(route.BackupIPs)),
		})
	}
	return info
}

// RouteDebug holds routing debug info.
type RouteDebug struct {
	Name           string
	MXPatterns     []string
	DomainPatterns []string
	PrimaryIPs     []string
	BackupIPs      []string
	HealthyPrimary int
	HealthyBackup  int
}

func (r *Router) matchRoute(route ProviderRoute, mxHost, domain string) bool {
	for _, pattern := range route.MXPatterns {
		if matchPattern(mxHost, strings.ToLower(pattern)) {
			return true
		}
	}
	for _, pattern := range route.DomainPatterns {
		if matchPattern(domain, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (r *Router) filterHealthy(ips []string) []string {
	var healthy []string
	for _, ip := range ips {
		if r.health.IsHealthy(ip) {
			healthy = append(healthy, ip)
		}
	}
	return healthy
}

// matchPattern matches a hostname against a glob pattern.
func matchPattern(host, pattern string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix)
	}
	return false
}

// ValidateConfig checks that a routing config is valid.
func ValidateConfig(config RouterConfig) error {
	seen := make(map[string]bool)
	for _, route := range config.Routes {
		if route.Name == "" {
			return fmt.Errorf("route missing name")
		}
		if seen[route.Name] {
			return fmt.Errorf("duplicate route name: %s", route.Name)
		}
		seen[route.Name] = true

		if len(route.MXPatterns) == 0 && len(route.DomainPatterns) == 0 {
			return fmt.Errorf("route %q has no MX or domain patterns", route.Name)
		}
		if len(route.PrimaryIPs) == 0 {
			return fmt.Errorf("route %q has no primary IPs", route.Name)
		}
	}
	if len(config.FallbackIPs) == 0 {
		return fmt.Errorf("no fallback IPs configured")
	}
	return nil
}
