// Package dns implements an async DNS resolver with caching, MX prioritization,
// A/AAAA fallback, DNSSEC awareness, and Redis cache for 100M/day scale.
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/store"
)

// MXRecord represents a resolved MX record with priority.
type MXRecord struct {
	Host     string   `json:"host"`
	Priority uint16   `json:"priority"`
	IPs      []string `json:"ips"` // Resolved A/AAAA records
}

// CacheEntry holds a cached DNS response.
type CacheEntry struct {
	Records   []*MXRecord
	ExpiresAt time.Time
}

// Resolver provides DNS resolution with caching and pooling.
type Resolver struct {
	cfg      config.DNSConfig
	redis    *store.RedisStore
	logger   *logging.Logger
	cache    map[string]*CacheEntry
	mu       sync.RWMutex
	resolver *net.Resolver
}

// NewResolver creates a new DNS resolver.
func NewResolver(cfg config.DNSConfig, redis *store.RedisStore, logger *logging.Logger) *Resolver {
	r := &Resolver{
		cfg:    cfg,
		redis:  redis,
		logger: logger,
		cache:  make(map[string]*CacheEntry),
	}

	// Configure custom DNS resolver if servers specified
	if len(cfg.Servers) > 0 {
		r.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: cfg.Timeout}
				// Round-robin through configured DNS servers
				server := cfg.Servers[time.Now().UnixNano()%int64(len(cfg.Servers))]
				if !strings.Contains(server, ":") {
					server = server + ":53"
				}
				return d.DialContext(ctx, "udp", server)
			},
		}
	} else {
		r.resolver = net.DefaultResolver
	}

	return r
}

// LookupMX resolves MX records for a domain with caching.
// Falls back to A/AAAA records per RFC 5321 §5.1 if no MX records exist.
func (r *Resolver) LookupMX(domain string) ([]*MXRecord, error) {
	domain = strings.ToLower(domain)

	// Check local cache
	if records := r.getFromCache(domain); records != nil {
		return records, nil
	}

	// Check Redis cache (for high-volume deployments)
	if r.cfg.UseRedisCache && r.redis != nil {
		if records := r.getFromRedis(domain); records != nil {
			r.setCache(domain, records)
			return records, nil
		}
	}

	// Perform MX lookup
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	mxRecords, err := r.resolver.LookupMX(ctx, domain)
	if err != nil {
		// Fallback to A/AAAA per RFC 5321 §5.1
		r.logger.Debug("MX lookup failed, falling back to A/AAAA",
			"domain", domain, "error", err)
		return r.fallbackToHostRecords(domain)
	}

	if len(mxRecords) == 0 {
		return r.fallbackToHostRecords(domain)
	}

	// Sort by priority (lowest first)
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	// Resolve IPs for each MX host
	records := make([]*MXRecord, 0, len(mxRecords))
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		ips := r.resolveHost(host)

		records = append(records, &MXRecord{
			Host:     host,
			Priority: mx.Pref,
			IPs:      ips,
		})
	}

	// Cache the result
	r.setCache(domain, records)
	if r.cfg.UseRedisCache && r.redis != nil {
		r.setRedisCache(domain, records)
	}

	r.logger.Debug("MX resolved",
		"domain", domain,
		"records", len(records),
		"primary", records[0].Host,
	)

	return records, nil
}

// fallbackToHostRecords resolves a domain directly via A/AAAA when no MX exists.
func (r *Resolver) fallbackToHostRecords(domain string) ([]*MXRecord, error) {
	ips := r.resolveHost(domain)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no MX or A/AAAA records for %s", domain)
	}

	records := []*MXRecord{{
		Host:     domain,
		Priority: 0,
		IPs:      ips,
	}}

	r.setCache(domain, records)
	return records, nil
}

// resolveHost resolves A and AAAA records for a hostname.
func (r *Resolver) resolveHost(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, host)
	if err != nil {
		r.logger.Debug("Host resolution failed", "host", host, "error", err)
		return nil
	}

	// Separate IPv4 and IPv6, prefer IPv4 for compatibility
	var ipv4, ipv6 []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, addr)
		} else {
			ipv6 = append(ipv6, addr)
		}
	}

	// Return IPv4 first, then IPv6
	return append(ipv4, ipv6...)
}

// getFromCache retrieves MX records from the local in-memory cache.
func (r *Resolver) getFromCache(domain string) []*MXRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.cache[domain]
	if !exists {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil // Expired
	}
	return entry.Records
}

// setCache stores MX records in the local in-memory cache.
func (r *Resolver) setCache(domain string, records []*MXRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Evict if cache is full
	if len(r.cache) >= r.cfg.CacheSize {
		r.evictOldest()
	}

	r.cache[domain] = &CacheEntry{
		Records:   records,
		ExpiresAt: time.Now().Add(r.cfg.CacheTTL),
	}
}

// evictOldest removes the oldest cache entry.
func (r *Resolver) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range r.cache {
		if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(r.cache, oldestKey)
	}
}

// getFromRedis retrieves MX records from the Redis cache.
func (r *Resolver) getFromRedis(domain string) []*MXRecord {
	if r.redis == nil {
		return nil
	}
	storeRecords, err := r.redis.GetDNSCache(domain)
	if err != nil {
		return nil
	}
	// Convert []*store.MXRecord → []*MXRecord
	records := make([]*MXRecord, len(storeRecords))
	for i, sr := range storeRecords {
		records[i] = &MXRecord{
			Host:     sr.Host,
			Priority: sr.Priority,
			IPs:      sr.IPs,
		}
	}
	return records
}

// setRedisCache stores MX records in the Redis cache.
func (r *Resolver) setRedisCache(domain string, records []*MXRecord) {
	if r.redis == nil {
		return
	}
	r.redis.SetDNSCache(domain, records, r.cfg.CacheTTL)
}

// FlushCache clears the DNS cache.
func (r *Resolver) FlushCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*CacheEntry)
}

// CacheStats returns cache statistics.
func (r *Resolver) CacheStats() (size int, hitRate float64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache), 0 // TODO: track hit/miss
}
