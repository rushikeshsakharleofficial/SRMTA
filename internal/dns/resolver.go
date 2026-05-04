// Package dns implements a DNS resolver with in-memory caching, MX prioritization,
// and A/AAAA fallback per RFC 5321 §5.1.
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
)

// MXRecord represents a resolved MX record with priority.
type MXRecord struct {
	Host     string   `json:"host"`
	Priority uint16   `json:"priority"`
	IPs      []string `json:"ips"`
}

// CacheEntry holds a cached DNS response.
type CacheEntry struct {
	Records   []*MXRecord
	ExpiresAt time.Time
}

// Resolver provides DNS resolution with in-memory caching.
type Resolver struct {
	cfg      config.DNSConfig
	logger   *logging.Logger
	cache    map[string]*CacheEntry
	mu       sync.RWMutex
	resolver *net.Resolver
	hits     int64
	misses   int64
}

// NewResolver creates a new DNS resolver.
func NewResolver(cfg config.DNSConfig, logger *logging.Logger) *Resolver {
	r := &Resolver{
		cfg:    cfg,
		logger: logger,
		cache:  make(map[string]*CacheEntry),
	}

	if len(cfg.Servers) > 0 {
		r.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: cfg.Timeout}
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

	if records := r.getFromCache(domain); records != nil {
		return records, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	mxRecords, err := r.resolver.LookupMX(ctx, domain)
	if err != nil {
		r.logger.Debug("MX lookup failed, falling back to A/AAAA", "domain", domain, "error", err)
		return r.fallbackToHostRecords(domain)
	}

	if len(mxRecords) == 0 {
		return r.fallbackToHostRecords(domain)
	}

	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	records := make([]*MXRecord, 0, len(mxRecords))
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		records = append(records, &MXRecord{
			Host:     host,
			Priority: mx.Pref,
			IPs:      r.resolveHost(host),
		})
	}

	r.setCache(domain, records)
	r.logger.Debug("MX resolved", "domain", domain, "records", len(records), "primary", records[0].Host)
	return records, nil
}

func (r *Resolver) fallbackToHostRecords(domain string) ([]*MXRecord, error) {
	ips := r.resolveHost(domain)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no MX or A/AAAA records for %s", domain)
	}
	records := []*MXRecord{{Host: domain, Priority: 0, IPs: ips}}
	r.setCache(domain, records)
	return records, nil
}

func (r *Resolver) resolveHost(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, host)
	if err != nil {
		r.logger.Debug("Host resolution failed", "host", host, "error", err)
		return nil
	}

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
	return append(ipv4, ipv6...)
}

func (r *Resolver) getFromCache(domain string) []*MXRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.cache[domain]
	if !exists {
		atomic.AddInt64(&r.misses, 1)
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddInt64(&r.misses, 1)
		return nil
	}
	atomic.AddInt64(&r.hits, 1)
	return entry.Records
}

func (r *Resolver) setCache(domain string, records []*MXRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.cache) >= r.cfg.CacheSize {
		r.evictOldest()
	}
	r.cache[domain] = &CacheEntry{
		Records:   records,
		ExpiresAt: time.Now().Add(r.cfg.CacheTTL),
	}
}

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

func (r *Resolver) FlushCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*CacheEntry)
}

func (r *Resolver) CacheStats() (size int, hitRate float64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	hits := atomic.LoadInt64(&r.hits)
	misses := atomic.LoadInt64(&r.misses)
	total := hits + misses
	if total == 0 {
		return len(r.cache), 0
	}
	return len(r.cache), float64(hits) / float64(total)
}
