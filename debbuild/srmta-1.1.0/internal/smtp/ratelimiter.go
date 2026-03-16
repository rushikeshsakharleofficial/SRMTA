// Package smtp — ratelimiter.go implements per-IP token bucket rate limiting
// for inbound SMTP connections to prevent abuse and DoS attacks.
package smtp

import (
	"sync"
	"time"
)

// RateLimiter implements a per-IP token bucket rate limiter.
type RateLimiter struct {
	rate    int // max requests per window
	window  time.Duration
	buckets map[string]*bucket
	mu      sync.Mutex
}

// bucket tracks request counts for a single IP.
type bucket struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a new per-IP rate limiter.
// rate is the maximum number of requests allowed per window duration.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rate:    rate,
		window:  window,
		buckets: make(map[string]*bucket),
	}

	// Start cleanup goroutine to evict expired buckets
	go rl.cleanup()
	return rl
}

// Allow checks if a request from the given IP should be allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]

	if !exists {
		rl.buckets[ip] = &bucket{
			count:       1,
			windowStart: now,
		}
		return true
	}

	// Check if window has expired
	if now.Sub(b.windowStart) > rl.window {
		b.count = 1
		b.windowStart = now
		return true
	}

	// Check rate
	if b.count >= rl.rate {
		return false
	}

	b.count++
	return true
}

// cleanup periodically removes expired buckets to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, b := range rl.buckets {
			if now.Sub(b.windowStart) > rl.window*2 {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}
