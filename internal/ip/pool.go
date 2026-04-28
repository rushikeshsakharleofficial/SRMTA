// Package ip implements IP pool management with health scoring,
// automatic disable/recovery, and warm-up policy for the SRMTA MTA.
package ip

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
)

// HealthMetrics tracks delivery health for a single IP.
type HealthMetrics struct {
	TotalSent   int64
	Delivered   int64
	SoftBounces int64
	HardBounces int64
	Timeouts    int64
	TLSFailures int64
	Rate4xx     float64
	Rate5xx     float64
	TimeoutRate float64
	TLSFailRate float64
	HealthScore float64 // 0.0 (worst) to 1.0 (best)
	LastUpdated time.Time
}

// PoolIP represents an IP address in the sending pool.
type PoolIP struct {
	Address    string
	Version    int // 4 or 6
	Weight     int
	Disabled   bool
	DisabledAt time.Time
	Health     HealthMetrics
	WarmUp     *WarmUpState
	mu         sync.Mutex
}

// WarmUpState tracks warm-up progress for a new IP.
type WarmUpState struct {
	Active     bool
	StartDate  time.Time
	CurrentDay int
	MaxRate    int // Current max emails/hour
	Schedule   []WarmUpStep
}

// WarmUpStep defines a warm-up schedule step.
type WarmUpStep struct {
	Day     int `yaml:"day"`
	MaxRate int `yaml:"max_rate"` // emails per hour
}

// Pool manages the IP sending pool.
type Pool struct {
	cfg    config.IPPoolConfig
	logger *logging.Logger
	ips    []*PoolIP
	mu     sync.RWMutex
}

// NewPool creates a new IP pool manager.
func NewPool(cfg config.IPPoolConfig, logger *logging.Logger) *Pool {
	p := &Pool{
		cfg:    cfg,
		logger: logger,
		ips:    make([]*PoolIP, 0, len(cfg.IPs)),
	}

	// Initialize IPs from configuration
	for _, ipCfg := range cfg.IPs {
		poolIP := &PoolIP{
			Address:  ipCfg.Address,
			Version:  ipCfg.Version,
			Weight:   ipCfg.Weight,
			Disabled: ipCfg.Disabled,
			Health: HealthMetrics{
				HealthScore: 1.0,
				LastUpdated: time.Now(),
			},
		}

		if ipCfg.WarmUp {
			poolIP.WarmUp = &WarmUpState{
				Active:    true,
				StartDate: time.Now(),
				MaxRate:   ipCfg.MaxRate,
				Schedule:  defaultWarmUpSchedule(),
			}
		}

		p.ips = append(p.ips, poolIP)
	}

	if len(p.ips) == 0 {
		// Add default IP (bind to all interfaces)
		p.ips = append(p.ips, &PoolIP{
			Address: "0.0.0.0",
			Version: 4,
			Weight:  100,
			Health: HealthMetrics{
				HealthScore: 1.0,
				LastUpdated: time.Now(),
			},
		})
	}

	return p
}

// SelectIP selects the best available IP for sending, considering health scores and weights.
func (p *Pool) SelectIP() *PoolIP {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best *PoolIP
	var bestScore float64 = -1

	for _, ip := range p.ips {
		ip.mu.Lock()
		if ip.Disabled {
			ip.mu.Unlock()
			continue
		}

		// Calculate weighted score
		score := ip.Health.HealthScore * float64(ip.Weight)

		// Penalize warm-up IPs that are at capacity
		if ip.WarmUp != nil && ip.WarmUp.Active {
			if ip.Health.TotalSent > int64(ip.WarmUp.MaxRate) {
				ip.mu.Unlock()
				continue
			}
		}

		if score > bestScore {
			bestScore = score
			best = ip
		}
		ip.mu.Unlock()
	}

	return best
}

// RecordResult updates health metrics for an IP based on a delivery result.
func (p *Pool) RecordResult(address string, delivered bool, responseCode int, tlsUsed bool, timeout bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, ip := range p.ips {
		if ip.Address != address {
			continue
		}
		ip.mu.Lock()
		p.updateIPHealth(ip, delivered, responseCode, tlsUsed, timeout)
		ip.mu.Unlock()
		return
	}
}

// updateIPHealth applies one delivery result to ip's counters, recalculates rates/score,
// and auto-disables the IP if the health score falls below the threshold.
// Caller must hold ip.mu.
func (p *Pool) updateIPHealth(ip *PoolIP, delivered bool, responseCode int, tlsUsed bool, timeout bool) {
	ip.Health.TotalSent++

	switch {
	case delivered:
		ip.Health.Delivered++
	case responseCode >= 500:
		ip.Health.HardBounces++
	case responseCode >= 400:
		ip.Health.SoftBounces++
	}

	if timeout {
		ip.Health.Timeouts++
	}
	if !tlsUsed {
		ip.Health.TLSFailures++
	}

	total := float64(ip.Health.TotalSent)
	if total > 0 {
		ip.Health.Rate4xx = float64(ip.Health.SoftBounces) / total
		ip.Health.Rate5xx = float64(ip.Health.HardBounces) / total
		ip.Health.TimeoutRate = float64(ip.Health.Timeouts) / total
		ip.Health.TLSFailRate = float64(ip.Health.TLSFailures) / total
	}

	ip.Health.HealthScore = p.calculateHealthScore(&ip.Health)
	ip.Health.LastUpdated = time.Now()

	if ip.Health.HealthScore < p.cfg.DisableThreshold && !ip.Disabled {
		ip.Disabled = true
		ip.DisabledAt = time.Now()
		p.logger.Warn("IP auto-disabled due to poor health",
			"ip", ip.Address,
			"score", ip.Health.HealthScore,
			"4xx_rate", ip.Health.Rate4xx,
			"5xx_rate", ip.Health.Rate5xx,
		)
		metrics.IPDisabled.WithLabelValues(ip.Address).Inc()
	}

	metrics.IPHealthScore.WithLabelValues(ip.Address).Set(ip.Health.HealthScore)
}

// calculateHealthScore computes a health score from 0.0 to 1.0.
func (p *Pool) calculateHealthScore(h *HealthMetrics) float64 {
	// Weighted factors
	score := 1.0
	score -= h.Rate5xx * 3.0     // Heavy penalty for 5xx
	score -= h.Rate4xx * 1.5     // Moderate penalty for 4xx
	score -= h.TimeoutRate * 2.0 // Heavy penalty for timeouts
	score -= h.TLSFailRate * 0.5 // Light penalty for TLS failures

	return math.Max(0.0, math.Min(1.0, score))
}

// StartHealthMonitor begins periodic health monitoring and recovery.
func (p *Pool) StartHealthMonitor(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkRecovery()
		}
	}
}

// checkRecovery re-enables IPs that have been disabled long enough.
func (p *Pool) checkRecovery() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, ip := range p.ips {
		ip.mu.Lock()
		if ip.Disabled && !ip.DisabledAt.IsZero() {
			if time.Since(ip.DisabledAt) >= p.cfg.RecoveryTime {
				ip.Disabled = false
				ip.Health = HealthMetrics{
					HealthScore: 0.7, // Start at 70% after recovery
					LastUpdated: time.Now(),
				}
				p.logger.Info("IP recovered from disable",
					"ip", ip.Address,
					"disabled_duration", time.Since(ip.DisabledAt),
				)
			}
		}
		ip.mu.Unlock()
	}
}

// Reload updates the IP pool from new configuration (hot-reload support).
func (p *Pool) Reload(cfg config.IPPoolConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cfg = cfg
	p.logger.Info("IP pool configuration reloaded")
}

// Stats returns health statistics for all IPs.
func (p *Pool) Stats() []IPStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make([]IPStats, len(p.ips))
	for i, ip := range p.ips {
		ip.mu.Lock()
		stats[i] = IPStats{
			Address:     ip.Address,
			Version:     ip.Version,
			Disabled:    ip.Disabled,
			HealthScore: ip.Health.HealthScore,
			TotalSent:   ip.Health.TotalSent,
			Delivered:   ip.Health.Delivered,
			Rate4xx:     ip.Health.Rate4xx,
			Rate5xx:     ip.Health.Rate5xx,
		}
		ip.mu.Unlock()
	}
	return stats
}

// IPStats holds statistics for a single IP.
type IPStats struct {
	Address     string  `json:"address"`
	Version     int     `json:"version"`
	Disabled    bool    `json:"disabled"`
	HealthScore float64 `json:"health_score"`
	TotalSent   int64   `json:"total_sent"`
	Delivered   int64   `json:"delivered"`
	Rate4xx     float64 `json:"rate_4xx"`
	Rate5xx     float64 `json:"rate_5xx"`
}

// defaultWarmUpSchedule returns the default IP warm-up schedule.
func defaultWarmUpSchedule() []WarmUpStep {
	return []WarmUpStep{
		{Day: 1, MaxRate: 50},
		{Day: 2, MaxRate: 100},
		{Day: 3, MaxRate: 500},
		{Day: 4, MaxRate: 1000},
		{Day: 5, MaxRate: 5000},
		{Day: 6, MaxRate: 10000},
		{Day: 7, MaxRate: 25000},
		{Day: 14, MaxRate: 50000},
		{Day: 21, MaxRate: 100000},
		{Day: 30, MaxRate: -1}, // Unlimited
	}
}
