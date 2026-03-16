// pool.go implements a DNS resolver pool for high-concurrency environments.
package dns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"

	"github.com/srmta/srmta/internal/config"
)

// Pool manages a pool of DNS resolvers for concurrent lookups.
type Pool struct {
	resolvers []*net.Resolver
	count     int
	index     uint64 // atomic, for round-robin
}

// NewPool creates a pool of DNS resolvers.
func NewPool(cfg config.DNSConfig) *Pool {
	p := &Pool{
		count:     cfg.PoolSize,
		resolvers: make([]*net.Resolver, cfg.PoolSize),
	}

	for i := 0; i < cfg.PoolSize; i++ {
		idx := i // capture for closure
		p.resolvers[i] = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: cfg.Timeout}
				if len(cfg.Servers) > 0 {
					// Distribute across configured DNS servers
					server := cfg.Servers[idx%len(cfg.Servers)]
					if !strings.Contains(server, ":") {
						server = server + ":53"
					}
					return d.DialContext(ctx, "udp", server)
				}
				return d.DialContext(ctx, network, address)
			},
		}
	}

	return p
}

// Get returns the next resolver from the pool using round-robin.
func (p *Pool) Get() *net.Resolver {
	idx := atomic.AddUint64(&p.index, 1)
	return p.resolvers[idx%uint64(p.count)]
}

// Size returns the pool size.
func (p *Pool) Size() int {
	return p.count
}
