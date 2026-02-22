// Package smtp implements the SRMTA SMTP server and client.
// The server provides RFC 5321-compliant inbound SMTP with ESMTP extensions,
// STARTTLS (TLS 1.2+), AUTH (PLAIN, LOGIN), pipelining, and open relay prevention.
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
	"github.com/srmta/srmta/internal/queue"
)

// Server is the inbound SMTP server.
type Server struct {
	cfg       config.SMTPConfig
	tlsCfg    *tls.Config
	listener  net.Listener
	queue     *queue.Manager
	logger    *logging.Logger
	sessions  sync.WaitGroup
	connCount int64 // atomic
	stopping  int32 // atomic, 1 = stopping
	mu        sync.Mutex
}

// NewServer creates a new SMTP server instance.
func NewServer(cfg config.SMTPConfig, tlsCfgData config.TLSConfig, q *queue.Manager, logger *logging.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		queue:  q,
		logger: logger,
	}

	// Configure TLS if cert/key provided
	if tlsCfgData.CertFile != "" && tlsCfgData.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfgData.CertFile, tlsCfgData.KeyFile)
		if err != nil {
			logger.Error("Failed to load TLS certificate", "error", err)
		} else {
			minVer := tls.VersionTLS12
			if tlsCfgData.MinVersion == "1.3" {
				minVer = tls.VersionTLS13
			}
			s.tlsCfg = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   uint16(minVer),
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			}
		}
	}

	return s
}

// Start begins accepting SMTP connections.
func (s *Server) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}

	s.logger.Info("SMTP server listening", "addr", s.cfg.ListenAddr)

	for {
		// Check if we're shutting down
		if atomic.LoadInt32(&s.stopping) == 1 {
			return nil
		}

		// Set accept deadline so we can check for shutdown
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Deadline exceeded, check shutdown again
			}
			if atomic.LoadInt32(&s.stopping) == 1 {
				return nil
			}
			s.logger.Error("Accept error", "error", err)
			continue
		}

		// Enforce connection limit
		currentConns := atomic.LoadInt64(&s.connCount)
		if currentConns >= int64(s.cfg.MaxConnections) {
			s.logger.Warn("Connection limit reached, rejecting",
				"current", currentConns,
				"max", s.cfg.MaxConnections,
				"remote", conn.RemoteAddr(),
			)
			conn.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			conn.Close()
			metrics.ConnectionsRejected.Inc()
			continue
		}

		atomic.AddInt64(&s.connCount, 1)
		metrics.ConnectionsActive.Set(float64(atomic.LoadInt64(&s.connCount)))
		metrics.ConnectionsTotal.Inc()

		// Handle connection in a new goroutine
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			defer func() {
				atomic.AddInt64(&s.connCount, -1)
				metrics.ConnectionsActive.Set(float64(atomic.LoadInt64(&s.connCount)))
			}()

			session := NewSession(conn, s.cfg, s.tlsCfg, s.queue, s.logger)
			session.Handle(ctx)
		}()
	}
}

// Stop initiates graceful shutdown of the SMTP server.
func (s *Server) Stop() {
	atomic.StoreInt32(&s.stopping, 1)
	if s.listener != nil {
		s.listener.Close()
	}
	// Wait for all active sessions to complete
	s.sessions.Wait()
	s.logger.Info("SMTP server stopped, all sessions drained")
}

// ConnectionCount returns the current number of active connections.
func (s *Server) ConnectionCount() int64 {
	return atomic.LoadInt64(&s.connCount)
}
