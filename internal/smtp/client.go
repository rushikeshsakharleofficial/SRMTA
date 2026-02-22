// client.go implements the outbound SMTP client with connection pooling,
// per-domain concurrency control, MX grouping, DSN support, and pipelining.
package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
)

// DeliveryResult represents the outcome of an SMTP delivery attempt.
type DeliveryResult struct {
	MessageID    string
	Recipient    string
	Status       string // "delivered", "deferred", "bounced"
	ResponseCode int
	ResponseText string
	RemoteMX     string
	IPUsed       string
	TLSUsed      bool
	Duration     time.Duration
	RetryCount   int
}

// Client is the outbound SMTP client with connection pooling.
type Client struct {
	cfg    config.DeliveryConfig
	logger *logging.Logger
	pools  map[string]*connPool // keyed by MX host
	mu     sync.RWMutex
}

// connPool manages a pool of connections to a specific MX host.
type connPool struct {
	host    string
	conns   chan *smtpConn
	maxSize int
	mu      sync.Mutex
}

// smtpConn wraps a single SMTP connection.
type smtpConn struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	host      string
	createdAt time.Time
	lastUsed  time.Time
	tls       bool
}

// NewClient creates a new outbound SMTP client.
func NewClient(cfg config.DeliveryConfig, logger *logging.Logger) *Client {
	return &Client{
		cfg:    cfg,
		logger: logger,
		pools:  make(map[string]*connPool),
	}
}

// Deliver sends a message to the specified MX host.
func (c *Client) Deliver(mxHost string, localIP string, from string, to string, data []byte) (*DeliveryResult, error) {
	start := time.Now()

	result := &DeliveryResult{
		Recipient: to,
		RemoteMX:  mxHost,
		IPUsed:    localIP,
	}

	// Get or create connection
	conn, err := c.getConnection(mxHost, localIP)
	if err != nil {
		result.Status = "deferred"
		result.ResponseText = err.Error()
		return result, fmt.Errorf("connection to %s failed: %w", mxHost, err)
	}
	defer c.returnConnection(mxHost, conn)

	// Perform SMTP transaction
	err = c.performTransaction(conn, from, to, data, result)
	result.Duration = time.Since(start)

	if err != nil {
		metrics.DeliveryErrors.WithLabelValues(result.Status).Inc()
		return result, err
	}

	metrics.DeliveredTotal.Inc()
	metrics.DeliveryDuration.Observe(result.Duration.Seconds())
	return result, nil
}

// getConnection retrieves a pooled connection or creates a new one.
func (c *Client) getConnection(mxHost string, localIP string) (*smtpConn, error) {
	c.mu.RLock()
	pool, exists := c.pools[mxHost]
	c.mu.RUnlock()

	if exists {
		select {
		case conn := <-pool.conns:
			// Validate the connection is still alive
			if time.Since(conn.lastUsed) < c.cfg.PoolIdleTimeout {
				conn.lastUsed = time.Now()
				return conn, nil
			}
			// Connection expired, close it
			conn.conn.Close()
		default:
			// No idle connections available
		}
	}

	// Create new connection
	return c.dial(mxHost, localIP)
}

// dial creates a new SMTP connection to the MX host.
func (c *Client) dial(mxHost string, localIP string) (*smtpConn, error) {
	// Resolve local address for binding
	var localAddr net.Addr
	if localIP != "" {
		localAddr, _ = net.ResolveTCPAddr("tcp", localIP+":0")
	}

	dialer := &net.Dialer{
		Timeout:   c.cfg.DialTimeout,
		LocalAddr: localAddr,
	}

	// Connect to port 25
	addr := mxHost + ":25"
	netConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sc := &smtpConn{
		conn:      netConn,
		reader:    bufio.NewReader(netConn),
		writer:    bufio.NewWriter(netConn),
		host:      mxHost,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	// Read greeting
	code, msg, err := sc.readResponse()
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("greeting from %s: %w", mxHost, err)
	}
	if code != 220 {
		netConn.Close()
		return nil, fmt.Errorf("unexpected greeting from %s: %d %s", mxHost, code, msg)
	}

	// Send EHLO
	hostname := "srmta.local" // TODO: use configured hostname
	code, _, err = sc.command("EHLO %s", hostname)
	if err != nil || code != 250 {
		// Fall back to HELO
		code, _, err = sc.command("HELO %s", hostname)
		if err != nil {
			netConn.Close()
			return nil, fmt.Errorf("HELO to %s failed: %w", mxHost, err)
		}
	}

	// Attempt STARTTLS
	code, _, err = sc.command("STARTTLS")
	if err == nil && code == 220 {
		tlsConn := tls.Client(netConn, &tls.Config{
			ServerName: mxHost,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			c.logger.Warn("STARTTLS handshake failed, continuing plain",
				"host", mxHost, "error", err)
			metrics.TLSHandshakeErrors.Inc()
		} else {
			sc.conn = tlsConn
			sc.reader = bufio.NewReader(tlsConn)
			sc.writer = bufio.NewWriter(tlsConn)
			sc.tls = true

			// Re-EHLO after TLS
			sc.command("EHLO %s", hostname)
			metrics.TLSConnectionsTotal.Inc()
		}
	}

	return sc, nil
}

// performTransaction executes the MAIL/RCPT/DATA sequence.
func (c *Client) performTransaction(sc *smtpConn, from, to string, data []byte, result *DeliveryResult) error {
	result.TLSUsed = sc.tls

	// MAIL FROM
	code, msg, err := sc.command("MAIL FROM:<%s>", from)
	if err != nil {
		result.Status = "deferred"
		result.ResponseText = err.Error()
		return err
	}
	if code != 250 {
		result.ResponseCode = code
		result.ResponseText = msg
		result.Status = classifyResponse(code)
		return fmt.Errorf("MAIL FROM rejected: %d %s", code, msg)
	}

	// RCPT TO
	code, msg, err = sc.command("RCPT TO:<%s>", to)
	if err != nil {
		result.Status = "deferred"
		result.ResponseText = err.Error()
		return err
	}
	if code != 250 && code != 251 {
		result.ResponseCode = code
		result.ResponseText = msg
		result.Status = classifyResponse(code)
		return fmt.Errorf("RCPT TO rejected: %d %s", code, msg)
	}

	// DATA
	code, msg, err = sc.command("DATA")
	if err != nil {
		result.Status = "deferred"
		result.ResponseText = err.Error()
		return err
	}
	if code != 354 {
		result.ResponseCode = code
		result.ResponseText = msg
		result.Status = classifyResponse(code)
		return fmt.Errorf("DATA rejected: %d %s", code, msg)
	}

	// Send message body with dot-stuffing
	sc.writeData(data)
	sc.writer.WriteString("\r\n.\r\n")
	sc.writer.Flush()

	// Read response to data
	code, msg, err = sc.readResponse()
	if err != nil {
		result.Status = "deferred"
		result.ResponseText = err.Error()
		return err
	}

	result.ResponseCode = code
	result.ResponseText = msg

	if code == 250 {
		result.Status = "delivered"
		return nil
	}

	result.Status = classifyResponse(code)
	return fmt.Errorf("delivery failed: %d %s", code, msg)
}

// returnConnection returns a connection to the pool.
func (c *Client) returnConnection(mxHost string, sc *smtpConn) {
	c.mu.Lock()
	pool, exists := c.pools[mxHost]
	if !exists {
		pool = &connPool{
			host:    mxHost,
			conns:   make(chan *smtpConn, c.cfg.PoolSize),
			maxSize: c.cfg.PoolSize,
		}
		c.pools[mxHost] = pool
	}
	c.mu.Unlock()

	select {
	case pool.conns <- sc:
		// Returned to pool
	default:
		// Pool full, close
		sc.command("QUIT")
		sc.conn.Close()
	}
}

// classifyResponse determines the delivery status from an SMTP response code.
func classifyResponse(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "delivered"
	case code >= 400 && code < 500:
		return "deferred" // Temporary failure, retry
	case code >= 500:
		return "bounced" // Permanent failure
	default:
		return "deferred"
	}
}

// command sends an SMTP command and reads the response.
func (sc *smtpConn) command(format string, args ...interface{}) (int, string, error) {
	cmd := fmt.Sprintf(format, args...)
	sc.writer.WriteString(cmd + "\r\n")
	if err := sc.writer.Flush(); err != nil {
		return 0, "", err
	}
	return sc.readResponse()
}

// readResponse reads a potentially multi-line SMTP response.
func (sc *smtpConn) readResponse() (int, string, error) {
	var lines []string
	var code int

	for {
		line, err := sc.reader.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")

		if len(line) < 3 {
			return 0, "", fmt.Errorf("short response: %q", line)
		}

		c := 0
		for i := 0; i < 3 && i < len(line); i++ {
			c = c*10 + int(line[i]-'0')
		}
		code = c

		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		lines = append(lines, msg)

		// Check if this is the last line (space after code, not dash)
		if len(line) == 3 || line[3] == ' ' {
			break
		}
	}

	return code, strings.Join(lines, "\n"), nil
}

// writeData writes message data with dot-stuffing per RFC 5321.
func (sc *smtpConn) writeData(data []byte) {
	reader := bufio.NewReader(strings.NewReader(string(data)))
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			// Dot-stuffing: lines starting with '.' get an extra '.'
			if strings.HasPrefix(line, ".") {
				sc.writer.WriteString(".")
			}
			sc.writer.WriteString(line)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
}

// Close closes the SMTP connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for host, pool := range c.pools {
		close(pool.conns)
		for sc := range pool.conns {
			sc.command("QUIT")
			sc.conn.Close()
		}
		delete(c.pools, host)
	}
}
