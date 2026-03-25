// session.go implements the per-connection SMTP session state machine.
// Handles the full SMTP command flow: EHLO → AUTH → MAIL → RCPT → DATA → QUIT
// with RFC 5321/5322 compliance, STARTTLS upgrade, input validation, and
// SMTP injection prevention.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
	"github.com/srmta/srmta/internal/queue"
)

// sessionState represents the current state in the SMTP transaction.
type sessionState int

const (
	stateConnect sessionState = iota
	stateGreeted              // EHLO/HELO received
	stateAuth                 // Authenticated (if required)
	stateMail                 // MAIL FROM received
	stateRcpt                 // At least one RCPT TO received
	stateData                 // DATA command received
)

// maxCommandLength is the maximum SMTP command line length per RFC 5321 §4.5.3.1.4.
const maxCommandLength = 512

// AuthValidator is an interface for validating SMTP authentication credentials.
type AuthValidator interface {
	ValidatePlain(username, password string) bool
	ValidateLogin(username, password string) bool
	ValidateCRAMMD5(username, challenge, response string) bool
}

// defaultAuthValidator rejects all credentials — a real AuthValidator must be injected.
type defaultAuthValidator struct{}

func (d *defaultAuthValidator) ValidatePlain(username, password string) bool { return false }
func (d *defaultAuthValidator) ValidateLogin(username, password string) bool { return false }
func (d *defaultAuthValidator) ValidateCRAMMD5(username, challenge, resp string) bool {
	return false
}

// Session handles a single SMTP connection.
type Session struct {
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	tp            *textproto.Conn
	cfg           config.SMTPConfig
	tlsCfg        *tls.Config
	queue         *queue.Manager
	logger        *logging.Logger
	authValidator AuthValidator
	rateLimiter   *RateLimiter
	state         sessionState
	tls           bool
	auth          bool
	remoteAddr    string
	remoteIP      string
	correlationID string
	heloHost      string
	mailFrom      string
	rcptTo        []string
	msgData       []byte
	startTime     time.Time
	cmdCount      int // commands processed in this session
}

// NewSession creates a new SMTP session for the given connection.
func NewSession(conn net.Conn, cfg config.SMTPConfig, tlsCfg *tls.Config, q *queue.Manager, logger *logging.Logger, rl *RateLimiter) *Session {
	remoteAddr := conn.RemoteAddr().String()
	// Extract IP from addr (strip port)
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	// Generate correlation ID for request tracing
	corrID := generateCorrelationID()

	return &Session{
		conn:          conn,
		reader:        bufio.NewReader(conn),
		writer:        bufio.NewWriter(conn),
		cfg:           cfg,
		tlsCfg:        tlsCfg,
		queue:         q,
		logger:        logger,
		authValidator: &defaultAuthValidator{},
		rateLimiter:   rl,
		state:         stateConnect,
		remoteAddr:    remoteAddr,
		remoteIP:      remoteIP,
		correlationID: corrID,
		startTime:     time.Now(),
		rcptTo:        make([]string, 0, 10),
	}
}

// generateCorrelationID creates a unique tracing ID for this session.
func generateCorrelationID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", time.Now().Format("20060102150405"), hex.EncodeToString(b))
}

// Handle processes the SMTP session from greeting to completion.
func (s *Session) Handle(ctx context.Context) {
	defer s.conn.Close()
	defer func() {
		duration := time.Since(s.startTime)
		s.logger.Access("SMTP connection closed",
			"remote", s.remoteAddr, "action", "disconnect",
			"duration_ms", duration.Milliseconds(),
			"messages", len(s.rcptTo),
			"tls", s.tls,
			"authenticated", s.auth,
			"correlation_id", s.correlationID)
	}()

	hostname := s.cfg.BannerHostname
	if hostname == "" {
		hostname = "srmta"
	}

	// Check per-IP rate limit before accepting
	if s.rateLimiter != nil && !s.rateLimiter.Allow(s.remoteIP) {
		s.writef("421 4.7.0 Too many connections from your IP, try again later")
		s.logger.Warn("Rate limited connection",
			"remote", s.remoteAddr, "correlation_id", s.correlationID)
		s.logger.Access("SMTP connection rejected (rate limit)",
			"remote", s.remoteAddr, "action", "reject",
			"reason", "rate_limit", "correlation_id", s.correlationID)
		metrics.ConnectionsRejected.Inc()
		return
	}

	s.logger.Access("SMTP connection opened",
		"remote", s.remoteAddr, "action", "connect",
		"correlation_id", s.correlationID)
	s.logger.Debug("New SMTP session",
		"remote", s.remoteAddr, "correlation_id", s.correlationID)

	// Send greeting banner
	bannerHost := s.cfg.BannerHostname
	if bannerHost == "" {
		bannerHost = "srmta.local"
	}
	s.writef("220 %s ESMTP SRMTA Ready", bannerHost)

	for {
		select {
		case <-ctx.Done():
			s.writef("421 4.3.2 Service shutting down")
			return
		default:
		}

		// Set read deadline
		s.conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))

		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("Read error",
					"remote", s.remoteAddr, "correlation_id", s.correlationID, "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		// Enforce command length limit per RFC 5321 §4.5.3.1.4
		if len(line) > maxCommandLength {
			s.writef("500 5.5.1 Command line too long")
			continue
		}

		// Reject lines with embedded null bytes (injection prevention)
		if strings.ContainsRune(line, 0) {
			s.writef("500 5.5.1 Invalid characters in command")
			s.logger.Warn("Null byte injection attempt",
				"remote", s.remoteAddr, "correlation_id", s.correlationID)
			continue
		}

		s.cmdCount++

		// Parse command and arguments
		cmd, args := s.parseCommand(line)

		metrics.SMTPCommandsTotal.WithLabelValues(cmd).Inc()

		switch cmd {
		case "EHLO":
			s.handleEHLO(args)
		case "HELO":
			s.handleHELO(args)
		case "STARTTLS":
			s.handleSTARTTLS()
		case "AUTH":
			s.handleAUTH(args)
		case "MAIL":
			s.handleMAIL(args)
		case "RCPT":
			s.handleRCPT(args)
		case "DATA":
			s.handleDATA()
		case "RSET":
			s.handleRSET()
		case "NOOP":
			s.writef("250 2.0.0 OK")
		case "QUIT":
			s.writef("221 2.0.0 Bye")
			return
		case "VRFY":
			s.writef("252 2.5.1 Cannot verify user")
		case "HELP":
			s.writef("214 2.0.0 See RFC 5321")
		default:
			s.writef("502 5.5.1 Command not recognized")
		}
	}
}

// parseCommand splits an SMTP command line into command and arguments.
func (s *Session) parseCommand(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}
	return cmd, args
}

// handleEHLO processes the EHLO command and advertises capabilities.
func (s *Session) handleEHLO(args string) {
	if args == "" {
		s.writef("501 5.5.4 EHLO requires a hostname")
		return
	}

	// Validate EHLO hostname — reject control characters (injection prevention)
	if containsControlChars(args) {
		s.writef("501 5.5.4 Invalid characters in hostname")
		s.logger.Warn("EHLO injection attempt",
			"remote", s.remoteAddr, "correlation_id", s.correlationID)
		return
	}

	s.heloHost = args
	s.state = stateGreeted
	s.reset()

	hostname := s.cfg.BannerHostname
	if hostname == "" {
		hostname = "srmta"
	}

	// Advertise ESMTP extensions
	extensions := []string{
		fmt.Sprintf("250-%s greets %s", hostname, args),
		fmt.Sprintf("250-SIZE %d", s.cfg.MaxMessageSize),
		"250-8BITMIME",
		"250-ENHANCEDSTATUSCODES",
		"250-DSN",
	}

	if s.cfg.EnablePipelining {
		extensions = append(extensions, "250-PIPELINING")
	}

	// Advertise STARTTLS only if TLS is configured and not already active
	if s.tlsCfg != nil && !s.tls {
		extensions = append(extensions, "250-STARTTLS")
	}

	// Advertise AUTH only after TLS (security best practice)
	if s.tls || !s.cfg.RequireTLS {
		extensions = append(extensions, "250-AUTH PLAIN LOGIN CRAM-MD5")
	}

	extensions = append(extensions, "250 SMTPUTF8")

	for _, ext := range extensions {
		s.writeDirect(ext)
	}
}

// handleHELO processes the legacy HELO command.
func (s *Session) handleHELO(args string) {
	if args == "" {
		s.writef("501 5.5.4 HELO requires a hostname")
		return
	}
	s.heloHost = args
	s.state = stateGreeted
	s.reset()

	hostname := s.cfg.BannerHostname
	if hostname == "" {
		hostname = "srmta"
	}
	s.writef("250 %s", hostname)
}

// handleSTARTTLS upgrades the connection to TLS.
func (s *Session) handleSTARTTLS() {
	if s.tlsCfg == nil {
		s.writef("454 4.7.0 TLS not available")
		return
	}
	if s.tls {
		s.writef("503 5.5.1 TLS already active")
		return
	}

	s.writef("220 2.0.0 Ready to start TLS")

	tlsConn := tls.Server(s.conn, s.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Error("TLS handshake failed", "remote", s.remoteAddr, "error", err)
		metrics.TLSHandshakeErrors.Inc()
		return
	}

	// Replace connection and readers/writers
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.tls = true
	s.state = stateConnect // Must re-EHLO after STARTTLS per RFC 3207

	metrics.TLSConnectionsTotal.Inc()
	s.logger.Debug("TLS established",
		"remote", s.remoteAddr,
		"version", tlsConn.ConnectionState().Version,
	)
}

// handleAUTH processes authentication (PLAIN, LOGIN).
func (s *Session) handleAUTH(args string) {
	if s.state < stateGreeted {
		s.writef("503 5.5.1 EHLO/HELO first")
		return
	}
	if s.cfg.RequireTLS && !s.tls {
		s.writef("538 5.7.11 Encryption required for authentication")
		return
	}
	if s.auth {
		s.writef("503 5.5.1 Already authenticated")
		return
	}

	parts := strings.SplitN(args, " ", 2)
	mechanism := strings.ToUpper(parts[0])

	switch mechanism {
	case "PLAIN":
		s.handleAuthPlain(parts)
	case "LOGIN":
		s.handleAuthLogin()
	case "CRAM-MD5":
		s.handleAuthCRAMMD5()
	default:
		s.writef("504 5.5.4 Authentication mechanism not supported")
	}
}

// handleAuthPlain processes PLAIN authentication (RFC 4616).
func (s *Session) handleAuthPlain(parts []string) {
	var encoded string
	if len(parts) > 1 {
		encoded = parts[1]
	} else {
		s.writef("334 ")
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		encoded = strings.TrimSpace(line)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		s.writef("501 5.5.2 Invalid Base64 encoding")
		return
	}

	// PLAIN: \0authcid\0password
	fields := bytes.Split(decoded, []byte{0})
	if len(fields) != 3 {
		s.writef("501 5.5.2 Malformed AUTH PLAIN data")
		return
	}

	username := string(fields[1])
	password := string(fields[2])

	// Validate credentials
	if s.authValidator != nil && !s.authValidator.ValidatePlain(username, password) {
		s.writef("535 5.7.8 Authentication credentials invalid")
		s.logger.Warn("AUTH PLAIN failed",
			"remote", s.remoteAddr, "user", logging.MaskEmail(username), "correlation_id", s.correlationID)
		metrics.AuthFailureTotal.Inc()
		return
	}

	s.auth = true
	s.state = stateAuth
	s.logger.Info("Authentication successful",
		"remote", s.remoteAddr, "user", logging.MaskEmail(username),
		"mechanism", "PLAIN", "correlation_id", s.correlationID)
	s.writef("235 2.7.0 Authentication successful")
	metrics.AuthSuccessTotal.Inc()
}

// handleAuthLogin processes LOGIN authentication.
func (s *Session) handleAuthLogin() {
	s.writef("334 VXNlcm5hbWU6") // "Username:" base64
	username, err := s.reader.ReadString('\n')
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)

	s.writef("334 UGFzc3dvcmQ6") // "Password:" base64
	password, err := s.reader.ReadString('\n')
	if err != nil {
		return
	}
	password = strings.TrimSpace(password)

	usernameBytes, err := base64.StdEncoding.DecodeString(username)
	if err != nil {
		s.writef("501 5.5.2 Invalid Base64 encoding")
		return
	}

	passwordBytes, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		s.writef("501 5.5.2 Invalid Base64 encoding")
		return
	}

	// Validate credentials
	if s.authValidator != nil && !s.authValidator.ValidateLogin(string(usernameBytes), string(passwordBytes)) {
		s.writef("535 5.7.8 Authentication credentials invalid")
		s.logger.Warn("AUTH LOGIN failed",
			"remote", s.remoteAddr, "user", logging.MaskEmail(string(usernameBytes)), "correlation_id", s.correlationID)
		metrics.AuthFailureTotal.Inc()
		return
	}

	s.auth = true
	s.state = stateAuth
	s.logger.Info("AUTH LOGIN successful",
		"remote", s.remoteAddr, "user", logging.MaskEmail(string(usernameBytes)),
		"mechanism", "LOGIN", "correlation_id", s.correlationID)
	s.writef("235 2.7.0 Authentication successful")
	metrics.AuthSuccessTotal.Inc()
}

// handleMAIL processes the MAIL FROM command.
func (s *Session) handleMAIL(args string) {
	if s.state < stateGreeted {
		s.writef("503 5.5.1 EHLO/HELO first")
		return
	}

	// Enforce authentication for open relay prevention
	if s.cfg.RequireAuth && !s.auth {
		s.writef("530 5.7.0 Authentication required")
		metrics.AuthFailureTotal.Inc()
		return
	}

	// Parse MAIL FROM:<address> [params]
	upperArgs := strings.ToUpper(args)
	if !strings.HasPrefix(upperArgs, "FROM:") {
		s.writef("501 5.5.4 Syntax: MAIL FROM:<address>")
		return
	}

	addr := args[5:] // Remove "FROM:"
	addr = strings.TrimSpace(addr)

	// Extract address from angle brackets
	email := s.extractAddress(addr)
	if email == "" && addr != "<>" { // Allow null sender for bounces
		s.writef("501 5.1.7 Invalid sender address")
		return
	}

	// Validate sender domain if configured
	if email != "" && len(s.cfg.AllowedDomains) > 0 {
		domain := s.extractDomain(email)
		if !s.isDomainAllowed(domain) {
			s.writef("553 5.7.1 Sender domain not allowed")
			s.logger.Warn("Rejected sender: domain not allowed",
				"remote", s.remoteAddr, "sender", logging.MaskEmail(email), "domain", domain)
			return
		}
	}

	s.mailFrom = email
	s.state = stateMail
	s.writef("250 2.1.0 OK")
}

// handleRCPT processes the RCPT TO command.
func (s *Session) handleRCPT(args string) {
	if s.state < stateMail {
		s.writef("503 5.5.1 MAIL FROM first")
		return
	}

	if len(s.rcptTo) >= s.cfg.MaxRecipients {
		s.writef("452 4.5.3 Too many recipients")
		return
	}

	// Parse RCPT TO:<address>
	upperArgs := strings.ToUpper(args)
	if !strings.HasPrefix(upperArgs, "TO:") {
		s.writef("501 5.5.4 Syntax: RCPT TO:<address>")
		return
	}

	addr := args[3:]
	addr = strings.TrimSpace(addr)
	email := s.extractAddress(addr)

	if email == "" {
		s.writef("501 5.1.3 Invalid recipient address")
		return
	}

	s.rcptTo = append(s.rcptTo, email)
	s.state = stateRcpt
	s.writef("250 2.1.5 OK")
}

// handleDATA processes the DATA command and receives the message body.
func (s *Session) handleDATA() {
	if s.state < stateRcpt {
		s.writef("503 5.5.1 RCPT TO first")
		return
	}

	s.writef("354 Start mail input; end with <CRLF>.<CRLF>")

	// Read message data until <CRLF>.<CRLF>
	var buf bytes.Buffer
	for {
		s.conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			s.logger.Error("Error reading DATA", "remote", s.remoteAddr, "error", err)
			return
		}

		// Check for end-of-data marker
		if bytes.Equal(bytes.TrimRight(line, "\r\n"), []byte(".")) {
			break
		}

		// Dot-stuffing: remove leading dot per RFC 5321 §4.5.2
		if len(line) > 1 && line[0] == '.' {
			line = line[1:]
		}

		// Enforce message size limit
		if buf.Len()+len(line) > int(s.cfg.MaxMessageSize) {
			s.writef("552 5.3.4 Message size exceeds limit")
			// Drain remaining data
			for {
				remaining, _ := s.reader.ReadBytes('\n')
				if bytes.Equal(bytes.TrimRight(remaining, "\r\n"), []byte(".")) {
					break
				}
			}
			s.reset()
			return
		}

		buf.Write(line)
	}

	s.msgData = buf.Bytes()

	// Enqueue the message
	msgID, err := s.queue.Enqueue(s.mailFrom, s.rcptTo, s.msgData, s.remoteAddr)
	if err != nil {
		s.logger.Error("Failed to enqueue message", "error", err, "remote", s.remoteAddr)
		s.writef("451 4.3.0 Temporary queue failure")
		metrics.EnqueueErrors.Inc()
		return
	}

	latency := time.Since(s.startTime)
	s.logger.Info("Message accepted",
		"message_id", msgID,
		"sender", logging.MaskEmail(s.mailFrom),
		"recipients", len(s.rcptTo),
		"size", len(s.msgData),
		"remote", s.remoteAddr,
		"tls", s.tls,
		"latency_ms", latency.Milliseconds(),
	)

	metrics.MessagesAccepted.Inc()
	metrics.MessageSizeBytes.Observe(float64(len(s.msgData)))
	metrics.ProcessingLatency.Observe(latency.Seconds())

	s.writef("250 2.0.0 OK: queued as %s", msgID)
	s.reset()
}

// handleRSET resets the session state for a new transaction.
func (s *Session) handleRSET() {
	s.reset()
	s.writef("250 2.0.0 OK")
}

// reset clears the transaction state but preserves connection state.
func (s *Session) reset() {
	s.mailFrom = ""
	s.rcptTo = s.rcptTo[:0]
	s.msgData = nil
	if s.state > stateGreeted {
		if s.auth {
			s.state = stateAuth
		} else {
			s.state = stateGreeted
		}
	}
}

// extractAddress extracts an email address from angle brackets or bare format.
// Includes SMTP injection prevention — rejects addresses with CRLF or null bytes.
func (s *Session) extractAddress(raw string) string {
	// SMTP injection prevention: check BEFORE trimming to catch trailing CRLF
	if strings.ContainsAny(raw, "\r\n\x00") {
		s.logger.Warn("SMTP injection attempt in address",
			"remote", s.remoteAddr, "correlation_id", s.correlationID)
		return ""
	}

	raw = strings.TrimSpace(raw)

	// Remove ESMTP parameters (e.g., SIZE=1234)
	if idx := strings.Index(raw, " "); idx > 0 {
		raw = raw[:idx]
	}

	// Remove angle brackets
	if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") {
		raw = raw[1 : len(raw)-1]
	}

	// Basic validation
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "@") && raw != "" {
		return "" // Must have @ for non-empty addresses
	}

	// Additional validation: no embedded spaces, reasonable length
	if strings.Contains(raw, " ") || len(raw) > 254 {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(raw))
}

// extractDomain returns the domain part of an email address.
func (s *Session) extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// isDomainAllowed checks if a domain is in the allowed list.
func (s *Session) isDomainAllowed(domain string) bool {
	for _, d := range s.cfg.AllowedDomains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// writef sends a formatted response to the client.
func (s *Session) writef(format string, args ...interface{}) {
	s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	msg := fmt.Sprintf(format, args...)
	s.writer.WriteString(msg + "\r\n")
	s.writer.Flush()
}

// writeDirect sends a raw line to the client (for multi-line responses).
func (s *Session) writeDirect(line string) {
	s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	s.writer.WriteString(line + "\r\n")
	s.writer.Flush()
}

// handleAuthCRAMMD5 processes CRAM-MD5 authentication per RFC 2195.
func (s *Session) handleAuthCRAMMD5() {
	// Generate challenge
	challenge := fmt.Sprintf("<%d.%d@%s>",
		time.Now().UnixNano(), time.Now().Unix(),
		s.cfg.BannerHostname)

	challengeB64 := base64.StdEncoding.EncodeToString([]byte(challenge))
	s.writef("334 %s", challengeB64)

	// Read response
	response, err := s.reader.ReadString('\n')
	if err != nil {
		return
	}
	response = strings.TrimSpace(response)

	if response == "*" {
		s.writef("501 5.7.0 Authentication cancelled")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		s.writef("501 5.5.2 Invalid Base64 encoding")
		return
	}

	// CRAM-MD5 response format: "username digest"
	parts := strings.SplitN(string(decoded), " ", 2)
	if len(parts) != 2 {
		s.writef("501 5.5.2 Malformed CRAM-MD5 response")
		return
	}

	username := parts[0]
	digest := parts[1]

	// Validate via auth backend
	if s.authValidator != nil && !s.authValidator.ValidateCRAMMD5(username, challenge, digest) {
		s.writef("535 5.7.8 Authentication credentials invalid")
		s.logger.Warn("AUTH CRAM-MD5 failed",
			"remote", s.remoteAddr, "user", logging.MaskEmail(username), "correlation_id", s.correlationID)
		metrics.AuthFailureTotal.Inc()
		return
	}

	s.auth = true
	s.state = stateAuth
	s.logger.Info("AUTH CRAM-MD5 successful",
		"remote", s.remoteAddr, "user", logging.MaskEmail(username),
		"mechanism", "CRAM-MD5", "correlation_id", s.correlationID)
	s.writef("235 2.7.0 Authentication successful")
	metrics.AuthSuccessTotal.Inc()
}

// ComputeCRAMMD5 computes the CRAM-MD5 digest for validation.
// Note: CRAM-MD5 uses HMAC-MD5 per RFC 2195. MD5 is weak but required by the protocol.
// Consider deprecating CRAM-MD5 in favor of PLAIN over TLS.
func ComputeCRAMMD5(challenge, password string) string {
	hmacHash := hmac.New(md5.New, []byte(password))
	hmacHash.Write([]byte(challenge))
	return hex.EncodeToString(hmacHash.Sum(nil))
}

// containsControlChars checks if a string contains ASCII control characters.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 32 && r != '\t' {
			return true
		}
	}
	return false
}
