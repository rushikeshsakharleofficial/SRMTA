// Package dkim implements DKIM signing with multi-key support per RFC 6376.
package dkim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/config"
)

// Signer handles DKIM signing for outbound messages.
type Signer struct {
	keys       map[string]*signingKey // domain:selector -> key
	defaultKey string
	mu         sync.RWMutex
}

// signingKey holds a parsed DKIM signing key.
type signingKey struct {
	Selector   string
	Domain     string
	PrivateKey *rsa.PrivateKey
	Algorithm  string
}

// NewSigner creates a new DKIM signer from configuration.
func NewSigner(cfg config.DKIMConfig) (*Signer, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	s := &Signer{
		keys:       make(map[string]*signingKey),
		defaultKey: cfg.DefaultKey,
	}

	for _, keyCfg := range cfg.Keys {
		privKey, err := loadPrivateKey(keyCfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load DKIM key %s/%s: %w",
				keyCfg.Domain, keyCfg.Selector, err)
		}

		keyID := keyCfg.Domain + ":" + keyCfg.Selector
		s.keys[keyID] = &signingKey{
			Selector:   keyCfg.Selector,
			Domain:     keyCfg.Domain,
			PrivateKey: privKey,
			Algorithm:  keyCfg.Algorithm,
		}
	}

	return s, nil
}

// Sign adds a DKIM-Signature header to the message.
func (s *Signer) Sign(data []byte, sender string) ([]byte, error) {
	if s == nil || len(s.keys) == 0 {
		return data, nil
	}

	// Determine signing domain from sender
	domain := extractDomain(sender)

	// Find appropriate key
	key := s.findKey(domain)
	if key == nil {
		return data, nil // No key for this domain, skip signing
	}

	// Parse headers and body
	headerEnd := findHeaderEnd(data)
	headers := string(data[:headerEnd])
	body := data[headerEnd:]

	// Canonicalize body (relaxed canonicalization)
	canonBody := canonicalizeBodyRelaxed(body)

	// Hash the body
	bodyHash := sha256.Sum256(canonBody)
	bodyHashB64 := base64.StdEncoding.EncodeToString(bodyHash[:])

	// Build DKIM-Signature header (without b= value)
	timestamp := time.Now().Unix()
	signedHeaders := extractSignedHeaders(headers)

	dkimHeader := fmt.Sprintf(
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s;\r\n"+
			"\tt=%d; bh=%s;\r\n"+
			"\th=%s;\r\n"+
			"\tb=",
		key.Domain, key.Selector, timestamp, bodyHashB64,
		strings.Join(signedHeaders, ":"),
	)

	// Canonicalize headers for signing
	canonHeaders := canonicalizeHeadersRelaxed(headers, signedHeaders)
	canonHeaders += canonicalizeHeaderRelaxed(dkimHeader)

	// Sign
	headerHash := sha256.Sum256([]byte(canonHeaders))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, headerHash[:])
	if err != nil {
		return nil, fmt.Errorf("DKIM signature failed: %w", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	// Fold the signature for readability (76-char lines)
	foldedSig := foldBase64(sigB64, 76)

	// Build complete DKIM header
	fullDKIM := dkimHeader + foldedSig + "\r\n"

	// Prepend DKIM header to message
	signed := make([]byte, 0, len(fullDKIM)+len(data))
	signed = append(signed, []byte(fullDKIM)...)
	signed = append(signed, data...)

	return signed, nil
}

// findKey selects the best signing key for a domain.
func (s *Signer) findKey(domain string) *signingKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try exact domain match first
	for _, key := range s.keys {
		if strings.EqualFold(key.Domain, domain) {
			return key
		}
	}

	// Try default key
	if s.defaultKey != "" {
		if key, ok := s.keys[s.defaultKey]; ok {
			return key
		}
	}

	// Return first available key
	for _, key := range s.keys {
		return key
	}

	return nil
}

// loadPrivateKey reads and parses a PEM-encoded RSA private key.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS8 first, then PKCS1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("key is not RSA")
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return rsaKey, nil
}

// extractDomain returns the domain part of an email address.
func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// findHeaderEnd finds the position where headers end and body begins.
func findHeaderEnd(data []byte) int {
	s := string(data)
	idx := strings.Index(s, "\r\n\r\n")
	if idx >= 0 {
		return idx + 4
	}
	idx = strings.Index(s, "\n\n")
	if idx >= 0 {
		return idx + 2
	}
	return len(data)
}

// extractSignedHeaders returns the list of headers to sign.
func extractSignedHeaders(headers string) []string {
	// Standard set of headers to sign
	signHeaders := []string{"from", "to", "subject", "date", "message-id", "mime-version", "content-type"}
	var found []string

	lines := strings.Split(headers, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		headerName := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		for _, sh := range signHeaders {
			if headerName == sh {
				found = append(found, headerName)
				break
			}
		}
	}

	return found
}

// canonicalizeBodyRelaxed applies relaxed body canonicalization per RFC 6376.
func canonicalizeBodyRelaxed(body []byte) []byte {
	s := string(body)

	// Reduce all sequences of WSP to a single SP
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		// Compress whitespace
		fields := strings.Fields(line)
		result = append(result, strings.Join(fields, " "))
	}

	// Remove trailing empty lines
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}

	canonical := strings.Join(result, "\r\n")
	if canonical != "" {
		canonical += "\r\n"
	}

	return []byte(canonical)
}

// canonicalizeHeadersRelaxed applies relaxed header canonicalization.
func canonicalizeHeadersRelaxed(headers string, signedHeaders []string) string {
	headerMap := parseHeaders(headers)
	var result []string

	for _, name := range signedHeaders {
		value, ok := headerMap[name]
		if !ok {
			continue
		}
		result = append(result, canonicalizeHeaderRelaxed(name+":"+value))
	}

	return strings.Join(result, "\r\n") + "\r\n"
}

// canonicalizeHeaderRelaxed canonicalizes a single header in relaxed mode.
func canonicalizeHeaderRelaxed(header string) string {
	colonIdx := strings.Index(header, ":")
	if colonIdx < 0 {
		return header
	}

	name := strings.ToLower(strings.TrimSpace(header[:colonIdx]))
	value := strings.TrimSpace(header[colonIdx+1:])

	// Compress whitespace in value
	fields := strings.Fields(value)
	value = strings.Join(fields, " ")

	return name + ":" + value
}

// parseHeaders parses raw headers into a name → value map.
func parseHeaders(raw string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(raw, "\n")

	var currentName, currentValue string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}

		// Check for header continuation (leading whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			currentValue += " " + strings.TrimSpace(line)
			continue
		}

		// Save previous header
		if currentName != "" {
			result[currentName] = currentValue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		currentName = strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		currentValue = strings.TrimSpace(line[colonIdx+1:])
	}

	if currentName != "" {
		result[currentName] = currentValue
	}

	return result
}

// foldBase64 folds a base64 string into lines of maxLen characters.
func foldBase64(s string, maxLen int) string {
	var result strings.Builder
	for i := 0; i < len(s); i += maxLen {
		end := i + maxLen
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			result.WriteString("\r\n\t")
		}
		result.WriteString(s[i:end])
	}
	return result.String()
}
