// Package compliance implements FBL ingestion, List-Unsubscribe, and DMARC awareness.
package compliance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/srmta/srmta/internal/logging"
)

// FeedbackLoop handles FBL (Feedback Loop) complaint ingestion.
type FeedbackLoop struct {
	logger  *logging.Logger
	handler func(complaint *Complaint)
}

// Complaint represents an FBL complaint.
type Complaint struct {
	MessageID    string    `json:"message_id"`
	Sender       string    `json:"sender"`
	Recipient    string    `json:"recipient"`
	FeedbackID   string    `json:"feedback_id"`
	FeedbackType string    `json:"feedback_type"` // abuse, fraud, not-spam
	Source       string    `json:"source"`        // ISP/provider name
	ReceivedAt   time.Time `json:"received_at"`
	RawARF       string    `json:"raw_arf,omitempty"` // Raw ARF report
}

// NewFeedbackLoop creates a new FBL ingestion handler.
func NewFeedbackLoop(logger *logging.Logger, handler func(*Complaint)) *FeedbackLoop {
	return &FeedbackLoop{
		logger:  logger,
		handler: handler,
	}
}

// WebhookHandler returns an HTTP handler for complaint webhook ingestion.
func (f *FeedbackLoop) WebhookHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var complaint Complaint
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		if err := json.NewDecoder(r.Body).Decode(&complaint); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		complaint.ReceivedAt = time.Now()

		f.logger.Info("Complaint received",
			"message_id", complaint.MessageID,
			"sender", complaint.Sender,
			"recipient", complaint.Recipient,
			"type", complaint.FeedbackType,
			"source", complaint.Source,
		)

		if f.handler != nil {
			f.handler(&complaint)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "received"})
	}
}

// Unsubscribe handles List-Unsubscribe header generation per RFC 2369 and RFC 8058.
type Unsubscribe struct {
	BaseURL string
	Secret  string
}

// NewUnsubscribe creates an Unsubscribe header generator.
func NewUnsubscribe(baseURL, secret string) *Unsubscribe {
	return &Unsubscribe{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Secret:  secret,
	}
}

// GenerateHeaders returns the List-Unsubscribe and List-Unsubscribe-Post headers.
// Compliant with RFC 2369 (mailto + https) and RFC 8058 (one-click).
func (u *Unsubscribe) GenerateHeaders(messageID, recipient string) map[string]string {
	// Generate unique unsubscribe URL with properly encoded parameters
	unsub := fmt.Sprintf("%s/unsubscribe?id=%s&email=%s",
		u.BaseURL, url.QueryEscape(messageID), url.QueryEscape(recipient))

	return map[string]string{
		"List-Unsubscribe":      fmt.Sprintf("<%s>, <mailto:unsubscribe@%s?subject=unsubscribe>", unsub, extractDomainFromURL(u.BaseURL)),
		"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
	}
}

// DMARCChecker provides DMARC alignment checking.
type DMARCChecker struct {
	logger *logging.Logger
}

// NewDMARCChecker creates a new DMARC alignment checker.
func NewDMARCChecker(logger *logging.Logger) *DMARCChecker {
	return &DMARCChecker{logger: logger}
}

// DMARCResult represents the result of a DMARC alignment check.
type DMARCResult struct {
	Aligned    bool   `json:"aligned"`
	SPFResult  string `json:"spf_result"`
	DKIMResult string `json:"dkim_result"`
	Policy     string `json:"policy"` // none, quarantine, reject
	FromDomain string `json:"from_domain"`
}

// CheckAlignment verifies DMARC alignment between From domain and SPF/DKIM domains.
func (d *DMARCChecker) CheckAlignment(fromDomain, spfDomain, dkimDomain string) *DMARCResult {
	fromDomain = strings.ToLower(fromDomain)
	spfDomain = strings.ToLower(spfDomain)
	dkimDomain = strings.ToLower(dkimDomain)

	result := &DMARCResult{
		FromDomain: fromDomain,
	}

	// SPF alignment (relaxed — organizational domain match)
	if spfDomain != "" {
		if spfDomain == fromDomain || isSubdomain(spfDomain, fromDomain) || isSubdomain(fromDomain, spfDomain) {
			result.SPFResult = "pass"
		} else {
			result.SPFResult = "fail"
		}
	}

	// DKIM alignment (relaxed)
	if dkimDomain != "" {
		if dkimDomain == fromDomain || isSubdomain(dkimDomain, fromDomain) || isSubdomain(fromDomain, dkimDomain) {
			result.DKIMResult = "pass"
		} else {
			result.DKIMResult = "fail"
		}
	}

	// DMARC passes if either SPF or DKIM aligns
	result.Aligned = result.SPFResult == "pass" || result.DKIMResult == "pass"

	return result
}

// isSubdomain checks if child is a subdomain of parent.
func isSubdomain(child, parent string) bool {
	return strings.HasSuffix(child, "."+parent)
}

// extractDomainFromURL extracts the domain from a URL.
func extractDomainFromURL(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.SplitN(url, "/", 2)
	return parts[0]
}
