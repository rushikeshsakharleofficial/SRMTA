// srmtaq — mailq-equivalent CLI for SRMTA
//
// Usage:
//
//	srmtaq                          # show queue summary (default)
//	srmtaq list                     # list all queued messages
//	srmtaq list -spool deferred     # list specific spool
//	srmtaq stat                     # detailed stats from metrics endpoint
//	srmtaq logs                     # tail the last N lines from each log file
//
// Flags:
//
//	-api   string   metrics/health API base URL (default: http://localhost:9090)
//	-spool string   spool directory (default: /tmp/srmta-spool)
//	-n     int      number of log lines to show (default: 20)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"

	// spoolDeadLetter is the canonical name for the dead-letter spool.
	spoolDeadLetter = "dead-letter"

	// fmtStatColor is the printf format for a colored stat line (label, color, value, reset).
	fmtStatColor = "    %-20s %s%d%s\n"

	// fmtStatPlain is the printf format for a plain (uncolored) stat line (label, value).
	fmtStatPlain = "    %-20s %d\n"
)

// Message mirrors queue.Message fields we care about.
type Message struct {
	ID         string    `json:"id"`
	Sender     string    `json:"sender"`
	Recipients []string  `json:"recipients"`
	Domain     string    `json:"domain"`
	Size       int64     `json:"size"`
	Priority   int       `json:"priority"`
	Spool      string    `json:"spool"`
	RetryCount int       `json:"retry_count"`
	NextRetry  time.Time `json:"next_retry"`
	CreatedAt  time.Time `json:"created_at"`
	LastError  string    `json:"last_error,omitempty"`
}

// HealthFull mirrors the /health/full response.
type HealthFull struct {
	Service    string `json:"service"`
	Status     string `json:"status"`
	Subsystems struct {
		Queue struct {
			Enqueued   int `json:"enqueued"`
			Completed  int `json:"completed"`
			Deferred   int `json:"deferred"`
			Failed     int `json:"failed"`
			DeadLetter int `json:"dead_letter"`
		} `json:"queue"`
		SMTP struct {
			TotalConnections  int `json:"total_connections"`
			ActiveConnections int `json:"active_connections"`
			Rejected          int `json:"rejected"`
		} `json:"smtp"`
		Delivery struct {
			Delivered    int   `json:"delivered"`
			AvgLatencyMs int64 `json:"avg_latency_ms"`
		} `json:"delivery"`
		Auth struct {
			Successes int `json:"successes"`
			Failures  int `json:"failures"`
		} `json:"auth"`
		TLS struct {
			Connections     int `json:"connections"`
			HandshakeErrors int `json:"handshake_errors"`
		} `json:"tls"`
	} `json:"subsystems"`
}

var (
	apiFlag   = flag.String("api", "http://localhost:9090", "SRMTA metrics API base URL")
	spoolFlag = flag.String("spool", "/tmp/srmta-spool", "SRMTA spool directory")
	nFlag     = flag.Int("n", 20, "number of log lines to show (for logs command)")
)

var spoolColors = map[string]string{
	"incoming":      colorCyan,
	"active":        colorGreen,
	"deferred":      colorYellow,
	"retry":         colorYellow,
	spoolDeadLetter: colorRed,
	"failed":        colorRed,
}

func main() {
	flag.Usage = usage
	flag.Parse()

	cmd := "summary"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}

	switch cmd {
	case "summary", "q":
		runSummary()
	case "list", "ls":
		spoolFilter := ""
		if flag.NArg() > 1 {
			spoolFilter = flag.Arg(1)
		}
		runList(spoolFilter)
	case "stat", "stats":
		runStat()
	case "logs":
		runLogs()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

// ── Summary (default) ───────────────────────────────────────────────────────

func runSummary() {
	h := fetchHealth()

	q := h.Subsystems.Queue
	total := q.Enqueued - q.Completed - q.Failed

	fmt.Printf("\n%s%s SRMTA Queue Summary%s  %s%s%s\n",
		colorBold, colorCyan, colorReset,
		colorGray, time.Now().Format("2006-01-02 15:04:05"), colorReset)
	fmt.Printf("%s%s%s\n\n", colorGray, strings.Repeat("─", 50), colorReset)

	statusColor := colorGreen
	if h.Status != "healthy" {
		statusColor = colorRed
	}
	fmt.Printf("  Service:  %s%s%s\n", statusColor, h.Status, colorReset)
	fmt.Printf("  In Queue: %s%d%s messages pending\n\n", colorBold, total, colorReset)

	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "  SPOOL\tCOUNT\tDESCRIPTION")
	fmt.Fprintln(tw, "  ─────\t─────\t───────────")

	spools := []struct {
		name  string
		count int
		desc  string
	}{
		{"incoming", countSpool("incoming") + q.Enqueued - q.Completed, "accepted, awaiting processing"},
		{"deferred", countSpool("deferred"), "temporary failure, will retry"},
		{"retry", countSpool("retry"), "queued for next retry attempt"},
		{spoolDeadLetter, countSpool(spoolDeadLetter), "exhausted retries"},
		{"failed", countSpool("failed"), "permanent failure"},
	}

	for _, s := range spools {
		c := countSpool(s.name)
		countStr := fmt.Sprintf("%d", c)
		col := colorGray
		if c > 0 {
			col = spoolColors[s.name]
		}
		fmt.Fprintf(tw, "  %s%s%s\t%s%s%s\t%s\n",
			col, s.name, colorReset,
			col, countStr, colorReset,
			s.desc)
	}

	fmt.Fprintf(tw, "\n  %sCompleted%s\t%s%d%s\tsuccessfully delivered\n",
		colorGreen, colorReset, colorGreen, q.Completed, colorReset)
	tw.Flush()

	fmt.Printf("\n%sTip:%s use %ssrmtaq list%s to see individual messages\n\n",
		colorGray, colorReset, colorCyan, colorReset)
}

// ── List messages ───────────────────────────────────────────────────────────

func runList(spoolFilter string) {
	spools := []string{"incoming", "active", "deferred", "retry", spoolDeadLetter, "failed"}
	if spoolFilter != "" {
		spools = []string{spoolFilter}
	}

	fmt.Printf("\n%s%sSRMTA Queue Listing%s  %s%s%s\n",
		colorBold, colorCyan, colorReset,
		colorGray, time.Now().Format("2006-01-02 15:04:05"), colorReset)

	totalShown := 0
	for _, spool := range spools {
		totalShown += printSpoolSection(spool)
	}

	if totalShown == 0 {
		fmt.Printf("\n  %sQueue is empty%s\n\n", colorGreen, colorReset)
	} else {
		fmt.Printf("\n  Total: %s%d messages%s\n\n", colorBold, totalShown, colorReset)
	}
}

// printSpoolSection prints one spool's messages and returns the count shown.
func printSpoolSection(spool string) int {
	messages := readSpool(spool)
	if len(messages) == 0 {
		return 0
	}

	col := spoolColors[spool]
	if col == "" {
		col = colorCyan
	}
	fmt.Printf("\n%s%s── %s (%d)%s\n", colorBold, col, strings.ToUpper(spool), len(messages), colorReset)

	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tSIZE\tFROM\tTO\tAGE\tRETRIES\tNEXT RETRY")
	fmt.Fprintln(tw, "  ──\t────\t────\t──\t───\t───────\t──────────")

	for _, msg := range messages {
		printMessageRow(tw, msg)
	}

	tw.Flush()
	return len(messages)
}

// printMessageRow writes a single message row (and optional error line) to tw.
func printMessageRow(tw *tabwriter.Writer, msg Message) {
	to := formatRecipients(msg.Recipients)
	ageStr := formatAge(time.Since(msg.CreatedAt).Round(time.Second))
	nextRetry := formatNextRetry(msg)

	fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%d\t%s\n",
		msg.ID, formatSize(msg.Size), truncate(msg.Sender, 28), truncate(to, 28),
		ageStr, msg.RetryCount, nextRetry)

	if msg.LastError != "" {
		fmt.Fprintf(tw, "  %s↳ %s%s\n", colorRed, truncate(msg.LastError, 60), colorReset)
	}
}

// formatRecipients returns the primary recipient string with overflow count.
func formatRecipients(rcpts []string) string {
	if len(rcpts) == 0 {
		return ""
	}
	to := rcpts[0]
	if len(rcpts) > 1 {
		to += fmt.Sprintf(" +%d", len(rcpts)-1)
	}
	return to
}

// formatNextRetry returns the human-readable next-retry string for a message.
func formatNextRetry(msg Message) string {
	if msg.NextRetry.IsZero() || msg.RetryCount == 0 {
		return "-"
	}
	untilRetry := time.Until(msg.NextRetry).Round(time.Second)
	if untilRetry > 0 {
		return "in " + formatAge(untilRetry)
	}
	return colorGreen + "now" + colorReset
}

// ── Detailed Stats ──────────────────────────────────────────────────────────

func runStat() {
	h := fetchHealth()
	q := h.Subsystems.Queue
	s := h.Subsystems.SMTP
	d := h.Subsystems.Delivery
	a := h.Subsystems.Auth
	tls := h.Subsystems.TLS

	fmt.Printf("\n%s%sSRMTA Detailed Stats%s\n%s%s\n\n",
		colorBold, colorCyan, colorReset,
		colorGray, strings.Repeat("─", 50)+colorReset)

	fmt.Printf("%s  Queue%s\n", colorBold, colorReset)
	fmt.Printf(fmtStatColor, "Enqueued total:", colorCyan, q.Enqueued, colorReset)
	fmt.Printf(fmtStatColor, "Completed:", colorGreen, q.Completed, colorReset)
	fmt.Printf(fmtStatColor, "Deferred:", colorYellow, q.Deferred, colorReset)
	fmt.Printf(fmtStatColor, "Failed:", colorRed, q.Failed, colorReset)
	fmt.Printf(fmtStatColor, "Dead letter:", colorRed, q.DeadLetter, colorReset)

	fmt.Printf("\n%s  SMTP Connections%s\n", colorBold, colorReset)
	fmt.Printf(fmtStatPlain, "Total:", s.TotalConnections)
	fmt.Printf(fmtStatPlain, "Active now:", s.ActiveConnections)
	fmt.Printf(fmtStatColor, "Rejected:", colorYellow, s.Rejected, colorReset)

	fmt.Printf("\n%s  Delivery%s\n", colorBold, colorReset)
	fmt.Printf(fmtStatPlain, "Delivered:", d.Delivered)
	fmt.Printf("    %-20s %dms\n", "Avg latency:", d.AvgLatencyMs)

	fmt.Printf("\n%s  Auth%s\n", colorBold, colorReset)
	fmt.Printf(fmtStatColor, "Successes:", colorGreen, a.Successes, colorReset)
	fmt.Printf(fmtStatColor, "Failures:", colorRed, a.Failures, colorReset)

	fmt.Printf("\n%s  TLS%s\n", colorBold, colorReset)
	fmt.Printf(fmtStatPlain, "Connections:", tls.Connections)
	fmt.Printf(fmtStatColor, "Handshake errors:", colorRed, tls.HandshakeErrors, colorReset)

	fmt.Printf("\n%s  Spool Files on Disk%s\n", colorBold, colorReset)
	for _, sp := range []string{"incoming", "active", "deferred", "retry", spoolDeadLetter, "failed"} {
		n := countSpool(sp)
		col := colorGray
		if n > 0 {
			col = spoolColors[sp]
		}
		fmt.Printf(fmtStatColor, sp+":", col, n, colorReset)
	}

	fmt.Println()
}

// ── Logs tail ───────────────────────────────────────────────────────────────

func runLogs() {
	logFiles := map[string]string{
		"Error":       "/tmp/srmta-logs/error.log",
		"Access":      "/tmp/srmta-logs/access.log",
		"Transaction": "/tmp/srmta-logs/transaction.csv",
	}

	for name, path := range logFiles {
		lines := tailFile(path, *nFlag)
		col := colorCyan
		if name == "Error" {
			col = colorRed
		}
		fmt.Printf("\n%s%s── %s Log (%s)%s\n", colorBold, col, name, path, colorReset)
		if len(lines) == 0 {
			fmt.Printf("  %s(empty)%s\n", colorGray, colorReset)
			continue
		}
		for _, l := range lines {
			fmt.Println(" ", l)
		}
	}
	fmt.Println()
}

// ── Helpers ────────────────────────────────────────────────────────────────

func fetchHealth() *HealthFull {
	resp, err := http.Get(*apiFlag + "/health/full")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError: cannot reach SRMTA at %s: %v%s\n",
			colorRed, *apiFlag, err, colorReset)
		fmt.Fprintf(os.Stderr, "Is SRMTA running? Try: /tmp/srmta -config /tmp/srmta-local.yaml\n")
		os.Exit(1)
	}
	defer resp.Body.Close()

	var h HealthFull
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing health response: %v\n", err)
		os.Exit(1)
	}
	return &h
}

func countSpool(spool string) int {
	dir := filepath.Join(*spoolFlag, spool)
	shards, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, s := range shards {
		if !s.IsDir() {
			continue
		}
		shardDir := filepath.Join(dir, s.Name())
		entries, _ := os.ReadDir(shardDir)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".meta") {
				count++
			}
		}
	}
	return count
}

func readSpool(spool string) []Message {
	dir := filepath.Join(*spoolFlag, spool)
	shards, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var messages []Message
	for _, s := range shards {
		if !s.IsDir() {
			continue
		}
		messages = append(messages, readShardMessages(filepath.Join(dir, s.Name()))...)
	}

	sort.Slice(messages, func(i, j int) bool {
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})
	return messages
}

// readShardMessages reads all message metadata files from a single shard directory.
func readShardMessages(shardDir string) []Message {
	entries, _ := os.ReadDir(shardDir)
	var messages []Message
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(shardDir, e.Name()))
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		messages = append(messages, msg)
	}
	return messages
}

func tailFile(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
	}
}

func formatSize(bytes int64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%dB", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%dK", bytes/1024)
	default:
		return fmt.Sprintf("%dM", bytes/(1024*1024))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func usage() {
	fmt.Printf(`%ssrmtaq%s — SRMTA queue inspection tool

%sUsage:%s
  srmtaq [flags] [command]

%sCommands:%s
  (default)   queue summary with counts per spool
  list        list all messages in the queue
  list <spool> list messages in a specific spool
              spools: incoming, active, deferred, retry, dead-letter, failed
  stat        detailed statistics (connections, delivery, auth, TLS)
  logs        tail the last N lines from error/access/transaction logs

%sFlags:%s
  -api   string  metrics API URL (default: http://localhost:9090)
  -spool string  spool directory (default: /tmp/srmta-spool)
  -n     int     log lines to show (default: 20)

%sExamples:%s
  srmtaq                      # queue summary
  srmtaq list                 # all messages
  srmtaq list deferred        # deferred messages only
  srmtaq stat                 # full stats
  srmtaq logs                 # tail all logs
  srmtaq -n 50 logs           # tail last 50 lines

`, colorBold, colorReset, colorBold, colorReset, colorBold, colorReset,
		colorBold, colorReset, colorBold, colorReset)
}
