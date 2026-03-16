// journal.go implements a write-ahead journal for crash-safe queue recovery.
// The journal records all queue state transitions so that on restart,
// the queue manager can replay the journal to reconstruct consistent state.
package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// JournalEntry represents a single journal record.
type JournalEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // enqueue, move:active, move:deferred, complete, fail
	MessageID string    `json:"message_id"`
	Spool     string    `json:"spool"`
	Domain    string    `json:"domain"`
}

var (
	journalMu   sync.Mutex
	journalFile *os.File
)

// WriteJournalEntry appends a journal entry to the crash-recovery log.
// Uses append-only file writes with fsync for durability.
func WriteJournalEntry(spoolDir string, entry JournalEntry) error {
	journalMu.Lock()
	defer journalMu.Unlock()

	// Open or create journal file
	if journalFile == nil {
		journalPath := filepath.Join(spoolDir, "journal.log")
		f, err := os.OpenFile(journalPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("failed to open journal: %w", err)
		}
		journalFile = f
	}

	// Serialize entry as JSON line
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal journal entry: %w", err)
	}

	// Write with newline delimiter
	if _, err := journalFile.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write journal entry: %w", err)
	}

	// fsync for crash durability
	if err := journalFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync journal: %w", err)
	}

	return nil
}

// ReadJournal reads all journal entries from the crash-recovery log.
func ReadJournal(spoolDir string) ([]JournalEntry, error) {
	journalPath := filepath.Join(spoolDir, "journal.log")

	data, err := os.ReadFile(journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No journal file, clean start
		}
		return nil, fmt.Errorf("failed to read journal: %w", err)
	}

	var entries []JournalEntry
	// Split by newlines and parse each line
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var entry JournalEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Skip corrupt entries, log warning
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// RotateJournal creates a new journal file, archiving the old one.
func RotateJournal(spoolDir string) error {
	journalMu.Lock()
	defer journalMu.Unlock()

	if journalFile != nil {
		journalFile.Close()
		journalFile = nil
	}

	journalPath := filepath.Join(spoolDir, "journal.log")
	archivePath := filepath.Join(spoolDir, fmt.Sprintf("journal.%s.log", time.Now().Format("20060102-150405")))

	if err := os.Rename(journalPath, archivePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to rotate journal: %w", err)
	}

	return nil
}

// CloseJournal closes the journal file handle.
func CloseJournal() {
	journalMu.Lock()
	defer journalMu.Unlock()

	if journalFile != nil {
		journalFile.Close()
		journalFile = nil
	}
}

// splitLines splits byte slice by newline characters.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
