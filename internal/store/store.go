// Package store manages local tamper-evident SHA-256 hash-chained scan run history.
package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luminariadev/raksa/internal/schema"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// RunRecord stores a single summarized scan execution linked into an append-only hash chain.
type RunRecord struct {
	Seq           int                 `json:"seq"`
	Timestamp     string              `json:"timestamp"`
	Profile       string              `json:"profile"`
	Target        string              `json:"target"`
	Posture       schema.PostureScore `json:"posture"`
	Summary       schema.Summary      `json:"summary"`
	ActiveLayers  []string            `json:"active_layers"`
	MissingLayers []string            `json:"missing_layers,omitempty"`
	PrevHash      string              `json:"prev_hash"`
	EntryHash     string              `json:"entry_hash"`
}

// Store wraps a local hash-chained NDJSON history ledger (runs.ndjson).
type Store struct {
	path string
}

// Open returns a Store backed by path (created lazily on first Append).
func Open(path string) *Store {
	return &Store{path: path}
}

// DefaultHistoryPath resolves ~/.raksa/runs.ndjson or ./.raksa/runs.ndjson fallback.
func DefaultHistoryPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".raksa", "runs.ndjson")
	}
	return filepath.Join(home, ".raksa", "runs.ndjson")
}

// Append appends a new SuiteReport summary into the SHA-256 hash chain.
func (s *Store) Append(rep schema.SuiteReport) (RunRecord, error) {
	records, err := s.readAll()
	if err != nil {
		return RunRecord{}, err
	}
	prev := genesisHash
	seq := 1
	if len(records) > 0 {
		last := records[len(records)-1]
		prev = last.EntryHash
		seq = last.Seq + 1
	}

	active := make([]string, 0, len(rep.Layers))
	missing := make([]string, 0)
	for _, l := range rep.Layers {
		if l.Status == "not_installed" {
			missing = append(missing, l.Layer)
		} else {
			active = append(active, l.Layer)
		}
	}

	rec := RunRecord{
		Seq:           seq,
		Timestamp:     rep.GeneratedAt,
		Profile:       rep.Profile,
		Target:        rep.Target,
		Posture:       rep.Posture,
		Summary:       rep.Summary,
		ActiveLayers:  active,
		MissingLayers: missing,
		PrevHash:      prev,
	}
	rec.EntryHash = computeEntryHash(rec)

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return RunRecord{}, fmt.Errorf("create history directory: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return RunRecord{}, fmt.Errorf("open history file: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(rec)
	if err != nil {
		return RunRecord{}, fmt.Errorf("encode run record: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return RunRecord{}, fmt.Errorf("write run record: %w", err)
	}
	return rec, nil
}

// List returns up to limit most recent records (newest first).
func (s *Store) List(limit int) ([]RunRecord, error) {
	records, err := s.readAll()
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(records) > limit {
		records = records[len(records)-limit:]
	}
	out := make([]RunRecord, len(records))
	for i := range records {
		out[i] = records[len(records)-1-i]
	}
	return out, nil
}

// VerifyChain validates sequential linkage and SHA-256 integrity across every entry.
func (s *Store) VerifyChain() (count int, ok bool, reason string, err error) {
	records, err := s.readAll()
	if err != nil {
		return 0, false, "", err
	}
	if len(records) == 0 {
		return 0, true, "empty ledger", nil
	}
	expectedPrev := genesisHash
	for idx, rec := range records {
		if rec.Seq != idx+1 {
			return len(records), false, fmt.Sprintf("sequence mismatch at index %d: got %d", idx, rec.Seq), nil
		}
		if rec.PrevHash != expectedPrev {
			return len(records), false, fmt.Sprintf("broken prev_hash at seq %d", rec.Seq), nil
		}
		expectedHash := computeEntryHash(rec)
		if rec.EntryHash != expectedHash {
			return len(records), false, fmt.Sprintf("entry_hash mismatch at seq %d", rec.Seq), nil
		}
		expectedPrev = rec.EntryHash
	}
	return len(records), true, "verified", nil
}

func (s *Store) readAll() ([]RunRecord, error) {
	raw, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open history %s: %w", s.path, err)
	}
	defer raw.Close()

	var out []RunRecord
	scanner := bufio.NewScanner(raw)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec RunRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parse history line %d: %w", lineNo, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan history %s: %w", s.path, err)
	}
	return out, nil
}

func computeEntryHash(r RunRecord) string {
	copyRec := r
	copyRec.EntryHash = ""
	payload, _ := json.Marshal(copyRec)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
