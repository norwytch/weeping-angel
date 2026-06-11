// Package main implements the out-of-band recorder: a host collector that
// watches file operations, computes a forward hash chain, and appends to the
// same append-only JSONL ledger the Python detector reads.
//
// The hash chain matches weeping_angel/ledger.py byte for byte. The preimage is a
// compact, key-sorted JSON object {event, index, prev_hash, recorded_at}; Go's
// encoder sorts map keys and (with HTML escaping disabled) emits the identical
// bytes as Python's json.dumps(sort_keys=True, separators=(",",":"),
// ensure_ascii=False). This holds only for integer/string values -- floats
// serialize differently across the two languages -- so the shared ledger uses
// integer (nanosecond) timestamps and string event fields.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one chained observation. The struct tag order is only the on-disk
// order; the hash is computed over a canonical key-sorted preimage, so storage
// order does not affect verification.
type Record struct {
	Index      int64          `json:"index"`
	RecordedAt int64          `json:"recorded_at"`
	Event      map[string]any `json:"event"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// canonical returns compact, key-sorted JSON with HTML escaping disabled, to
// match Python's canonical serialization exactly.
func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func digest(index, recordedAt int64, event map[string]any, prevHash string) (string, error) {
	pre, err := canonical(map[string]any{
		"event":       event,
		"index":       index,
		"prev_hash":   prevHash,
		"recorded_at": recordedAt,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:]), nil
}

// Ledger is an in-memory append-only hash chain.
type Ledger struct {
	records []Record
}

func (l *Ledger) headHash() string {
	if len(l.records) == 0 {
		return genesisHash
	}
	return l.records[len(l.records)-1].Hash
}

// Append commits a new observation and returns it.
func (l *Ledger) Append(recordedAt int64, event map[string]any) (Record, error) {
	index := int64(len(l.records))
	prev := l.headHash()
	h, err := digest(index, recordedAt, event, prev)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Index: index, RecordedAt: recordedAt, Event: event, PrevHash: prev, Hash: h}
	l.records = append(l.records, rec)
	return rec, nil
}

// Dump writes the ledger as JSONL, one canonical record per line. Keys are
// sorted so the output is byte-identical to the Python writer's.
func (l *Ledger) Dump(path string) error {
	// Create owner-only (0600): the integrity artifact should not be
	// world-readable or world-writable. Mirrors weeping_angel/ledger.py's dump.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	for _, r := range l.records {
		line, err := canonical(map[string]any{
			"index":       r.Index,
			"recorded_at": r.RecordedAt,
			"event":       r.Event,
			"prev_hash":   r.PrevHash,
			"hash":        r.Hash,
		})
		if err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return nil
}

// Load reads a JSONL ledger, preserving stored hashes so Verify can re-derive
// and check them.
func Load(path string) (*Ledger, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l := &Ledger{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		l.records = append(l.records, r)
	}
	return l, sc.Err()
}

// Verify recomputes every hash and checks index continuity and chain links.
func (l *Ledger) Verify() (bool, []string) {
	var problems []string
	expectedPrev := genesisHash
	for i, r := range l.records {
		if r.Index != int64(i) {
			problems = append(problems,
				fmt.Sprintf("index discontinuity at position %d: record claims index %d", i, r.Index))
		}
		h, err := digest(r.Index, r.RecordedAt, r.Event, r.PrevHash)
		if err != nil {
			problems = append(problems, fmt.Sprintf("record %d: %v", r.Index, err))
			continue
		}
		if h != r.Hash {
			problems = append(problems,
				fmt.Sprintf("record %d: stored hash does not match contents (payload edited)", r.Index))
		}
		if r.PrevHash != expectedPrev {
			problems = append(problems, fmt.Sprintf("record %d: broken chain link", r.Index))
		}
		expectedPrev = r.Hash
	}
	return len(problems) == 0, problems
}
