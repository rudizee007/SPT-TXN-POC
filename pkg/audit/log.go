// Package audit implements the SPT-Txn append-only audit log with periodic
// signed Merkle-root publication — Milestone 6.
//
// Every significant event (token issued, verification decision) is appended as
// an Entry. Each entry carries the hash of the previous one, forming a hash
// chain: any modification, reordering, or deletion of a past entry breaks the
// chain and is detected on reload. Periodically each domain publishes a
// Merkle root over its entries, signed with its audit key (merkle.go), so an
// external auditor can confirm the log has not been altered without holding the
// whole log.
//
// File format is one JSON object per line (JSONL), opened append-only. Standard
// library only.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// genesis is the conventional PrevHash of the first entry, so the chain has a
// fixed, domain-separated anchor rather than an empty value.
func genesis() []byte {
	h := sha256.Sum256([]byte("spt-txn-audit-genesis-v1"))
	return h[:]
}

// Entry is a single audit record. Hash is computed over all other fields plus
// PrevHash, chaining entries together.
type Entry struct {
	Seq      uint64
	Time     int64
	Type     string            // e.g. "cat_issued", "txn_issued", "verify_decision"
	Subject  string            // the entity the event concerns (jti, holder, etc.)
	Detail   map[string]string // free-form, deterministically hashed
	PrevHash []byte
	Hash     []byte
}

// computeHash derives the entry hash deterministically (independent of JSON
// key ordering) from every field except Hash itself.
func (e *Entry) computeHash() []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%d\n%s\n%s\n", e.Seq, e.Time, e.Type, e.Subject)
	keys := make([]string, 0, len(e.Detail))
	for k := range e.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, e.Detail[k])
	}
	h.Write(e.PrevHash)
	return h.Sum(nil)
}

// Log is an append-only, hash-chained audit log backed by a JSONL file.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	entries  []Entry
	lastHash []byte
	nextSeq  uint64
}

type record struct {
	Seq      uint64            `json:"seq"`
	Time     int64             `json:"time"`
	Type     string            `json:"type"`
	Subject  string            `json:"subject"`
	Detail   map[string]string `json:"detail,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Open opens (or creates) an audit log at path. If the file exists, its entries
// are loaded and the hash chain is verified; a broken chain returns an error.
func Open(path string) (*Log, error) {
	l := &Log{path: path, lastHash: genesis(), nextSeq: 1}

	if data, err := os.ReadFile(path); err == nil {
		if err := l.load(data); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) load(data []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := genesis()
	var seq uint64 = 1
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("audit: parse entry %d: %w", seq, err)
		}
		e, err := r.toEntry()
		if err != nil {
			return err
		}
		if e.Seq != seq {
			return fmt.Errorf("audit: entry out of sequence: got %d want %d", e.Seq, seq)
		}
		if !equal(e.PrevHash, prev) {
			return fmt.Errorf("audit: chain broken at entry %d (prev_hash mismatch)", seq)
		}
		if !equal(e.Hash, e.computeHash()) {
			return fmt.Errorf("audit: entry %d hash does not match contents (tampered)", seq)
		}
		l.entries = append(l.entries, *e)
		prev = e.Hash
		seq++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	l.lastHash = prev
	l.nextSeq = seq
	return nil
}

// sensitiveDetailKeys are Detail keys that would leak PII into the audit log.
// Callers MUST pass commitments, hashes, or opaque IDs instead of raw values;
// Append rejects any of these keys to keep the published log PII-free (AUD-2).
var sensitiveDetailKeys = map[string]bool{
	"amount":  true,
	"name":    true,
	"account": true,
	"pan":     true,
	"iban":    true,
	"dob":     true,
}

// ErrPIIInAuditDetail is returned by Append when a Detail key is on the
// known-sensitive list. The audit log must carry only opaque references.
var ErrPIIInAuditDetail = fmt.Errorf("audit: detail contains a PII key; pass a commitment/hash/opaque id instead")

// checkNoPII rejects detail maps that carry a known-sensitive (PII) key.
func checkNoPII(detail map[string]string) error {
	for k := range detail {
		if sensitiveDetailKeys[strings.ToLower(k)] {
			return fmt.Errorf("%w (key %q)", ErrPIIInAuditDetail, k)
		}
	}
	return nil
}

// Append adds an event to the log and flushes it to disk. It returns the new
// entry. Subject and Detail values must be opaque (commitments/hashes/IDs), not
// PII; Append rejects Detail maps carrying a known-sensitive key (AUD-2).
// Concurrent-safe.
func (l *Log) Append(eventType, subject string, detail map[string]string) (Entry, error) {
	if err := checkNoPII(detail); err != nil {
		return Entry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Seq:      l.nextSeq,
		Time:     time.Now().UTC().Unix(),
		Type:     eventType,
		Subject:  subject,
		Detail:   detail,
		PrevHash: l.lastHash,
	}
	e.Hash = e.computeHash()

	line, err := json.Marshal(e.toRecord())
	if err != nil {
		return Entry{}, err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, err
	}

	l.entries = append(l.entries, e)
	l.lastHash = e.Hash
	l.nextSeq++
	return e, nil
}

// Entries returns a copy of all entries in order.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Verify re-checks the in-memory hash chain end to end.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := genesis()
	for i, e := range l.entries {
		if !equal(e.PrevHash, prev) {
			return fmt.Errorf("audit: chain broken at entry %d", i+1)
		}
		if !equal(e.Hash, e.computeHash()) {
			return fmt.Errorf("audit: entry %d tampered", i+1)
		}
		prev = e.Hash
	}
	return nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// ── record conversion ────────────────────────────────────────────────────────

func (e Entry) toRecord() record {
	return record{
		Seq: e.Seq, Time: e.Time, Type: e.Type, Subject: e.Subject, Detail: e.Detail,
		PrevHash: hex.EncodeToString(e.PrevHash),
		Hash:     hex.EncodeToString(e.Hash),
	}
}

func (r record) toEntry() (*Entry, error) {
	ph, err := hex.DecodeString(r.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("audit: bad prev_hash: %w", err)
	}
	hh, err := hex.DecodeString(r.Hash)
	if err != nil {
		return nil, fmt.Errorf("audit: bad hash: %w", err)
	}
	return &Entry{
		Seq: r.Seq, Time: r.Time, Type: r.Type, Subject: r.Subject, Detail: r.Detail,
		PrevHash: ph, Hash: hh,
	}, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
