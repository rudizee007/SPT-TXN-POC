// Package trustregistry — file-backed persistent implementation.
//
// PersistentRegistry has the same in-memory map semantics as MockRegistry
// but survives process restarts by writing the full record set to a single
// JSON file on every mutation. It is pure Go — no SQLite, no CGo, no
// external dependencies — so it builds and runs unchanged under the
// OpenBSD pledge/unveil sandbox (where modernc.org/libc has known
// compatibility issues).
//
// Why this matters (security review M7 / Trust Registry persistence):
// trsvc previously used MockRegistry, which lives only for the process
// lifetime. On every restart the registry came up empty and seedIfEmpty
// re-seeded *revoked placeholder* records — silently invalidating every
// issuer that had been registered via regkey. Enforcement still failed
// closed (a good failure), but issuance broke until the operator re-ran
// register-issuers.sh. PersistentRegistry removes that footgun: once a
// real key is registered it is durable, and seedIfEmpty is a no-op on a
// non-empty store.
//
// Durability model: each mutation rewrites the whole file via a
// write-temp-then-rename sequence in the same directory, so a reader (or a
// crash) never observes a partially written file — the rename is atomic on
// POSIX filesystems. The file is created mode 0600 (owner-only); registry
// integrity is trust-critical even though the contents are public keys.
package trustregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistentRegistry is a file-backed Registry and Mutable implementation.
type PersistentRegistry struct {
	mu      sync.RWMutex
	records map[registryKey][]*Record
	path    string
}

// fileFormat is the on-disk JSON envelope. Versioned so the format can
// evolve without silently mis-parsing an older file.
type fileFormat struct {
	Version int       `json:"version"`
	Records []*Record `json:"records"`
}

const persistVersion = 1

// NewPersistentRegistry opens (or creates) a registry backed by the JSON
// file at path. If the file exists it is loaded; a missing file yields an
// empty registry (the caller may then seed it). Returns an error only if an
// existing file cannot be read or parsed — a corrupt store is surfaced, not
// silently discarded.
func NewPersistentRegistry(path string) (*PersistentRegistry, error) {
	if path == "" {
		return nil, fmt.Errorf("trustregistry: empty db path")
	}
	r := &PersistentRegistry{
		records: make(map[registryKey][]*Record),
		path:    path,
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// load reads the backing file into memory. A non-existent file is not an
// error (fresh deploy); any other read/parse failure is.
func (r *PersistentRegistry) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("trustregistry: read %s: %w", r.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	var ff fileFormat
	if err := json.Unmarshal(data, &ff); err != nil {
		return fmt.Errorf("trustregistry: parse %s: %w", r.path, err)
	}
	for _, rec := range ff.Records {
		if rec == nil {
			continue
		}
		key := registryKey{rec.Iss, rec.Role}
		r.records[key] = append(r.records[key], copyRecord(rec))
	}
	return nil
}

// save atomically rewrites the backing file. Callers MUST hold r.mu (write
// lock) so the snapshot is consistent with in-memory state.
func (r *PersistentRegistry) save() error {
	flat := make([]*Record, 0, len(r.records))
	for _, recs := range r.records {
		flat = append(flat, recs...)
	}
	data, err := json.MarshalIndent(fileFormat{Version: persistVersion, Records: flat}, "", "  ")
	if err != nil {
		return fmt.Errorf("trustregistry: marshal: %w", err)
	}

	dir := filepath.Dir(r.path)
	tmp, err := os.CreateTemp(dir, ".registry-*.tmp")
	if err != nil {
		return fmt.Errorf("trustregistry: temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	// os.CreateTemp already opens the file mode 0600 (owner-only) before
	// umask, so no explicit fchmod is needed — which keeps the trsvc pledge
	// set free of "fattr" (we only need stdio/rpath/wpath/cpath here).
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("trustregistry: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("trustregistry: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trustregistry: close temp: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		return fmt.Errorf("trustregistry: rename into place: %w", err)
	}
	return nil
}

// Register implements Mutable. The in-memory mutation and the disk write
// happen under a single held lock, so the file and memory never diverge on
// success; on a write failure the in-memory change is rolled back so the
// store stays consistent with what is durable.
func (r *PersistentRegistry) Register(_ context.Context, rec *Record) error {
	if err := validateRecord(rec); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	key := registryKey{rec.Iss, rec.Role}
	for _, existing := range r.records[key] {
		if existing.Status == StatusActive {
			return ErrConflict
		}
	}
	cp := copyRecord(rec)
	r.records[key] = append(r.records[key], cp)
	if err := r.save(); err != nil {
		// Roll back the append so memory matches disk.
		r.records[key] = r.records[key][:len(r.records[key])-1]
		return err
	}
	return nil
}

// Lookup implements Registry.
func (r *PersistentRegistry) Lookup(_ context.Context, iss string, role Role) (*Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := registryKey{iss, role}
	now := time.Now().UTC()
	var best *Record
	for _, rec := range r.records[key] {
		if rec.IsCurrentlyValid(now) {
			if best == nil || rec.ValidFrom.After(best.ValidFrom) {
				best = rec
			}
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return copyRecord(best), nil
}

// List implements Registry.
func (r *PersistentRegistry) List(_ context.Context, role Role) ([]*Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*Record
	for key, recs := range r.records {
		if role != "" && key.Role != role {
			continue
		}
		for _, rec := range recs {
			out = append(out, copyRecord(rec))
		}
	}
	return out, nil
}

// Revoke implements Mutable.
func (r *PersistentRegistry) Revoke(_ context.Context, iss string, role Role, at time.Time) error {
	return r.setStatus(iss, role, StatusRevoked, at)
}

// Supersede implements Mutable.
func (r *PersistentRegistry) Supersede(_ context.Context, iss string, role Role, at time.Time) error {
	return r.setStatus(iss, role, StatusSuperseded, at)
}

func (r *PersistentRegistry) setStatus(iss string, role Role, status RecordStatus, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := registryKey{iss, role}
	for _, rec := range r.records[key] {
		if rec.Status == StatusActive {
			prev := rec.Status
			rec.Status = status
			if err := r.save(); err != nil {
				rec.Status = prev // roll back
				return err
			}
			return nil
		}
	}
	return ErrNotFound
}

// Close implements Registry. The store is durable after every mutation, so
// Close has nothing to flush; defined for interface completeness.
func (r *PersistentRegistry) Close() error { return nil }
