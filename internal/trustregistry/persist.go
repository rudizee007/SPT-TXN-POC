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
	"sort"

	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
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
	return r.loadFrom(data)
}

// loadFrom parses an in-memory snapshot body. It exists so that a caller which
// has already AUTHENTICATED some bytes can load exactly those bytes, rather than
// naming a path and hoping the filesystem returns the same content twice.
func (r *PersistentRegistry) loadFrom(data []byte) error {
	if len(data) == 0 {
		// save() writes the full JSON envelope via a temp-then-rename, so it
		// never produces a zero-byte backing file. A present-but-empty file is
		// therefore a truncated/corrupted store (e.g. a crash mid-write on a
		// filesystem that lost the rename, or external tampering). Treat it like
		// malformed JSON: surface an error rather than silently re-seeding, which
		// would wipe every registered issuer (security review SVC-4). An absent
		// file (os.IsNotExist, handled above) remains a legitimately fresh deploy.
		return fmt.Errorf("trustregistry: %s is present but empty (corrupt or truncated store)", r.path)
	}
	var ff fileFormat
	if err := json.Unmarshal(data, &ff); err != nil {
		return fmt.Errorf("trustregistry: parse %s: %w", r.path, err)
	}
	for i, rec := range ff.Records {
		if rec == nil {
			continue
		}
		// Register and Replace validate; load did not, so a snapshot could carry
		// a record with any role, any key length and any status, and pkg/verify
		// documented that as a known condition rather than refusing it. A record
		// this package would not accept through its own API is not one it should
		// accept from a file either.
		if err := validateRecord(rec); err != nil {
			return fmt.Errorf("trustregistry: %s record %d (iss %q, role %q): %w",
				r.path, i, rec.Iss, rec.Role, err)
		}
		key := registryKey{rec.Iss, rec.Role}
		r.records[key] = append(r.records[key], copyRecord(rec))
	}
	return nil
}

// OpenVerified is the ONLY way to open a snapshot as a root of trust.
//
// It takes two files because a body on its own authenticates nothing: the
// manifest carries the signature, the body carries the records, and a verifier
// handed only a body has no root of trust and must fail closed
// (docs/spec/TRUST-REGISTRY-SNAPSHOT.md §2).
//
// It lives here rather than in pkg/verify so that every consumer goes through
// the same door. The gateway reaches it through pkg/verify.FromSignedSnapshot;
// cmd/agentsvc and cmd/deanonsvc use internal types and would otherwise have to
// reimplement the flow, which is how one service ends up verifying and another
// not — the state this repository was in before 2026-08-26.
//
// NewPersistentRegistry remains, and is correct, for the registry WRITER
// (cmd/trsvc): a service that owns the file does not authenticate its own
// state, and for it an absent file really is a fresh deploy. Readers must not
// use it.
func OpenVerified(manifestPath, bodyPath string, opts trustsnapshot.Options) (*PersistentRegistry, error) {
	manifestJSON, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read snapshot manifest: %w", err)
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		return nil, fmt.Errorf("read snapshot body: %w", err)
	}
	if _, err := trustsnapshot.Verify(manifestJSON, body, opts); err != nil {
		return nil, fmt.Errorf("snapshot rejected: %w", err)
	}
	// Load the bytes that were VERIFIED, not the path they came from.
	//
	// This previously ended `return NewPersistentRegistry(bodyPath)`, which threw
	// away the authenticated `body` and re-read the file. Anyone able to write
	// that path between the two reads -- the entire adversary this function
	// exists to stop -- substituted their own records after the signature check
	// and installed attacker-chosen ct_issuer/tts_issuer keys in agentsvc, or
	// escrow_req keys in deanonsvc. Nothing signed the substituted content.
	//
	// Verify what you load; load what you verified. Same defect class as the
	// bound-ceiling re-read in settle/base3009 -- validate, then go back to the
	// mutable source for the value actually used.
	if bodyPath == "" {
		return nil, fmt.Errorf("trustregistry: empty db path")
	}
	reg := &PersistentRegistry{
		records: make(map[registryKey][]*Record),
		path:    bodyPath,
	}
	if err := reg.loadFrom(body); err != nil {
		return nil, err
	}
	return reg, nil
}

// ManifestPathFor returns the conventional manifest path for a body:
// "<body>.manifest.json". The pair travels together so an operator cannot mount
// one and not notice the other is missing.
func ManifestPathFor(bodyPath string) string { return bodyPath + ".manifest.json" }

// ExportBody renders the registry as a snapshot body in a DETERMINISTIC record
// order, so signing the same registry twice produces the same digest.
//
// Order matters because the body digest is JCS over the body and JCS sorts
// object keys, not arrays: the record sequence is part of what is digested.
// Sorting here means the sequence is a property of the registry's content rather
// than of Go's map iteration, which is randomised.
func (r *PersistentRegistry) ExportBody() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	flat := make([]*Record, 0, len(r.records))
	for _, recs := range r.records {
		flat = append(flat, recs...)
	}
	sort.Slice(flat, func(i, j int) bool {
		a, b := flat[i], flat[j]
		if a.Iss != b.Iss {
			return a.Iss < b.Iss
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if !a.ValidFrom.Equal(b.ValidFrom) {
			return a.ValidFrom.Before(b.ValidFrom)
		}
		return string(a.PublicKey) < string(b.PublicKey)
	})
	return json.MarshalIndent(fileFormat{Version: persistVersion, Records: flat}, "", "  ")
}

// IssuerIDs returns the distinct issuer identifiers in the registry, sorted, for
// the manifest's issuer_ids field.
func (r *PersistentRegistry) IssuerIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := map[string]bool{}
	out := []string{}
	for k := range r.records {
		if !seen[k.Iss] {
			seen[k.Iss] = true
			out = append(out, k.Iss)
		}
	}
	sort.Strings(out)
	return out
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
	// fsync the parent directory so the rename itself is durable: without
	// this, a crash immediately after a confirmed registration could lose the
	// directory entry update even though the file data was synced, silently
	// reverting the just-acknowledged write (security review SVC-3). Needs only
	// the existing rpath promise.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
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

// Replace implements Mutable. It atomically revokes any existing active
// record for (rec.Iss, rec.Role) and appends rec as the new active record
// under a SINGLE lock and a SINGLE save(). If save() fails, BOTH in-memory
// edits (the revoke of the old record and the append of the new one) are
// rolled back, so the prior active record survives the failure intact
// (security review SVC-1). This closes the window where a separate Revoke
// then Register could crash between the two persisted saves and leave the
// issuer with no active key.
func (r *PersistentRegistry) Replace(_ context.Context, rec *Record) error {
	if err := validateRecord(rec); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	key := registryKey{rec.Iss, rec.Role}

	// Revoke the current active record (if any) in memory, remembering it so we
	// can restore its status on a save failure.
	var revoked *Record
	for _, existing := range r.records[key] {
		if existing.Status == StatusActive {
			revoked = existing
			existing.Status = StatusRevoked
			break
		}
	}

	cp := copyRecord(rec)
	r.records[key] = append(r.records[key], cp)

	if err := r.save(); err != nil {
		// Roll back BOTH edits so memory matches what is durable.
		r.records[key] = r.records[key][:len(r.records[key])-1]
		if revoked != nil {
			revoked.Status = StatusActive
		}
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

// jsonUnmarshal and jsonMarshalIndent exist so tests can build a body in the
// on-disk format without re-declaring it. Keeping the shape in one place is the
// point: a test that mirrors the format by hand stops testing the format.
func jsonUnmarshal(b []byte, v any) error     { return json.Unmarshal(b, v) }
func jsonMarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
