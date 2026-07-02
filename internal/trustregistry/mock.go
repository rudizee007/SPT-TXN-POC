// Package trustregistry — in-memory mock implementation.
//
// Uses a plain Go map protected by sync.RWMutex. No SQLite, no CGo,
// no external dependencies. Suitable for the POC on OpenBSD where
// modernc.org/libc has known compatibility issues.
//
// Data is seeded on startup and lives only for the process lifetime.
// Persistence is not required for the POC demo.
package trustregistry

import (
	"context"
	"sync"
	"time"
)

// registryKey uniquely identifies a record by issuer + role.
type registryKey struct {
	Iss  string
	Role Role
}

// MockRegistry is an in-memory Registry and Mutable implementation.
type MockRegistry struct {
	mu      sync.RWMutex
	records map[registryKey][]*Record // all records, including revoked
}

// NewMockRegistry creates a new empty in-memory registry.
// The path argument is accepted for API compatibility but ignored.
func NewMockRegistry(_ string) (*MockRegistry, error) {
	return &MockRegistry{
		records: make(map[registryKey][]*Record),
	}, nil
}

// Register implements Mutable.
func (r *MockRegistry) Register(_ context.Context, rec *Record) error {
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
	// Store a copy.
	cp := copyRecord(rec)
	r.records[key] = append(r.records[key], cp)
	return nil
}

// Replace implements Mutable. It revokes any existing active record for
// (rec.Iss, rec.Role) and appends rec as the new active record under a
// single held lock. MockRegistry has no persistence, so there is no save to
// fail and nothing to roll back — but it mirrors PersistentRegistry.Replace
// so callers behave identically against either implementation (security
// review SVC-1).
func (r *MockRegistry) Replace(_ context.Context, rec *Record) error {
	if err := validateRecord(rec); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	key := registryKey{rec.Iss, rec.Role}
	for _, existing := range r.records[key] {
		if existing.Status == StatusActive {
			existing.Status = StatusRevoked
			break
		}
	}
	cp := copyRecord(rec)
	r.records[key] = append(r.records[key], cp)
	return nil
}

// Lookup implements Registry.
func (r *MockRegistry) Lookup(_ context.Context, iss string, role Role) (*Record, error) {
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
func (r *MockRegistry) List(_ context.Context, role Role) ([]*Record, error) {
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
func (r *MockRegistry) Revoke(_ context.Context, iss string, role Role, at time.Time) error {
	return r.setStatus(iss, role, StatusRevoked, at)
}

// Supersede implements Mutable.
func (r *MockRegistry) Supersede(_ context.Context, iss string, role Role, at time.Time) error {
	return r.setStatus(iss, role, StatusSuperseded, at)
}

func (r *MockRegistry) setStatus(iss string, role Role, status RecordStatus, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := registryKey{iss, role}
	for _, rec := range r.records[key] {
		if rec.Status == StatusActive {
			rec.Status = status
			return nil
		}
	}
	return ErrNotFound
}

// Close implements Registry. No-op for the in-memory implementation.
func (r *MockRegistry) Close() error { return nil }

// ── helpers ────────────────────────────────────────────────────────────

// validKeyTypes is the set of key types accepted by this implementation, with
// their per-type validation rules applied in validateRecord.
//
// The classical types (Ed25519 signing, X25519 escrow) are 32-byte keys. The
// hybrid escrow type (X25519+ML-KEM-768) additionally carries a 1184-byte
// ML-KEM-768 encapsulation key in MlkemEncapKey and is permitted ONLY for the
// escrow role — it is the post-quantum harvest-now-decrypt-later fix for stored
// escrow envelopes (internal/escrow, Scheme 2). PQ *signature* types
// (ML-DSA-44/65) remain deliberately unsupported until token signing migrates.
var validKeyTypes = map[string]bool{
	KeyTypeEd25519:        true,
	KeyTypeX25519:         true,
	KeyTypeX25519MLKEM768: true,
}

func validateRecord(rec *Record) error {
	if rec.Iss == "" {
		return ErrInvalidRecord
	}
	if !rec.Role.IsValid() {
		return ErrInvalidRecord
	}
	if !validKeyTypes[rec.KeyType] {
		return ErrInvalidRecord
	}
	// Per-KeyType shape checks. The X25519 half is always 32 bytes; the hybrid
	// type adds a 1184-byte ML-KEM-768 key and is escrow-only. Classical types
	// must NOT carry an ML-KEM key (reject stray/confused material).
	switch rec.KeyType {
	case KeyTypeEd25519, KeyTypeX25519:
		if len(rec.PublicKey) != 32 || len(rec.MlkemEncapKey) != 0 {
			return ErrInvalidRecord
		}
	case KeyTypeX25519MLKEM768:
		if rec.Role != RoleEscrow {
			return ErrInvalidRecord
		}
		if len(rec.PublicKey) != 32 || len(rec.MlkemEncapKey) != MlkemEncapKeySize {
			return ErrInvalidRecord
		}
	default:
		return ErrInvalidRecord
	}
	if !rec.ValidUntil.After(rec.ValidFrom) {
		return ErrInvalidRecord
	}
	return nil
}

func copyRecord(src *Record) *Record {
	dst := *src
	dst.PublicKey = make([]byte, len(src.PublicKey))
	copy(dst.PublicKey, src.PublicKey)
	if src.MlkemEncapKey != nil {
		dst.MlkemEncapKey = make([]byte, len(src.MlkemEncapKey))
		copy(dst.MlkemEncapKey, src.MlkemEncapKey)
	}
	if src.Metadata != nil {
		dst.Metadata = make(map[string]string, len(src.Metadata))
		for k, v := range src.Metadata {
			dst.Metadata[k] = v
		}
	}
	return &dst
}
