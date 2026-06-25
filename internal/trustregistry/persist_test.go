package trustregistry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleRecord(iss string, role Role) *Record {
	now := time.Now().UTC()
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i + 1) // non-zero
	}
	return &Record{
		Iss:        iss,
		Role:       role,
		PublicKey:  pk,
		KeyType:    "Ed25519",
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(24 * time.Hour),
		Status:     StatusActive,
		Metadata:   map[string]string{"note": "test"},
	}
}

// TestPersistenceSurvivesRestart is the core regression test for security
// review M7: a registered issuer must still be active after the process
// "restarts" (a fresh registry opened on the same file).
func TestPersistenceSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.db")

	reg1, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := reg1.Register(ctx, sampleRecord("did:web:authorg", RoleCTIssuer)); err != nil {
		t.Fatalf("register: %v", err)
	}
	_ = reg1.Close()

	// File must exist and be owner-only (0600).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("registry file mode = %o, want 600", perm)
	}

	// Simulated restart: brand-new instance, same file.
	reg2, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer reg2.Close()

	rec, err := reg2.Lookup(ctx, "did:web:authorg", RoleCTIssuer)
	if err != nil {
		t.Fatalf("lookup after restart: %v", err)
	}
	if rec.Status != StatusActive {
		t.Fatalf("status after restart = %q, want active", rec.Status)
	}
	if len(rec.PublicKey) != 32 || rec.PublicKey[0] != 1 {
		t.Fatalf("public key not round-tripped: %v", rec.PublicKey)
	}
}

// TestRevokePersists confirms a revocation is durable across a restart.
func TestRevokePersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.db")

	reg1, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := reg1.Register(ctx, sampleRecord("issuer-x", RoleTTSIssuer)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg1.Revoke(ctx, "issuer-x", RoleTTSIssuer, time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_ = reg1.Close()

	reg2, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer reg2.Close()

	if _, err := reg2.Lookup(ctx, "issuer-x", RoleTTSIssuer); err != ErrNotFound {
		t.Fatalf("revoked key lookup err = %v, want ErrNotFound", err)
	}
	// After revocation a fresh active registration must be accepted.
	if err := reg2.Register(ctx, sampleRecord("issuer-x", RoleTTSIssuer)); err != nil {
		t.Fatalf("re-register after revoke: %v", err)
	}
}

// TestCorruptFileSurfaced ensures a corrupt store is reported, not silently
// treated as empty (which would mask tampering).
func TestCorruptFileSurfaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if _, err := NewPersistentRegistry(path); err == nil {
		t.Fatal("expected error opening corrupt registry, got nil")
	}
}

// TestMissingFileIsEmpty confirms a fresh deploy (no file yet) opens clean.
func TestMissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.db")
	reg, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.Close()
	recs, err := reg.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("fresh registry has %d records, want 0", len(recs))
	}
}
