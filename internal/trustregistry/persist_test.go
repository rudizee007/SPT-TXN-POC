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

// TestEmptyFileSurfaced ensures a present-but-zero-byte backing file is
// treated as corruption, not as a fresh/empty store (security review SVC-4).
// save() never writes a zero-byte file, so an empty one means truncation or
// tampering; silently re-seeding would wipe every registered issuer.
func TestEmptyFileSurfaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	if _, err := NewPersistentRegistry(path); err == nil {
		t.Fatal("expected error opening empty (truncated) registry, got nil")
	}
}

// TestReplace_RotatesAtomically confirms Replace supersedes the prior active
// record and installs the new one, and that the result is durable across a
// restart (security review SVC-1).
func TestReplace_RotatesAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.db")

	reg1, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	old := sampleRecord("issuer-z", RoleCTIssuer)
	if err := reg1.Register(ctx, old); err != nil {
		t.Fatalf("register old: %v", err)
	}
	// New key, different first byte so we can tell them apart.
	newRec := sampleRecord("issuer-z", RoleCTIssuer)
	newRec.PublicKey[0] = 0xAA
	if err := reg1.Replace(ctx, newRec); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, err := reg1.Lookup(ctx, "issuer-z", RoleCTIssuer)
	if err != nil {
		t.Fatalf("lookup after replace: %v", err)
	}
	if got.PublicKey[0] != 0xAA {
		t.Fatalf("active key after replace = %#v, want new key", got.PublicKey[0])
	}
	_ = reg1.Close()

	// Durable across restart, and only ONE active record remains.
	reg2, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer reg2.Close()
	got2, err := reg2.Lookup(ctx, "issuer-z", RoleCTIssuer)
	if err != nil {
		t.Fatalf("lookup after restart: %v", err)
	}
	if got2.PublicKey[0] != 0xAA {
		t.Fatalf("active key after restart = %#v, want new key", got2.PublicKey[0])
	}
	all, err := reg2.List(ctx, RoleCTIssuer)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	active := 0
	for _, rec := range all {
		if rec.Status == StatusActive {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active records after replace = %d, want 1", active)
	}
}

// TestReplace_SaveFailureKeepsPriorActive is the core SVC-1 regression: if the
// persisted save fails mid-Replace, BOTH in-memory edits roll back and the
// prior active record survives intact — the issuer is never left with no key.
// We force a save failure by removing the backing directory's write access (the
// temp-file create then fails inside save()).
func TestReplace_SaveFailureKeepsPriorActive(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.db")

	reg, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := sampleRecord("issuer-rb", RoleCTIssuer)
	old.PublicKey[0] = 0x11
	if err := reg.Register(ctx, old); err != nil {
		t.Fatalf("register old: %v", err)
	}

	// Make the directory unwritable so save()'s os.CreateTemp fails. Root
	// ignores directory modes, so under root (containerised CI) the failure
	// this test needs cannot be produced; skip rather than report a defect
	// the code does not have.
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unwritable directory is writable, so the save failure cannot be induced")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // so TempDir cleanup works

	newRec := sampleRecord("issuer-rb", RoleCTIssuer)
	newRec.PublicKey[0] = 0xAA
	if err := reg.Replace(ctx, newRec); err == nil {
		t.Fatal("expected Replace to fail with unwritable dir, got nil")
	}

	// The prior active record must still be the live one (rolled back).
	got, err := reg.Lookup(ctx, "issuer-rb", RoleCTIssuer)
	if err != nil {
		t.Fatalf("lookup after failed replace: %v", err)
	}
	if got.PublicKey[0] != 0x11 {
		t.Fatalf("active key after failed replace = %#v, want prior key (0x11)", got.PublicKey[0])
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
