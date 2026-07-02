package trustregistry

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// hybridEscrowRecord builds a well-formed hybrid escrow record with non-zero
// key material of the correct lengths.
func hybridEscrowRecord() *Record {
	pub := make([]byte, 32)
	pub[0] = 1
	encap := make([]byte, MlkemEncapKeySize)
	encap[0] = 1
	return &Record{
		Iss:           "domain-a.authorg",
		Role:          RoleEscrow,
		PublicKey:     pub,
		MlkemEncapKey: encap,
		KeyType:       KeyTypeX25519MLKEM768,
		ValidFrom:     time.Now().Add(-time.Hour),
		ValidUntil:    time.Now().Add(24 * time.Hour),
		Status:        StatusActive,
	}
}

func TestHybridEscrow_RegisterAndLookup(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()

	if err := r.Register(ctx, hybridEscrowRecord()); err != nil {
		t.Fatalf("Register hybrid escrow: %v", err)
	}
	got, err := r.Lookup(ctx, "domain-a.authorg", RoleEscrow)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.KeyType != KeyTypeX25519MLKEM768 {
		t.Fatalf("KeyType = %q, want %q", got.KeyType, KeyTypeX25519MLKEM768)
	}
	if len(got.PublicKey) != 32 {
		t.Fatalf("X25519 half = %d bytes, want 32", len(got.PublicKey))
	}
	if len(got.MlkemEncapKey) != MlkemEncapKeySize {
		t.Fatalf("ML-KEM half = %d bytes, want %d", len(got.MlkemEncapKey), MlkemEncapKeySize)
	}

	// Lookup must return a copy: mutating it cannot corrupt the stored record.
	got.MlkemEncapKey[0] ^= 0xFF
	again, _ := r.Lookup(ctx, "domain-a.authorg", RoleEscrow)
	if again.MlkemEncapKey[0] == got.MlkemEncapKey[0] {
		t.Error("Lookup returned aliased ML-KEM key material (must be a copy)")
	}
}

func TestHybridEscrow_ValidationRejects(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*Record){
		"hybrid on non-escrow role": func(rec *Record) { rec.Role = RoleCTIssuer },
		"missing ML-KEM half":       func(rec *Record) { rec.MlkemEncapKey = nil },
		"wrong ML-KEM length":       func(rec *Record) { rec.MlkemEncapKey = make([]byte, 100) },
		"wrong X25519 length":       func(rec *Record) { rec.PublicKey = make([]byte, 16) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTestRegistry(t)
			rec := hybridEscrowRecord()
			mutate(rec)
			if err := r.Register(ctx, rec); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Register(%s) err = %v, want ErrInvalidRecord", name, err)
			}
		})
	}
}

func TestClassical_RejectsStrayMlkemKey(t *testing.T) {
	r := newTestRegistry(t)
	rec := &Record{
		Iss:           "domain-a",
		Role:          RoleEscrow,
		PublicKey:     func() []byte { b := make([]byte, 32); b[0] = 1; return b }(),
		MlkemEncapKey: make([]byte, MlkemEncapKeySize), // not allowed for classical X25519
		KeyType:       KeyTypeX25519,
		ValidFrom:     time.Now().Add(-time.Hour),
		ValidUntil:    time.Now().Add(24 * time.Hour),
		Status:        StatusActive,
	}
	if err := r.Register(context.Background(), rec); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("classical record with stray ML-KEM key err = %v, want ErrInvalidRecord", err)
	}
}

// TestHybridEscrow_PersistRoundtrip: a hybrid record survives a save/reload of
// the file-backed registry with its ML-KEM half intact (JSON round-trip).
func TestHybridEscrow_PersistRoundtrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.json")

	r1, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("NewPersistentRegistry: %v", err)
	}
	if err := r1.Register(ctx, hybridEscrowRecord()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_ = r1.Close()

	r2, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = r2.Close() })
	got, err := r2.Lookup(ctx, "domain-a.authorg", RoleEscrow)
	if err != nil {
		t.Fatalf("Lookup after reload: %v", err)
	}
	if got.KeyType != KeyTypeX25519MLKEM768 || len(got.MlkemEncapKey) != MlkemEncapKeySize {
		t.Fatalf("hybrid record did not round-trip: KeyType=%q mlkem=%d", got.KeyType, len(got.MlkemEncapKey))
	}
}
