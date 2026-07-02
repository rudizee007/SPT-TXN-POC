package escrow

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// TestV1BackCompat: a legacy Scheme 1 (X25519-only) envelope still opens with a
// hybrid key — Open dispatches on the Scheme byte, so pre-migration ciphertext
// is not stranded. Exercises the unexported sealClassical migration path.
func TestV1BackCompat(t *testing.T) {
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519 keygen: %v", err)
	}
	identity := []byte("legacy-identity")
	env, err := sealClassical(identity, xk.PublicKey(), "anchor-v1", "iss", 1000)
	if err != nil {
		t.Fatalf("sealClassical: %v", err)
	}
	if env.Scheme != SchemeX25519 {
		t.Fatalf("Scheme = %d, want %d (legacy)", env.Scheme, SchemeX25519)
	}
	if len(env.KemCiphertext) != 0 {
		t.Fatalf("legacy envelope must carry no ML-KEM ciphertext, got %d bytes", len(env.KemCiphertext))
	}
	// A hybrid Key whose X25519 half matches opens the v1 envelope.
	k := &Key{x25519: xk}
	got, err := env.Open(k)
	if err != nil {
		t.Fatalf("Open v1: %v", err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatalf("Open returned %q, want %q", got, identity)
	}
}

// TestDeriveKey_HKDF (ESC-2): the HKDF-SHA256 derivation is deterministic for a
// given shared secret (so Seal and Open agree) and produces a 32-byte AES-256
// key, while different shared secrets yield different keys.
func TestDeriveKey_HKDF(t *testing.T) {
	shared := []byte("x25519-ecdh-shared-secret-32bytes!!")

	k1, err := deriveKey(shared)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32 (AES-256)", len(k1))
	}

	k2, err := deriveKey(shared)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("HKDF derivation must be deterministic for the same shared secret")
	}

	other, err := deriveKey([]byte("a-different-shared-secret-value!!"))
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if bytes.Equal(k1, other) {
		t.Error("distinct shared secrets must derive distinct keys")
	}
}
