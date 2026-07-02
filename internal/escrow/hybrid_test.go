package escrow_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/escrow"
)

// TestHybrid_DefaultSchemeIsV2: NewEscrowKey + Seal produce a hybrid (Scheme 2)
// envelope carrying a non-empty ML-KEM-768 ciphertext (1088 bytes).
func TestHybrid_DefaultSchemeIsV2(t *testing.T) {
	esk, err := escrow.NewEscrowKey()
	if err != nil {
		t.Fatalf("NewEscrowKey: %v", err)
	}
	env, err := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-hy", "iss", time.Now().Unix())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.Scheme != escrow.SchemeX25519MLKEM768 {
		t.Fatalf("Scheme = %d, want %d (hybrid)", env.Scheme, escrow.SchemeX25519MLKEM768)
	}
	if len(env.KemCiphertext) != 1088 {
		t.Fatalf("KemCiphertext len = %d, want 1088 (ML-KEM-768)", len(env.KemCiphertext))
	}
	if len(env.EphemeralPub) != 32 {
		t.Fatalf("EphemeralPub len = %d, want 32 (X25519)", len(env.EphemeralPub))
	}
}

// TestHybrid_Roundtrip: a v2 envelope opens back to the exact identity.
func TestHybrid_Roundtrip(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	identity := []byte("the-real-name-behind-the-anchor")
	env, err := escrow.Seal(identity, esk.PublicKey(), "anchor-A", "domain-a.authorg", 1000)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := env.Open(esk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatalf("Open returned %q, want %q", got, identity)
	}
}

// TestHybrid_WrongKeyFails: a different escrow key cannot open the envelope
// (fails on ML-KEM decapsulate → AEAD, never silently succeeds).
func TestHybrid_WrongKeyFails(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	other, _ := escrow.NewEscrowKey()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)
	if _, err := env.Open(other); err == nil {
		t.Error("opening a hybrid envelope with the wrong key must fail")
	}
}

// TestHybrid_TranscriptBinding: substituting the ML-KEM ciphertext for another
// valid one (from a re-seal) must make Open fail — the combiner binds kemCT into
// the HKDF salt, defeating mix-and-match / re-encapsulation.
func TestHybrid_TranscriptBinding(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)

	// A second seal to the same key yields a different, independently-valid kemCT.
	env2, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)
	env.KemCiphertext = env2.KemCiphertext

	if _, err := env.Open(esk); err == nil {
		t.Error("swapping the ML-KEM ciphertext must break Open (transcript binding)")
	}
}

// TestHybrid_TamperedAADFails: altering any authenticated field breaks Open.
func TestHybrid_TamperedAADFails(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	env, _ := escrow.Seal([]byte("identity"), esk.PublicKey(), "anchor-1", "iss", 1000)
	env.HumanAnchor = "anchor-2" // re-point to a different anchor
	if _, err := env.Open(esk); err == nil {
		t.Error("a tampered AAD field must make Open fail")
	}
}

// TestHybrid_KeySerializeRoundtrip: a private key survives Bytes()/ParseKey and
// still opens an envelope sealed to the original public key.
func TestHybrid_KeySerializeRoundtrip(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	b := esk.Bytes()
	if len(b) != escrow.PrivateKeySize {
		t.Fatalf("serialized key = %d bytes, want %d", len(b), escrow.PrivateKeySize)
	}
	loaded, err := escrow.ParseKey(b)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	identity := []byte("recoverable-identity")
	env, _ := escrow.Seal(identity, esk.PublicKey(), "anchor-1", "iss", 1000)
	got, err := env.Open(loaded)
	if err != nil {
		t.Fatalf("Open with reloaded key: %v", err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatalf("reloaded key opened to %q, want %q", got, identity)
	}
	if _, err := escrow.ParseKey(b[:10]); err == nil {
		t.Error("ParseKey must reject a short buffer")
	}
}

// TestHybrid_RegistryPath: mirrors the production flow — the public halves are
// exported to bytes (as stored in the Trust Registry escrow-role record), an
// issuer rebuilds the hybrid public key via NewPublicKey and seals, and the
// escrow authority opens with the private key.
func TestHybrid_RegistryPath(t *testing.T) {
	esk, _ := escrow.NewEscrowKey()
	pub := esk.PublicKey()

	// What the registry stores + what an issuer reads back:
	rebuilt, err := escrow.NewPublicKey(pub.X25519Bytes(), pub.MlkemEncapKeyBytes())
	if err != nil {
		t.Fatalf("NewPublicKey from registry bytes: %v", err)
	}
	identity := []byte("real-name")
	env, err := escrow.Seal(identity, rebuilt, "anchor-1", "iss", 1000)
	if err != nil {
		t.Fatalf("Seal with rebuilt pub: %v", err)
	}
	got, err := env.Open(esk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, identity) {
		t.Fatalf("registry-path round-trip opened to %q, want %q", got, identity)
	}

	// A corrupted encapsulation key must be rejected at rebuild.
	bad := append([]byte{}, pub.MlkemEncapKeyBytes()...)
	bad = bad[:len(bad)-1]
	if _, err := escrow.NewPublicKey(pub.X25519Bytes(), bad); err == nil {
		t.Error("NewPublicKey must reject a malformed ML-KEM encapsulation key")
	}
}
