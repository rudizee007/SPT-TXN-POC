package audit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/audit"
)

func TestLog_AppendReloadVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append("txn_issued", "jti-"+strconv.Itoa(i), map[string]string{"amount_commitment": "c3b0...opaque"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n := len(l.Entries()); n != 5 {
		t.Fatalf("entries = %d, want 5", n)
	}
	l.Close()

	// Reopen from disk: entries replay and the chain re-verifies.
	l2, err := audit.Open(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer l2.Close()
	if n := len(l2.Entries()); n != 5 {
		t.Fatalf("reloaded entries = %d, want 5", n)
	}
	if err := l2.Verify(); err != nil {
		t.Fatalf("reload verify: %v", err)
	}
	// Appending continues the chain across reopen.
	if _, err := l2.Append("verify_decision", "jti-x", map[string]string{"allow": "true"}); err != nil {
		t.Fatalf("append after reload: %v", err)
	}
	if err := l2.Verify(); err != nil {
		t.Fatalf("verify after reload append: %v", err)
	}
}

func TestLog_TamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("a", "subject-one", nil)
	l.Append("b", "subject-two", nil)
	l.Append("c", "subject-three", nil)
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Alter a past entry's subject without recomputing its hash chain.
	corrupted := strings.Replace(string(data), "subject-two", "subject-EVIL", 1)
	if corrupted == string(data) {
		t.Fatal("test setup: nothing was replaced")
	}
	if err := os.WriteFile(path, []byte(corrupted), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := audit.Open(path); err == nil {
		t.Error("a tampered log must fail to reopen (chain integrity)")
	}
}

func TestMerkle_DeterministicAndSigned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.log")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		l.Append("e", "s"+strconv.Itoa(i), nil)
	}
	entries := l.Entries()

	r1 := audit.MerkleRoot(entries)
	r2 := audit.MerkleRoot(entries)
	if len(r1) == 0 || string(r1) != string(r2) {
		t.Fatal("Merkle root must be deterministic and non-empty")
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sr := audit.PublishRoot(entries, priv)
	if !audit.VerifyRoot(sr, pub) {
		t.Error("signed root must verify with the audit key")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if audit.VerifyRoot(sr, otherPub) {
		t.Error("signed root must not verify with a different key")
	}

	// Adding an entry must change the published root.
	l.Append("e", "s-new", nil)
	if string(audit.MerkleRoot(l.Entries())) == string(r1) {
		t.Error("Merkle root must change when the log changes")
	}
	l.Close()
}

// AUD-2: Append must reject Detail maps that carry a known-sensitive (PII) key,
// forcing callers to log commitments/opaque IDs instead of raw values.
func TestLog_RejectsPIIDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pii.log")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, k := range []string{"amount", "name", "account", "pan", "iban", "dob", "AMOUNT"} {
		if _, err := l.Append("txn_issued", "jti-1", map[string]string{k: "secret"}); err == nil {
			t.Errorf("Append with PII key %q must be rejected", k)
		}
	}
	// An opaque reference is accepted.
	if _, err := l.Append("txn_issued", "jti-1", map[string]string{"amount_commitment": "c0ffee"}); err != nil {
		t.Errorf("opaque detail must be accepted, got %v", err)
	}
	if n := len(l.Entries()); n != 1 {
		t.Fatalf("only the opaque append should have succeeded, got %d entries", n)
	}
}
