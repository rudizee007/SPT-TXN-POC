package receiptlog

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// TestEmitAndProveInclusion is the end-to-end P2 path: decisions emit signed
// receipts into the hash-chained log; a signed Merkle root is published; any
// single receipt is provable against that root without the rest of the log.
func TestEmitAndProveInclusion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	em, err := NewLogEmitter(log, priv)
	if err != nil {
		t.Fatal(err)
	}

	var hashes []string
	for i := 0; i < 7; i++ {
		dec, class, rule := receipt.DecisionPermit, receipt.ClassOK, "authorize.ok"
		if i%3 == 0 {
			dec, class, rule = receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch"
		}
		r, err := receipt.New("pep.test", dec, class, rule, receipt.TokenHash("tok"), receipt.TokenHash("policy"))
		if err != nil {
			t.Fatal(err)
		}
		h, err := em.Emit(r)
		if err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
		// The stored signature must verify.
		if err := r.Verify(pub); err != nil {
			t.Fatalf("emitted receipt %d does not verify: %v", i, err)
		}
		hashes = append(hashes, h)
	}

	// Log chain must be intact and re-verifiable.
	if err := log.Verify(); err != nil {
		t.Fatalf("log chain broken: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 7 {
		t.Fatalf("entries = %d", len(entries))
	}

	// Publish a signed root, then prove receipt #4 against it.
	sr := audit.PublishRoot(entries, priv)
	if !audit.VerifyRoot(sr, pub) {
		t.Fatal("published root does not verify")
	}
	idx := 4
	if entries[idx].Subject != hashes[idx] {
		t.Fatalf("entry %d subject %s != receipt hash %s", idx, entries[idx].Subject, hashes[idx])
	}
	path, err := audit.MerkleProof(entries, idx)
	if err != nil {
		t.Fatal(err)
	}
	if !audit.VerifyInclusion(entries[idx].Hash, idx, len(entries), path, sr.Root) {
		t.Fatal("inclusion proof failed against published root")
	}

	// Tamper: a rewritten leaf hash must not prove inclusion under the
	// previously published root.
	tampered := make([]byte, len(entries[idx].Hash))
	copy(tampered, entries[idx].Hash)
	tampered[0] ^= 0x01
	if audit.VerifyInclusion(tampered, idx, len(entries), path, sr.Root) {
		t.Fatal("tampered leaf still proves inclusion under the published root")
	}
}
