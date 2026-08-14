package trustsnapshot

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// katFile mirrors trust-snapshot-signing-v1.kat.json (only the fields the gate
// asserts on).
type katFile struct {
	// sig_domain, not domain: the vector file distinguishes the signature
	// domain from the body-digest domain, which are different objects and must
	// not be confusable. This verifier implements the signing input only, so it
	// asserts on sig_domain and ignores body_domain and the content-digest
	// expectations — deliberately, rather than by omission.
	SigDomain  string `json:"sig_domain"`
	SigningKey struct {
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
	} `json:"signing_key"`
	Vectors []struct {
		Name  string `json:"name"`
		Input struct {
			ID             string   `json:"id"`
			IssuedMs       uint64   `json:"issued_ms"`
			IssuerIDs      []string `json:"issuer_ids"`
			DigestHex      string   `json:"digest_hex"`
			PrevSnapshotID *string  `json:"prev_snapshot_id"`
		} `json:"input"`
		ExpectedSigningInputHex string `json:"expected_signing_input_hex"`
		ExpectedSignatureHex    string `json:"expected_signature_hex"`
	} `json:"vectors"`
}

func loadKAT(t *testing.T) katFile {
	t.Helper()
	b, err := os.ReadFile("testdata/trust-snapshot-signing-v1.kat.json")
	if err != nil {
		t.Fatalf("read KAT: %v", err)
	}
	var k katFile
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatalf("parse KAT: %v", err)
	}
	if k.SigDomain != SnapshotSigDomain {
		t.Fatalf("KAT sig_domain %q != code domain %q", k.SigDomain, SnapshotSigDomain)
	}
	if len(k.Vectors) == 0 {
		t.Fatal("KAT has no vectors")
	}
	return k
}

// TestSigningInputMatchesKAT is the cross-language CI gate: our SigningInput
// must equal the golden bytes in the published vectors, and signing them with
// the pinned seed must reproduce the golden signature. A drift in either
// language's canonicalization fails here.
func TestSigningInputMatchesKAT(t *testing.T) {
	k := loadKAT(t)
	seed, err := hex.DecodeString(k.SigningKey.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("bad seed: err=%v len=%d", err, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pub); got != k.SigningKey.PublicKeyHex {
		t.Fatalf("derived pubkey %s != KAT %s", got, k.SigningKey.PublicKeyHex)
	}

	for _, v := range k.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			in := SigningInput(v.Input.ID, v.Input.IssuedMs, v.Input.IssuerIDs, v.Input.DigestHex, v.Input.PrevSnapshotID)
			if got := hex.EncodeToString(in); got != v.ExpectedSigningInputHex {
				t.Fatalf("signing input mismatch\n got %s\nwant %s", got, v.ExpectedSigningInputHex)
			}
			sig := ed25519.Sign(priv, in)
			if got := hex.EncodeToString(sig); got != v.ExpectedSignatureHex {
				t.Fatalf("signature mismatch\n got %s\nwant %s", got, v.ExpectedSignatureHex)
			}
			// The golden signature MUST verify against the recomputed input.
			if !ed25519.Verify(pub, in, sig) {
				t.Fatal("golden signature does not verify against recomputed input")
			}
		})
	}
}

// TestTrapsAreRejected proves the two canonicalization traps produce inputs
// whose golden signature does not verify — i.e. getting canonicalization wrong
// fails closed, it does not silently pass.
func TestTrapsAreRejected(t *testing.T) {
	k := loadKAT(t)
	seed, _ := hex.DecodeString(k.SigningKey.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Use v1 (prev = null) as the base.
	var v1 struct {
		id        string
		issuedMs  uint64
		issuerIDs []string
		digestHex string
	}
	v1.id, v1.issuedMs, v1.issuerIDs, v1.digestHex = "snap-1", 1000, []string{"iss-a", "iss-b"}, "deadbeef"
	golden := ed25519.Sign(priv, SigningInput(v1.id, v1.issuedMs, v1.issuerIDs, v1.digestHex, nil))

	// Trap A: declaration/macro order instead of sorted keys.
	trapA := []byte(`{"domain":"` + SnapshotSigDomain + `","id":"snap-1","issued_ms":1000,"issuer_ids":["iss-a","iss-b"],"digest_hex":"deadbeef","prev_snapshot_id":null}`)
	if ed25519.Verify(pub, trapA, golden) {
		t.Fatal("trap A (macro order) unexpectedly verified — canonicalization not enforced")
	}
	// Trap B: prev_snapshot_id omitted (wire-form mirror).
	trapB := []byte(`{"digest_hex":"deadbeef","domain":"` + SnapshotSigDomain + `","id":"snap-1","issued_ms":1000,"issuer_ids":["iss-a","iss-b"]}`)
	if ed25519.Verify(pub, trapB, golden) {
		t.Fatal("trap B (omitted null prev) unexpectedly verified")
	}
}
