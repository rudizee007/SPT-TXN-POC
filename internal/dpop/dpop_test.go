package dpop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/dpop"
)

const verifyURL = "https://foss.violetskysecurity.com/b/verify"

func TestProofVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, err := dpop.Proof(priv, "POST", verifyURL, "")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	jkt, jti, err := dpop.Verify(proof, "POST", verifyURL, "", 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if jkt != dpop.Thumbprint(pub) {
		t.Error("returned thumbprint does not match the holder key thumbprint")
	}
	if jti == "" {
		t.Error("Verify must return the proof jti for replay tracking")
	}
}

func TestVerify_HTMMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "GET", "https://x/y", "", 0); err == nil {
		t.Error("htm mismatch must be rejected")
	}
}

func TestVerify_HTUMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "POST", "https://x/z", "", 0); err == nil {
		t.Error("htu mismatch must be rejected")
	}
}

func TestVerify_Expired(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof, _ := dpop.Proof(priv, "POST", "https://x/y", "")
	if _, _, err := dpop.Verify(proof, "POST", "https://x/y", "", 1*time.Nanosecond); err == nil {
		t.Error("stale proof must be rejected")
	}
}

// ath binding: a proof carrying one token's hash must not verify against another.
func TestVerify_ATHBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	athA := dpop.ATH("token-A")
	proof, _ := dpop.Proof(priv, "POST", verifyURL, athA)

	if _, _, err := dpop.Verify(proof, "POST", verifyURL, athA, 0); err != nil {
		t.Errorf("proof should verify against its own token's ath: %v", err)
	}
	if _, _, err := dpop.Verify(proof, "POST", verifyURL, dpop.ATH("token-B"), 0); err == nil {
		t.Error("proof bound to token-A must not verify against token-B's ath")
	}
}

// htu normalization (RFC 9449 §4.3): a proof and the expected htu that differ
// only in scheme/host case or in a query/fragment must still match.
func TestVerify_HTUNormalization(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Proof carries an upper-cased host and a query+fragment; the verifier expects
	// the canonical lower-cased URI with neither.
	proof, _ := dpop.Proof(priv, "POST", "HTTPS://FOSS.Violetskysecurity.com/b/verify?x=1#frag", "")
	if _, _, err := dpop.Verify(proof, "POST", "https://foss.violetskysecurity.com/b/verify", "", 0); err != nil {
		t.Errorf("normalized-equivalent htu should match: %v", err)
	}
	// A genuinely different path must still be rejected — normalization must not
	// loosen the path boundary.
	proof2, _ := dpop.Proof(priv, "POST", "https://foss.violetskysecurity.com/b/verify", "")
	if _, _, err := dpop.Verify(proof2, "POST", "https://foss.violetskysecurity.com/b/admin", "", 0); err == nil {
		t.Error("different path must still be rejected")
	}
}

func TestThumbprint_Stable(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if dpop.Thumbprint(pub) != dpop.Thumbprint(pub) {
		t.Error("thumbprint must be stable for the same key")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if dpop.Thumbprint(pub) == dpop.Thumbprint(other) {
		t.Error("different keys must yield different thumbprints")
	}
}

// An empty expected binding must be refused rather than compared.
//
// The comparisons in Verify are equality, so "" == "" passes: a caller that does
// not know the method and URI would get a proof-of-possession answer about
// nothing, and one token would authorize any request. The gateway refuses before
// reaching here, but that is a property of today's callers, not of this function.
func TestVerify_RefusesAnEmptyBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct{ htm, htu string }{
		"no htm":  {"", "https://api.example/pay"},
		"no htu":  {"POST", ""},
		"neither": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := dpop.Proof(priv, c.htm, c.htu, "ath")
			if err != nil {
				t.Fatalf("Proof: %v", err)
			}
			if _, _, err := dpop.Verify(p, c.htm, c.htu, "ath", time.Minute); err == nil {
				t.Fatal("an empty binding was accepted; one proof would authorize any request")
			}
		})
	}
}
