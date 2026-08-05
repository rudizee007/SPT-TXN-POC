package receipt

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sample(t *testing.T) *Receipt {
	t.Helper()
	r, err := New("pep.example", DecisionDeny, ClassViolation, "intent.digest-mismatch",
		TokenHash("eyJhbGciOiJFZERTQSJ9.x.y"), TokenHash("policy-bundle-v3"))
	if err != nil {
		t.Fatal(err)
	}
	r.IntentDigest = "abc"
	r.Jurisdiction = "EU-DORA"
	return r
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	r := sample(t)
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	pub, priv := keys(t)
	mutations := []func(*Receipt){
		func(r *Receipt) { r.Decision = DecisionPermit; r.Class = ClassOK }, // flip deny→permit
		func(r *Receipt) { r.Class = ClassUnavailable },                     // reclassify attack as outage
		func(r *Receipt) { r.RulePath = "replay.ok" },
		func(r *Receipt) { r.TokenHash = TokenHash("other-token") },
		func(r *Receipt) { r.PolicyHash = TokenHash("older-policy") },
		func(r *Receipt) { r.TS++ },
		func(r *Receipt) { r.Nonce = strings.Repeat("A", 22) },
		func(r *Receipt) { r.IntentDigest = "" },
		func(r *Receipt) { r.Jurisdiction = "US-FED" },
	}
	for i, mutate := range mutations {
		r := sample(t)
		if err := r.Sign(priv); err != nil {
			t.Fatal(err)
		}
		mutate(r)
		if err := r.Verify(pub); err == nil {
			t.Errorf("mutation %d: tampered receipt verified", i)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	_, priv := keys(t)
	otherPub, _ := keys(t)
	r := sample(t)
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(otherPub); err == nil {
		t.Fatal("receipt verified under wrong key")
	}
}

func TestConstructionRejectsMislabeledDecisions(t *testing.T) {
	cases := []struct{ decision, class string }{
		{DecisionPermit, ClassViolation},
		{DecisionPermit, ClassUnavailable},
		{DecisionDeny, ClassOK},
		{"ALLOW", ClassOK},
		{"", ""},
		{DecisionDeny, "weird"},
	}
	for _, tc := range cases {
		if _, err := New("pep", tc.decision, tc.class, "rule", "", ""); err == nil {
			t.Errorf("New(%q,%q) accepted; want reject", tc.decision, tc.class)
		}
	}
	// Empty rule path is also a defect: evidence must explain itself.
	if _, err := New("pep", DecisionDeny, ClassViolation, "", "", ""); err == nil {
		t.Error("empty rule path accepted")
	}
}

func TestVerifyRejectsInvalidPairEvenIfSigned(t *testing.T) {
	pub, priv := keys(t)
	r := sample(t)
	r.Decision = DecisionPermit // force invalid pair PERMIT/violation
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err == nil {
		t.Fatal("mislabeled decision/class pair verified")
	}
}

func TestHashRequiresSignature(t *testing.T) {
	r := sample(t)
	if _, err := r.Hash(); err == nil {
		t.Fatal("hash of unsigned receipt accepted")
	}
}

func TestNoncesUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		r, err := New("pep", DecisionPermit, ClassOK, "ok", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if seen[r.Nonce] {
			t.Fatal("nonce repeated")
		}
		seen[r.Nonce] = true
	}
}

func TestAuditDetailNoRawContent(t *testing.T) {
	_, priv := keys(t)
	r := sample(t)
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	d, err := r.AuditDetail()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range d {
		if strings.Contains(v, "eyJ") {
			t.Errorf("detail %q appears to carry raw token material: %q", k, v)
		}
	}
	if d["receipt_hash"] == "" {
		t.Error("missing receipt_hash")
	}
}
