package civicpass_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/civicpass"
	"github.com/rudizee007/spt-txn-poc/internal/identityroot"
)

// The adapter must satisfy the shared identity-root seam — the same interface
// the mock implements, so issuance code swaps one for the other unchanged.
var _ identityroot.Provider = (*civicpass.Verifier)(nil)

func nullKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// newVerifier returns a Verifier trusting a single attester and allowing the
// "proof-of-personhood" claim, plus that attester's signing key.
func newVerifier(t *testing.T) (*civicpass.Verifier, ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	v, _, err := civicpass.NewVerifier(nullKey(t))
	if err != nil {
		t.Fatal(err)
	}
	attPub, attPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const attesterID = "civic-gatekeeper:uniqueness-v1"
	if err := v.TrustAttester(attesterID, attPub); err != nil {
		t.Fatal(err)
	}
	v.AllowClaim("proof-of-personhood")
	return v, v.AuthorityPublic(), attPriv, attesterID
}

func personhoodPass(attester, subject string, attPriv ed25519.PrivateKey) *civicpass.Attestation {
	now := time.Now().UTC()
	a := &civicpass.Attestation{
		Scheme:    civicpass.SchemeCivicPass,
		Attester:  attester,
		Subject:   subject,
		Claim:     "proof-of-personhood",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
	a.Sign(attPriv)
	return a
}

// End to end: verify a Civic pass, resolve it, verify the adapter assertion, and
// seal the anchor into a real CAT via the IdentityAnchor seam — the single place
// a real identity root plugs in. Also asserts the seam type is honored.
func TestSealsCivicAnchorIntoCAT(t *testing.T) {
	v, authPub, attPriv, attester := newVerifier(t)
	if err := v.Present(personhoodPass(attester, "wallet:So1aNa…alice", attPriv)); err != nil {
		t.Fatalf("present valid pass: %v", err)
	}

	var provider identityroot.Provider = v // used through the seam only
	a, err := provider.Resolve(context.Background(), "wallet:So1aNa…alice", "bank-A")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if a.Method != civicpass.SchemeCivicPass {
		t.Fatalf("method = %q, want %q", a.Method, civicpass.SchemeCivicPass)
	}
	if err := civicpass.VerifyAssertion(a, authPub); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}

	issPub, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 2, TTL: time.Hour, HolderPublicKey: holderPub,
		IdentityAnchor: a.Anchor.Bytes(), // ← the identity-root seam
	}, issPriv)
	if err != nil {
		t.Fatalf("issue CAT with civic anchor: %v", err)
	}
	if cat.HumanAnchor != a.Anchor {
		t.Fatalf("CAT humanAnchor %s != civic anchor %s", cat.HumanAnchor, a.Anchor)
	}
	claims, err := cattoken.Verify(cat.Token, issPub)
	if err != nil {
		t.Fatalf("verify CAT: %v", err)
	}
	if claims["human_anchor"] != a.Anchor.String() {
		t.Fatal("verified CAT does not carry the civic anchor")
	}
}

// The adapter mints nothing: every way an attestation can be untrustworthy must
// reject, and a subject with no verified attestation must not resolve.
func TestFailClosed(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)

	// No verified attestation for the subject.
	if _, err := v.Resolve(context.Background(), "wallet:nobody", "bank-A"); err == nil {
		t.Fatal("resolved a subject with no verified attestation")
	}

	// Untrusted attester.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := v.Present(personhoodPass("civic-gatekeeper:impostor", "wallet:a", otherPriv)); err == nil {
		t.Fatal("accepted an attestation from an untrusted attester")
	}

	// Disallowed claim.
	kyc := personhoodPass(attester, "wallet:b", attPriv)
	kyc.Claim = "some-unlisted-claim"
	kyc.Sign(attPriv)
	if err := v.Present(kyc); err == nil {
		t.Fatal("accepted a disallowed claim")
	}

	// Unsupported scheme.
	bad := personhoodPass(attester, "wallet:c", attPriv)
	bad.Scheme = "not-a-real-root"
	bad.Sign(attPriv)
	if err := v.Present(bad); err == nil {
		t.Fatal("accepted an unsupported scheme")
	}

	// Tampered signature (mutate a field after signing).
	tampered := personhoodPass(attester, "wallet:d", attPriv)
	tampered.Subject = "wallet:d-elevated"
	if err := v.Present(tampered); err == nil {
		t.Fatal("accepted a tampered attestation")
	}

	// Expired attestation (beyond leeway).
	expired := personhoodPass(attester, "wallet:e", attPriv)
	expired.IssuedAt = time.Now().Add(-2 * time.Hour)
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	expired.Sign(attPriv)
	if err := v.Present(expired); err == nil {
		t.Fatal("accepted an expired attestation")
	}

	// Empty context on resolve.
	if err := v.Present(personhoodPass(attester, "wallet:f", attPriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(context.Background(), "wallet:f", ""); err == nil {
		t.Fatal("resolved with an empty context")
	}
}

// Derived-nullifier path: stable per (subject, context), unlinkable across
// contexts, fresh anchor per issuance — the property SPT-Txn needs.
func TestNullifier_StablePerContext_UnlinkableAcross(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)
	if err := v.Present(personhoodPass(attester, "wallet:alice", attPriv)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	a1, _ := v.Resolve(ctx, "wallet:alice", "bank-A")
	a2, _ := v.Resolve(ctx, "wallet:alice", "bank-A")
	a3, _ := v.Resolve(ctx, "wallet:alice", "bank-B")

	if a1.Nullifier != a2.Nullifier {
		t.Fatal("nullifier not stable per (subject, context)")
	}
	if a1.Nullifier == a3.Nullifier {
		t.Fatal("nullifier identical across contexts — cross-context linkability")
	}
	if a1.Anchor == a2.Anchor {
		t.Fatal("anchor not freshly randomized per issuance")
	}
}

func TestNullifier_DistinctSubjects(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)
	_ = v.Present(personhoodPass(attester, "wallet:alice", attPriv))
	_ = v.Present(personhoodPass(attester, "wallet:bob", attPriv))
	a, _ := v.Resolve(context.Background(), "wallet:alice", "bank-A")
	b, _ := v.Resolve(context.Background(), "wallet:bob", "bank-A")
	if a.Nullifier == b.Nullifier {
		t.Fatal("distinct subjects produced the same nullifier in one context")
	}
}

// Native-nullifier path: when the identity root supplies its own per-context
// nullifier, the adapter uses it for the matching context and refuses others.
func TestNativeNullifier(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)

	native := make([]byte, 32)
	if _, err := rand.Read(native); err != nil {
		t.Fatal(err)
	}
	att := personhoodPass(attester, "wallet:carol", attPriv)
	att.NativeNullifier = native
	att.NullifierContext = "app-x"
	att.Sign(attPriv) // re-sign: native fields are covered by the signature
	if err := v.Present(att); err != nil {
		t.Fatalf("present native-nullifier pass: %v", err)
	}

	// Matching context resolves.
	if _, err := v.Resolve(context.Background(), "wallet:carol", "app-x"); err != nil {
		t.Fatalf("resolve matching native context: %v", err)
	}
	// Different context is refused (the native nullifier is bound to app-x).
	if _, err := v.Resolve(context.Background(), "wallet:carol", "app-y"); err == nil {
		t.Fatal("resolved a context the native nullifier is not bound to")
	}
}

// A native nullifier not covered by the signature must be rejected at Present.
func TestNativeNullifier_MustBeSigned(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)
	att := personhoodPass(attester, "wallet:dave", attPriv) // signed WITHOUT native fields
	att.NativeNullifier = []byte("injected-after-signing-................")
	att.NullifierContext = "app-x"
	if err := v.Present(att); err == nil {
		t.Fatal("accepted a native nullifier not covered by the attester signature")
	}
}

// The downstream adapter assertion must reject tampering and the wrong key.
func TestVerifyAssertion_Tamper(t *testing.T) {
	v, authPub, attPriv, attester := newVerifier(t)
	_ = v.Present(personhoodPass(attester, "wallet:alice", attPriv))
	a, err := v.Resolve(context.Background(), "wallet:alice", "bank-A")
	if err != nil {
		t.Fatal(err)
	}
	if err := civicpass.VerifyAssertion(a, authPub); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := civicpass.VerifyAssertion(a, otherPub); err == nil {
		t.Fatal("assertion verified under wrong authority key")
	}

	mutate := []func(x *identityroot.Assertion){
		func(x *identityroot.Assertion) { x.Anchor[0] ^= 1 },
		func(x *identityroot.Assertion) { x.Nullifier[0] ^= 1 },
		func(x *identityroot.Assertion) { x.Context = "bank-B" },
		func(x *identityroot.Assertion) { x.IssuedAt = x.IssuedAt.Add(time.Second) },
		func(x *identityroot.Assertion) { x.Method = civicpass.SchemeSAS },
	}
	for i, mut := range mutate {
		cp := *a
		cp.Proof = append([]byte(nil), a.Proof...)
		mut(&cp)
		if err := civicpass.VerifyAssertion(&cp, authPub); err == nil {
			t.Fatalf("mutation %d: tampered assertion verified", i)
		}
	}
}

// A personhood attestation must carry an expiry — a zero ExpiresAt would be
// infinitely valid and (with no cache revocation) resolve forever.
func TestPresent_RequiresExpiry(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)
	att := personhoodPass(attester, "wallet:noexp", attPriv)
	att.ExpiresAt = time.Time{} // no expiry
	att.Sign(attPriv)
	if err := v.Present(att); err == nil {
		t.Fatal("accepted an attestation with no expiry")
	}
}

// Revocation must actually revoke: once an attester is untrusted, an attestation
// already Presented under it must stop resolving (no Present-time cache bypass).
func TestResolve_UntrustedAttesterFailsClosed(t *testing.T) {
	v, _, attPriv, attester := newVerifier(t)
	if err := v.Present(personhoodPass(attester, "wallet:alice", attPriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(context.Background(), "wallet:alice", "bank-A"); err != nil {
		t.Fatalf("resolve before revocation: %v", err)
	}
	v.UntrustAttester(attester)
	if _, err := v.Resolve(context.Background(), "wallet:alice", "bank-A"); err == nil {
		t.Fatal("resolved after the attester was untrusted — revocation bypass")
	}
}
