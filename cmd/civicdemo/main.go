// Command civicdemo drives the REAL identity-root adapter (internal/civicpass)
// end to end, in-process, with real cryptography, narrating each step:
//
//	go run ./cmd/civicdemo
//
// The point it makes: SPT-Txn's identity root is a swappable dependency. Here a
// shipping root — Civic Pass / the Solana Attestation Service — is wired into the
// exact seam a future .zkdid would fill, so the Solana hackathon ships today and
// is not blocked on any one provider's timeline.
//
// The narrative:
//  1. A stand-in Civic/SAS attester issues a signed proof-of-personhood
//     attestation for a subject wallet (in production this is an on-chain Civic
//     Pass / SAS attestation account).
//  2. The relying party's civicpass.Verifier trusts that attester and allow-lists
//     the claim, then VERIFIES the attestation (fail-closed) — and REFUSES an
//     impostor. The adapter mints no personhood; it verifies someone else's.
//  3. Resolve the same subject in two contexts (bank-A, bank-B): the context
//     nullifier is stable within a context (Sybil detection) but diverges across
//     them (relying parties cannot correlate the person), and the anchor is fresh
//     each issuance.
//  4. Verify the adapter's assertion signature; a tampered one is rejected.
//  5. Seal the anchor into a real CAT via the IdentityAnchor seam and verify the
//     CAT carries exactly that anchor.
//  6. Swap the provider: the labelled mock (internal/zkdidmock) drives the SAME
//     issuance code through the SAME interface, unchanged — that is the seam.
//
// Everything here is exercised by the package tests; this program is the guided
// tour, not a substitute for them.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/civicpass"
	"github.com/rudizee007/spt-txn-poc/internal/identityroot"
	"github.com/rudizee007/spt-txn-poc/internal/zkdidmock"
)

const (
	issCAT     = "domain-a.authorg"               // the CAT issuer (a KYC provider / SAS attester in production)
	attesterID = "civic-gatekeeper:uniqueness-v1" // the trusted Civic gatekeeper network / SAS credential
	subject    = "So1anaWa11et:demo-alice"        // stable subject ref — stays INSIDE the adapter
	claim      = "proof-of-personhood"
)

func main() {
	ctx := context.Background()

	banner("SPT-Txn — real identity root (Civic Pass / Solana Attestation Service)")
	fmt.Println("The identity root is a swappable dependency. Watch a shipping root plug into")
	fmt.Println("the same seam a future .zkdid would fill — verified, not asserted, then sealed")
	fmt.Println("into a transaction-scoped CAT. Offline, with real signatures.")

	// Keys: the CAT issuer, and the attester standing in for the on-chain root.
	catPub, catPriv := genKey()
	attPub, attPriv := genKey()

	// ── 1. the identity root issues an attestation ─────────────────────
	step(1, "A Civic/SAS attester issues a signed proof-of-personhood attestation")
	att := &civicpass.Attestation{
		Scheme:    civicpass.SchemeCivicPass,
		Attester:  attesterID,
		Subject:   subject,
		Claim:     claim,
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	att.Sign(attPriv) // in production: an on-chain Civic Pass / SAS attestation, not our signature
	fmt.Printf("   scheme           : %s\n", att.Scheme)
	fmt.Printf("   claim            : %s (attester %s)\n", att.Claim, att.Attester)
	fmt.Printf("   subject ref      : %s  — never leaves the adapter\n", att.Subject)

	// ── 2. the relying party verifies it (fail-closed) ─────────────────
	step(2, "The relying party VERIFIES the attestation — and refuses an impostor")
	v, authPub, err := civicpass.NewVerifier(mustRandom(32))
	check(err, "new verifier")
	check(v.TrustAttester(attesterID, attPub), "trust attester")
	v.AllowClaim(claim)

	check(v.Present(att), "present valid attestation")
	fmt.Printf("   valid pass       : %s\n", okStr(true))

	// An attestation from an untrusted attester must be refused — the trust
	// anchor is Civic/SAS, not this adapter.
	_, impostorPriv := genKey()
	impostor := &civicpass.Attestation{
		Scheme: civicpass.SchemeCivicPass, Attester: "civic-gatekeeper:impostor",
		Subject: "So1anaWa11et:mallory", Claim: claim,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	impostor.Sign(impostorPriv)
	if err := v.Present(impostor); err != nil {
		fmt.Printf("   impostor pass    : REFUSED (%v)\n", err)
	} else {
		fail("impostor attestation was accepted")
	}

	// ── 3. resolve in two contexts — nullifiers diverge ────────────────
	step(3, "Resolve the same human in two contexts — the nullifier diverges")
	var prov identityroot.Provider = v // used only through the seam from here

	a1, err := prov.Resolve(ctx, subject, "bank-A")
	check(err, "resolve bank-A")
	a1b, err := prov.Resolve(ctx, subject, "bank-A")
	check(err, "resolve bank-A again")
	a2, err := prov.Resolve(ctx, subject, "bank-B")
	check(err, "resolve bank-B")

	fmt.Printf("   bank-A nullifier : %s\n", short(a1.Nullifier[:]))
	fmt.Printf("   bank-A (again)   : %s  %s\n", short(a1b.Nullifier[:]), tag(a1.Nullifier == a1b.Nullifier, "stable → Sybil-detectable"))
	fmt.Printf("   bank-B nullifier : %s  %s\n", short(a2.Nullifier[:]), tag(a1.Nullifier != a2.Nullifier, "differs → uncorrelatable"))
	fmt.Printf("   anchors          : %s  %s\n", short(a1.Anchor.Bytes()), tag(a1.Anchor != a1b.Anchor, "fresh each issuance → unlinkable"))
	if a1.Nullifier != a1b.Nullifier || a1.Nullifier == a2.Nullifier || a1.Anchor == a1b.Anchor {
		fail("nullifier/anchor properties violated")
	}

	// ── 4. verify the adapter assertion ────────────────────────────────
	step(4, "Verify the adapter's assertion signature; a tampered one is rejected")
	check(civicpass.VerifyAssertion(a1, authPub), "verify assertion")
	fmt.Printf("   assertion        : %s\n", okStr(true))
	tampered := *a1
	tampered.Nullifier[0] ^= 0xFF
	if err := civicpass.VerifyAssertion(&tampered, authPub); err != nil {
		fmt.Printf("   tampered         : REJECTED (%v)\n", err)
	} else {
		fail("tampered assertion verified")
	}

	// ── 5. seal into a CAT via the seam ────────────────────────────────
	step(5, "Seal the anchor into a transaction-scoped CAT and verify it carries it")
	anchorHex := sealViaSeam(ctx, prov, subject, "bank-A", catPub, catPriv)
	fmt.Printf("   CAT humanAnchor  : %s…  %s\n", anchorHex[:24], okStr(true))

	// ── 6. swap the provider — issuance code unchanged ─────────────────
	step(6, "Swap the provider: the mock drives the SAME issuance through the SAME seam")
	mock, mockPub, err := zkdidmock.NewMockProvider()
	check(err, "new mock provider")
	check(mock.Enroll("demo-alice"), "enroll in mock")
	var mockProv identityroot.Provider = mock
	ma, err := mockProv.Resolve(ctx, "demo-alice", "bank-A")
	check(err, "mock resolve")
	check(zkdidmock.VerifyAssertion(ma, mockPub), "verify mock assertion")
	mockAnchor := sealViaSeam(ctx, mockProv, "demo-alice", "bank-A", catPub, catPriv)
	fmt.Printf("   mock CAT anchor  : %s…  %s\n", mockAnchor[:24], okStr(true))
	fmt.Printf("   same code path   : civicpass and zkdidmock both fill identityroot.Provider\n")

	banner("Done — a shipping identity root, verified and sealed, behind a swappable seam.")
	fmt.Println("Civic/SAS today; .zkdid later; the issuance code never changes.")
}

// sealViaSeam is the ONE piece of issuance code both providers drive. It takes
// any identityroot.Provider, resolves an anchor, seals it as a CAT humanAnchor,
// and confirms the verified CAT carries exactly that anchor. That it is provider-
// agnostic is the whole point of the seam.
func sealViaSeam(ctx context.Context, prov identityroot.Provider, subjectRef, contextLabel string, issPub ed25519.PublicKey, issPriv ed25519.PrivateKey) string {
	a, err := prov.Resolve(ctx, subjectRef, contextLabel)
	check(err, "resolve via seam")
	holderPub, _ := genKey()
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCAT, Subject: "principal:demo", PrincipalName: "demo",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 5000, "currency": "USD"},
		DelegationDepthMax: 2, TTL: 4 * time.Minute, HolderPublicKey: holderPub,
		IdentityAnchor: a.Anchor.Bytes(), // ← the identity-root seam
	}, issPriv)
	check(err, "issue CAT")
	if cat.HumanAnchor != a.Anchor {
		fail("CAT humanAnchor does not match the resolved anchor")
	}
	claims, err := cattoken.Verify(cat.Token, issPub)
	check(err, "verify CAT")
	if claims["human_anchor"] != a.Anchor.String() {
		fail("verified CAT does not carry the resolved anchor")
	}
	return a.Anchor.String()
}

// ── helpers ────────────────────────────────────────────────────────────

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err, "keygen")
	return pub, priv
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fail("random: %v", err)
	}
	return b
}

func short(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 16 {
		h = h[:16] + "…"
	}
	return h
}

func tag(ok bool, msg string) string {
	if ok {
		return "\033[32m" + msg + "\033[0m"
	}
	return "\033[31mFAILED: " + msg + "\033[0m"
}

func banner(s string) { fmt.Printf("\n\033[1m%s\033[0m\n%s\n", s, line(len(s))) }
func line(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}
func step(n int, s string) { fmt.Printf("\n[%d] %s\n", n, s) }

func okStr(ok bool) string {
	if ok {
		return "\033[32mverified\033[0m"
	}
	return "\033[31mFAILED\033[0m"
}

func check(err error, what string) {
	if err != nil {
		fail("%s: %v", what, err)
	}
}
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\ndemo failed: "+format+"\n", args...)
	os.Exit(1)
}
