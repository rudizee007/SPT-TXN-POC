package main

// Regression test for the exp-clamp skip (adversarial review 8, fix 6b).
//
// The clamp was `if rem := time.Until(id.ExpiresAt); rem > 0 && rem < ttl`,
// which SKIPPED the clamp entirely when rem <= 0 -- handing an already-expired
// attestation the full 15-minute default CAT. The longest-lived capability went
// to the least-alive proof.
//
// The path is reachable, not theoretical: internal/attest tolerates 30s of clock
// skew on exp (jwt.go, `now.After(exp.Add(leeway))` with leeway = clockSkew =
// 30s), so an SVID expired by less than that verifies successfully and arrives
// here with no remaining life to inherit.
//
// cmd/idp-bridge was fixed for this first; workload-bridge is its twin and kept
// the bug. Both halves of the pair are asserted here so the next fix to one is
// visibly owed to the other.

import (
	"net/http"
	"testing"
	"time"
)

func TestExchange_ExpiredAttestationIsRefusedNotGivenTheDefaultTTL(t *testing.T) {
	e := newEnv(t)
	now := time.Now()

	// Expired 10s ago: inside attest's 30s skew tolerance, so it verifies, and
	// under the old guard `rem > 0` was false and the clamp was skipped.
	attExp := now.Add(-10 * time.Second)
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now.Add(-time.Hour), attExp, e.svidPriv)

	rr := e.post(e.validParams(svid))
	if rr.Code == http.StatusOK {
		t.Fatal("SECURITY: an already-expired attestation was exchanged for a CAT")
	}
	assertDenied(t, rr, http.StatusForbidden)
}

// An attestation with no exp has no lifetime to inherit and nothing to clamp
// against, so it must not silently receive the full default TTL either.
func TestExchange_AttestationWithoutExpiryIsRefused(t *testing.T) {
	e := newEnv(t)
	now := time.Now()

	svid := mintJWT(e.kid, map[string]any{
		"sub": spiffeSubject,
		"aud": []string{testAudience},
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		// no exp
	}, e.svidPriv)

	rr := e.post(e.validParams(svid))
	if rr.Code == http.StatusOK {
		t.Fatal("SECURITY: an attestation with no expiry was exchanged for a CAT")
	}
}
