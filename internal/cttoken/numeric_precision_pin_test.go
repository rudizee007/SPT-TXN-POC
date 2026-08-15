package cttoken_test

// PINNED LIMITATION — numeric claims decode through float64.
//
// This file does not test that the code is correct. It tests that a known
// defect is still exactly as bad as we believe it to be, and it is written to
// FAIL the moment somebody fixes it. That is the point: the defect is invisible
// at every call site, so the only way to keep it visible is to assert it.
//
// WHAT IS WRONG. cttoken.Verify (and cattoken.Verify) decode claims with
// json.Unmarshal into map[string]any, which yields float64 for every JSON
// number. float64 represents every integer exactly only up to 2^53. Above that
// the decoded ceiling is the nearest representable double, which may be higher
// or lower than the value that was signed.
//
// WHY IT MATTERS, in three escalating ways:
//
//  1. The comparison is asymmetric. tbac.TxnScope deliberately carries the
//     TRANSACTION amount as json.Number — "the exact decimal string ... not
//     lossy float64 — important for large values like XRP drops (> 2^53)".
//     So the transaction side is exact and the ceiling side is not. An exact
//     value is being compared against a rounded one.
//
//  2. Rounding is not always downward. A ceiling can round UP, which widens
//     authority. 999999999999999999 wei becomes 1000000000000000000.
//     Economically trivial; structurally it is an issuer/verifier divergence on
//     the one number the grant is about.
//
//  3. verifier/engine.go passes uint64(maxAmt) — derived from that float64 —
//     as a PUBLIC INPUT to the ZK chain proof. So the proof can be bound to a
//     ceiling that is not the ceiling in the token.
//
// Nothing has surfaced because USD cents do not reach 2^53. Wei and drops do,
// routinely.
//
// THE FIX IS NOT HERE, deliberately. Decoding with UseNumber() flips the type
// of every numeric claim at once, and 16 non-test call sites currently assert
// .(float64) across cttoken, cattoken, txntoken, verifier, decision, statuslist
// and sdjwt — five of them trust boundary. Sixteen simultaneous behaviour
// changes in the authorization path is a spec-first change with an adversarial
// pass, not a quick follow-on. See docs/WORKITEM-numeric-claims.md.

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// unrepresentable is 2^53 + 1: the smallest positive integer a float64 cannot
// hold. It round-trips to 2^53.
const unrepresentable = int64(1)<<53 + 1

// A ceiling above 2^53 cannot be delegated AT ALL, and the error blames the
// wrong party.
//
// The first draft of this test expected mere imprecision — issue, verify, and
// compare the decoded ceiling. It failed, and the failure was the better
// finding: issuance is rejected outright. The parent CAT is signed carrying
// 2^53+1; decoding it yields 2^53; a child requesting the IDENTICAL value then
// exceeds a ceiling its parent never declared.
//
// This is fail-closed, so it is safe. It is also unusable — the chain cannot
// carry a ceiling in that range — and the diagnostic points at the child for a
// widening it did not attempt, which is the kind of message that costs an
// afternoon.
func TestPinnedLimitation_CeilingAboveTwoPow53CannotBeDelegated(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holder, _ := keypair(t)

	scope := cattoken.CapabilityScope{
		"action":     "payment",
		"max_amount": unrepresentable,
		"currency":   "USD",
	}
	cat := issueParentCAT(t, issuerPriv, holder, scope, 3)

	_, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		// Byte-identical to what the parent was signed with.
		RequestedScope:  tbac.Scope{"max_amount": unrepresentable},
		HolderPublicKey: holder,
		TTL:             5 * time.Minute,
	}, issuerPriv)

	if err == nil {
		t.Fatalf("PINNED LIMITATION HAS CHANGED: a ceiling of %d now delegates successfully.\n"+
			"That is the fix landing — delete this test and close\n"+
			"docs/WORKITEM-numeric-claims.md. Do not 'repair' the assertion to keep it passing.",
			unrepresentable)
	}

	// Pin the CAUSE, not just the rejection. The parent ceiling in the message
	// is 2^53 — the rounded value — which is what identifies decode precision as
	// the culprit rather than a genuine attenuation violation. If this substring
	// stops matching, re-read the error before adjusting anything.
	const roundedParent = "9007199254740992"
	const childAsked = "9007199254740993"
	msg := err.Error()
	if !strings.Contains(msg, roundedParent) || !strings.Contains(msg, childAsked) {
		t.Fatalf("expected the rejection to show the child asking for %s against a parent\n"+
			"ceiling of %s (the rounded value), proving decode precision is the cause.\n"+
			"got: %v", childAsked, roundedParent, err)
	}
	t.Logf("delegation of a 2^53+1 ceiling is refused, blaming the child: %v", err)
}

func TestPinnedLimitation_CeilingCanRoundUpwardWideningAuthority(t *testing.T) {
	// The direction that matters. Downward rounding is conservative — the
	// verifier enforces a ceiling slightly tighter than granted. Upward rounding
	// enforces one LOOSER than was signed, which is a widening of authority by
	// float representation rather than by any delegation step.
	//
	// This asserts the arithmetic directly. It is deliberately independent of
	// the token path so that it keeps describing the hazard even if issuance
	// changes shape.
	// Scan a small band of wei-scale integers and find one that rounds UP.
	// Asserting that at least one exists is the real claim; naming a single
	// magic constant would pin an accident of one value rather than the hazard.
	const base = int64(1_000_000_000_000_000_000) // 10^18 wei == 1 ETH
	var widened, examples int64
	for d := int64(-64); d <= 64; d++ {
		v := base + d
		if r := int64(float64(v)); r > v {
			widened++
			if examples < 3 {
				t.Logf("ceiling %d decodes as %d — %d MORE than was signed", v, r, r-v)
				examples++
			}
		}
	}
	if widened == 0 {
		t.Fatal("PINNED LIMITATION HAS CHANGED: no wei-scale ceiling in the sampled band " +
			"rounds upward. float64 no longer widens ceilings here — re-check whether the " +
			"decode path still uses float64 before trusting this.")
	}
	t.Logf("%d of 129 sampled wei-scale ceilings decode HIGHER than signed", widened)

	// The spacing of float64 at 10^18 is what makes this unavoidable, and it is
	// worth stating numerically: no fix at the comparison site helps, because
	// the value is already wrong by the time it is compared.
	spacing := math.Nextafter(float64(base), math.Inf(1)) - float64(base)
	t.Logf("float64 spacing at 10^18 is %.0f — every ceiling in that range is "+
		"quantised to a multiple of it", spacing)
	if spacing < 2 {
		t.Errorf("expected float64 spacing at 10^18 to exceed 1 wei, got %.0f", spacing)
	}
}
