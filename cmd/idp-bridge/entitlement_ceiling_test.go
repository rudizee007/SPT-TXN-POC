package main

// Regression test for the scope-widening bypass (adversarial review 8, fix 1).
//
// The IdP's spt_scope claim is the principal's ENTITLEMENT. It was consulted
// only when the request was absent, which made it skippable: any client could
// send a scope that narrowed nothing it cared about, and because the request was
// now non-nil the entitlement was never read -- the grant fell back to the
// deployment-wide `permitted` ceiling instead.
//
// Why no existing test caught it: TestIDPExchange_ScopePrecedence covers a
// request BELOW the claim (100 against 5000), where old and new logic agree.
// The discriminating case is the reverse -- a low entitlement and a request that
// does not mention the entitled dimension at all.

import (
	"net/http"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

func TestIDPExchange_EntitlementBoundsEvenWhenAScopeIsRequested(t *testing.T) {
	e := newIDPEnv(t)

	// This principal is entitled to 100 against a bridge permitting 10000.
	lowEntitlement := map[string]any{"spt_scope": map[string]any{"max_amount": float64(100)}}

	for _, c := range []struct {
		name, scope string
	}{
		// Each of these narrows something, or nothing, but none of them mentions
		// max_amount -- so under the old logic each one skipped the entitlement.
		{"narrows_a_different_dimension", `{"currency":"USD"}`},
		{"narrows_nothing_it_holds", `{"action":"transfer"}`},
		{"narrows_two_other_dimensions", `{"currency":"USD","action":"transfer"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := e.validParams(e.token(lowEntitlement))
			p["scope"] = c.scope

			rr := e.post(p)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d (%s)", rr.Code, rr.Body.String())
			}
			claims, err := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
			if err != nil {
				t.Fatal(err)
			}
			cs, ok := claims["capability_scope"].(map[string]any)
			if !ok {
				t.Fatalf("no capability_scope in the minted CAT: %v", claims)
			}
			if got := cs["max_amount"]; got != float64(100) {
				t.Fatalf("WIDENING: entitlement was 100, request did not mention max_amount, "+
					"CAT sealed max_amount=%v (the deployment ceiling is 10000)", got)
			}
		})
	}
}

// The mirror: an spt_scope claim cannot widen past the policy ceiling either.
func TestIDPExchange_EntitlementCannotExceedThePolicyCeiling(t *testing.T) {
	e := newIDPEnv(t)
	p := e.validParams(e.token(map[string]any{
		"spt_scope": map[string]any{"max_amount": float64(999999)},
	}))
	rr := e.post(p)
	if rr.Code != http.StatusOK {
		// Denial is an acceptable outcome; issuing above the ceiling is not.
		return
	}
	claims, err := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
	if err != nil {
		t.Fatal(err)
	}
	cs := claims["capability_scope"].(map[string]any)
	if got := cs["max_amount"]; got != float64(10000) {
		t.Fatalf("WIDENING: spt_scope asked for 999999 against a 10000 ceiling, got %v", got)
	}
}
