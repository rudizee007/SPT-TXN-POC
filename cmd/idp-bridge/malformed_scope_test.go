package main

import (
	"net/http"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

// A scope that is present but unusable must be REFUSED. Before this test it was
// indistinguishable from an omitted scope, and an omitted scope grants the full
// permitted ceiling — so a truncated body, a wrong content encoding, or a typo
// minted a CAT at the deployment's MAXIMUM authority. This is the one place in
// the service where a parse FAILURE produced a WIDER grant, and it is the shape
// of bug that a demo reviewer probes for first.
func TestIDPExchange_MalformedScopeIsDeniedNotWidened(t *testing.T) {
	e := newIDPEnv(t)

	malformed := map[string]string{
		"truncated object":      `{"max_amount":100`,
		"bare brace":            `{`,
		"not json":              `max_amount=100`,
		"json array":            `[]`,
		"json null":             `null`,
		"json string":           `"max_amount"`,
		"json number":           `100`,
		"json bool":             `true`,
		"trailing garbage":      `{"max_amount":100} drop table`,
		"two objects":           `{"max_amount":100}{"max_amount":10000}`,
		"nul byte":              "{\"max_amount\":100}\x00",
		"utf16-ish binary":      "\xff\xfe{\x00}",
		"whitespace then junk":  "   nope",
		"object missing quotes": `{max_amount:100}`,
	}

	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			p := e.validParams(e.token(nil))
			p["scope"] = raw
			rr := e.post(p)

			if rr.Code == http.StatusOK {
				claims, err := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
				if err == nil {
					t.Fatalf("a malformed scope was minted at scope %v", claims["capability_scope"])
				}
				t.Fatal("a malformed scope produced a 200")
			}
			assertDenied(t, rr, http.StatusBadRequest)
		})
	}
}

// A malformed request must not fall through to the IdP's spt_scope claim
// either: a client that asked for something and got it mangled must be told,
// not silently handed the identity provider's default.
func TestIDPExchange_MalformedScopeDoesNotFallBackToTheClaim(t *testing.T) {
	e := newIDPEnv(t)
	p := e.validParams(e.token(map[string]any{"spt_scope": map[string]any{"max_amount": float64(5000)}}))
	p["scope"] = `{"max_amount":100`
	assertDenied(t, e.post(p), http.StatusBadRequest)
}

// An spt_scope claim that is present but is not an object has the same shape of
// hazard: the type assertion failed silently and the grant fell through to the
// full ceiling.
func TestIDPExchange_NonObjectSptScopeClaimIsDenied(t *testing.T) {
	e := newIDPEnv(t)
	for name, claim := range map[string]any{
		"string": "max_amount=100",
		"number": float64(100),
		"array":  []any{"transfer"},
		"bool":   true,
	} {
		t.Run(name, func(t *testing.T) {
			p := e.validParams(e.token(map[string]any{"spt_scope": claim}))
			assertDenied(t, e.post(p), http.StatusForbidden)
		})
	}
}

// The fix must not over-deny: an absent scope, and an empty-object scope, are
// both legitimate and still yield the permitted ceiling.
func TestIDPExchange_AbsentAndEmptyScopeStillGrantTheCeiling(t *testing.T) {
	e := newIDPEnv(t)
	for name, raw := range map[string]string{
		"absent":       "",
		"whitespace":   "   ",
		"empty object": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := e.validParams(e.token(nil))
			if raw != "" {
				p["scope"] = raw
			}
			rr := e.post(p)
			if rr.Code != http.StatusOK {
				t.Fatalf("legitimate request refused: status %d (%s)", rr.Code, rr.Body.String())
			}
			claims, err := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			cs := claims["capability_scope"].(map[string]any)
			if cs["action"] != "transfer" || cs["max_amount"] != float64(10000) {
				t.Fatalf("ceiling not granted: %v", cs)
			}
		})
	}
}
