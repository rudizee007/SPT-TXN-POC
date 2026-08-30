package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

// A scope that is present but unusable must be REFUSED. It used to be
// indistinguishable from an omitted scope, and an omitted scope grants the full
// permitted ceiling — so a truncated body or a wrong content encoding minted an
// attested CAT at the deployment's MAXIMUM authority. A parse failure must never
// widen a grant.
func TestExchange_MalformedScopeIsDeniedNotWidened(t *testing.T) {
	e := newEnv(t)
	now := time.Now()

	malformed := map[string]string{
		"truncated object":      `{"max_amount":50`,
		"bare brace":            `{`,
		"not json":              `max_amount=50`,
		"json array":            `[]`,
		"json null":             `null`,
		"json string":           `"max_amount"`,
		"json number":           `50`,
		"json bool":             `false`,
		"trailing garbage":      `{"max_amount":50} and more`,
		"two objects":           `{"max_amount":50}{"max_amount":10000}`,
		"nul byte":              "{\"max_amount\":50}\x00",
		"object missing quotes": `{max_amount:50}`,
	}

	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
			p := e.validParams(svid)
			p["scope"] = raw

			rr := e.post(p)
			if rr.Code == http.StatusOK {
				claims, err := cattoken.Verify(decodeBody(t, rr)["access_token"].(string), e.catPub)
				if err == nil {
					t.Fatalf("a malformed scope was minted at scope %v", claims["capability_scope"])
				}
				t.Fatal("a malformed scope produced a 200")
			}
			assertDenied(t, rr, http.StatusBadRequest)
		})
	}
}

// The fix must not over-deny: an absent scope and an empty object are both
// legitimate and still yield the permitted ceiling.
func TestExchange_AbsentAndEmptyScopeStillGrantTheCeiling(t *testing.T) {
	e := newEnv(t)
	now := time.Now()

	for name, raw := range map[string]string{
		"absent":       "",
		"whitespace":   "  ",
		"empty object": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
			p := e.validParams(svid)
			if raw != "" {
				p["scope"] = raw
			}
			rr := e.post(p)
			if rr.Code != http.StatusOK {
				t.Fatalf("legitimate request refused: status %d (%s)", rr.Code, rr.Body.String())
			}
			claims, err := cattoken.Verify(decodeBody(t, rr)["access_token"].(string), e.catPub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			cs := claims["capability_scope"].(map[string]any)
			if cs["action"] != "transfer" || cs["max_amount"] != float64(10000) || cs["currency"] != "USD" {
				t.Fatalf("ceiling not granted: %v", cs)
			}
		})
	}
}
