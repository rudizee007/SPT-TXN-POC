package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── the requested scope ───────────────────────────────────────────────────

// `{}` restricts nothing, so it is the absence of a request written out, and it
// must read that way consistently: an empty object may not count as PRESENT for
// the purpose of skipping the IdP entitlement claim while counting as ABSENT for
// the purpose of narrowing. One reading, both times.
func TestScope_EmptyObjectDoesNotSuppressTheIdPClaim(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{
		"spt_scope": map[string]any{"max_amount": float64(100)},
	})

	for _, requested := range []string{"", "{}", "  {}  "} {
		t.Run("scope="+requested, func(t *testing.T) {
			p := e.validParams(tok)
			if requested != "" {
				p["scope"] = requested
			}
			p["dry_run"] = "true"
			rr := e.post(p)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
			}
			granted, _ := body(t, rr)["granted_scope"].(map[string]any)
			if granted == nil {
				t.Fatalf("no granted_scope: %s", rr.Body.String())
			}
			if got := granted["max_amount"]; got != float64(100) {
				t.Fatalf("max_amount = %v, want the IdP claim's 100 — the entitlement claim was skipped", got)
			}
		})
	}
}

// The request narrows FURTHER than the entitlement, and the narrower value is
// what gets sealed. Renamed from "...StillOverridesTheClaim", which described
// the model review 8 removed: the request never overrides the entitlement, it
// composes with it (policy, then entitlement, then request, each narrowing).
// This case cannot tell the two models apart -- 50 is below the claim's 100, so
// both answer 50 -- and the old name read as licence to reintroduce the bypass.
// TestIDPExchange_EntitlementBoundsEvenWhenAScopeIsRequested is the case that
// does discriminate.
func TestScope_ARequestMayNarrowFurtherThanTheClaim(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{"spt_scope": map[string]any{"max_amount": float64(100)}})
	p := e.validParams(tok)
	p["scope"] = `{"max_amount":50}`
	p["dry_run"] = "true"
	rr := e.post(p)
	granted, _ := body(t, rr)["granted_scope"].(map[string]any)
	if granted["max_amount"] != float64(50) {
		t.Fatalf("max_amount = %v, want the request's narrower 50", granted["max_amount"])
	}
}

// ── the subject token type ────────────────────────────────────────────────

// Without this, every RS256 JWT the issuer signs is the same input: access
// token, ID token, refresh token, logout token.
func TestSubjectTokenType_IsRequiredAndAllowlisted(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(nil)

	for _, c := range []struct {
		name, value string
	}{
		{"absent", ""},
		{"id token", "urn:ietf:params:oauth:token-type:id_token"},
		{"refresh token", "urn:ietf:params:oauth:token-type:refresh_token"},
		{"saml", "urn:ietf:params:oauth:token-type:saml2"},
		{"nonsense", "please"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := e.validParams(tok)
			if c.value == "" {
				delete(p, "subject_token_type")
			} else {
				p["subject_token_type"] = c.value
			}
			assertDenied(t, e.post(p), http.StatusBadRequest)
		})
	}

	for _, ok := range []string{tokenTypeAccessToken, tokenTypeJWT} {
		t.Run("accepted: "+ok, func(t *testing.T) {
			p := e.validParams(tok)
			p["subject_token_type"] = ok
			if rr := e.post(p); rr.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// ── the subject token's remaining life ────────────────────────────────────

// The verifier tolerates clock skew either side of exp, so a token can arrive
// already past it. Such a token has no remaining life for the CAT to inherit,
// which makes it a denial rather than an input the clamp can do anything with.
func TestSubjectToken_ExpiredInsideTheSkewWindowIsDenied(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{"exp": time.Now().Add(-30 * time.Second).Unix()})
	assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
}

func TestSubjectToken_ShortLifeStillClampsRatherThanDenying(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{"exp": time.Now().Add(90 * time.Second).Unix()})
	rr := e.post(e.validParams(tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("a live short-lived token was denied: %s", rr.Body.String())
	}
	exp, _ := body(t, rr)["expires_in"].(float64)
	if exp <= 0 || exp > 120 {
		t.Fatalf("expires_in = %v, want it clamped to the subject token's ~90s", exp)
	}
}

// ── ttl_hours ─────────────────────────────────────────────────────────────

// time.Duration is int64 nanoseconds, so a large hour count wraps negative and
// slips past a `> max` cap, producing an allow-shaped response carrying a token
// that was already expired when it was signed.
func TestTTLHours_OverflowDoesNotProduceAnAllowShapedDeadToken(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(nil)
	for _, h := range []string{"2562048", "9223372036854775807", "999999999999"} {
		t.Run("ttl_hours="+h, func(t *testing.T) {
			p := e.validParams(tok)
			p["ttl_hours"] = h
			rr := e.post(p)
			if rr.Code != http.StatusOK {
				return // a refusal is also acceptable; a 200 with a dead token is not
			}
			exp, _ := body(t, rr)["expires_in"].(float64)
			if exp <= 0 {
				t.Fatalf("200 response carrying expires_in = %v", exp)
			}
			if exp > float64(maxCATTTL/time.Second) {
				t.Fatalf("expires_in = %v exceeds maxCATTTL", exp)
			}
		})
	}
}

// ── where credentials may travel ──────────────────────────────────────────

// r.Form merges the URL query, which would let a bearer identity assertion be
// supplied in the request line — where every proxy and trace on the path records
// it (RFC 6750 §2.3).
func TestParams_QueryStringIsNotACredentialChannel(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(nil)
	q := "/token?grant_type=" + grantTokenExchange +
		"&subject_token=" + tok +
		"&subject_token_type=" + tokenTypeAccessToken +
		"&holder_key_hex=" + e.holderHex
	req := httptest.NewRequest(http.MethodPost, q, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.handler(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("a credential supplied in the request line was honoured: %s", rr.Body.String())
	}
}

// ── the holder key ────────────────────────────────────────────────────────

// Demonstrate the property BEFORE asserting the refusal, so the test documents
// why these encodings are special rather than asserting a magic constant.
func TestHolderKey_DegenerateEncodingsAreRefused(t *testing.T) {
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 0x01 // R = the neutral element, S = 0

	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 0x01
	zeros := make([]byte, ed25519.PublicKeySize)

	// Measured, not assumed: the neutral element accepts the forgery for every
	// message, the all-zero encoding for roughly one in four. See
	// internal/cattoken.degenerateHolderKeys for the numbers.
	for _, k := range [][]byte{identity, zeros} {
		hits := 0
		for i := 0; i < 200; i++ {
			if ed25519.Verify(ed25519.PublicKey(k), []byte(fmt.Sprintf("probe-%d", i)), forged) {
				hits++
			}
		}
		if hits == 0 {
			t.Fatalf("premise failed: %x accepted the forgery for none of 200 messages on this "+
				"toolchain — re-derive the set before trusting this test", k[:4])
		}
	}

	e := newIDPEnv(t)
	tok := e.token(nil)
	for _, k := range [][]byte{identity, zeros} {
		t.Run(hex.EncodeToString(k[:4]), func(t *testing.T) {
			p := e.validParams(tok)
			p["holder_key_hex"] = hex.EncodeToString(k)
			rr := e.post(p)
			if rr.Code == http.StatusOK {
				t.Fatalf("a holder key that constrains nobody was sealed into a CAT: %s", rr.Body.String())
			}
		})
	}

	t.Run("control: a real key is still accepted", func(t *testing.T) {
		if rr := e.post(e.validParams(tok)); rr.Code != http.StatusOK {
			t.Fatalf("a real holder key was refused: %s", rr.Body.String())
		}
	})
}
