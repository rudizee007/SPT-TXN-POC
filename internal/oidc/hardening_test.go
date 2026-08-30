package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── the audience bound means aud, and only aud ────────────────────────────

// azp names the client that REQUESTED the token, so it rides on every token
// that client obtains for every resource. Accepting it as an audience match
// converts "which resource may consume this" into "which client asked for it",
// and those bound different things.
func TestAudience_AzpDoesNotSatisfyTheBound(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, err := NewVerifier(context.Background(), i.issuer, WithAudience("spt-agent"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("azp matching, aud naming another resource", func(t *testing.T) {
		tok := i.mint(t, i.stdClaims(map[string]any{
			"azp": "spt-agent",
			"aud": []any{"some-other-api", "account"},
		}))
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("a token for another resource was accepted because azp matched")
		}
	})

	t.Run("azp matching, no aud at all", func(t *testing.T) {
		c := i.stdClaims(map[string]any{"azp": "spt-agent"})
		delete(c, "aud")
		if _, err := v.Verify(context.Background(), i.mint(t, c)); err == nil {
			t.Fatal("a token with no aud was accepted because azp matched")
		}
	})

	t.Run("control: a correct aud still verifies", func(t *testing.T) {
		if _, err := v.Verify(context.Background(), i.mint(t, i.stdClaims(nil))); err != nil {
			t.Fatalf("a correctly-addressed token was refused: %v", err)
		}
	})
}

// ── discovery decides which keys are trusted, for the process lifetime ────

// newDiscovery serves a discovery document the test controls, so the checks
// that run against it can be driven directly.
func newDiscovery(t *testing.T, doc func(selfURL string) map[string]any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(doc(srv.URL))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The issuer member is required, not optional-if-present: a document that omits
// it must be refused rather than accepted unchecked, because the party that
// answers the request would otherwise decide whether the check runs at all.
func TestDiscovery_IssuerMemberIsRequired(t *testing.T) {
	srv := newDiscovery(t, func(self string) map[string]any {
		return map[string]any{"jwks_uri": self + "/jwks"} // no issuer
	})
	_, err := NewVerifier(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a discovery document with no issuer member was accepted")
	}
	if !strings.Contains(err.Error(), "declares no issuer") {
		t.Fatalf("wrong diagnosis: %v", err)
	}
}

func TestDiscovery_IssuerMismatchIsStillRefused(t *testing.T) {
	srv := newDiscovery(t, func(self string) map[string]any {
		return map[string]any{"issuer": "https://somewhere.else", "jwks_uri": self + "/jwks"}
	})
	if _, err := NewVerifier(context.Background(), srv.URL); err == nil {
		t.Fatal("a discovery document declaring a different issuer was accepted")
	}
}

// jwks_uri arrives inside the document being validated and decides which keys
// this verifier trusts. Off-origin means the document chooses the authority.
func TestDiscovery_JWKSURIMustShareTheIssuerOrigin(t *testing.T) {
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer attacker.Close()

	srv := newDiscovery(t, func(self string) map[string]any {
		return map[string]any{"issuer": self, "jwks_uri": attacker.URL + "/jwks"}
	})
	_, err := NewVerifier(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("a jwks_uri on a foreign origin was accepted")
	}
	if !strings.Contains(err.Error(), "not on the issuer's origin") {
		t.Fatalf("wrong diagnosis: %v", err)
	}
}

func TestIssuerScheme(t *testing.T) {
	t.Run("plaintext non-loopback is refused", func(t *testing.T) {
		_, err := NewVerifier(context.Background(), "http://idp.internal/realms/x")
		if err == nil {
			t.Fatal("a plaintext non-loopback issuer was accepted")
		}
		if !strings.Contains(err.Error(), "plaintext http") {
			t.Fatalf("wrong diagnosis: %v", err)
		}
	})
	t.Run("the opt-out is explicit and works", func(t *testing.T) {
		// Reaches discovery and fails there, not at the scheme check.
		_, err := NewVerifier(context.Background(), "http://127.0.0.1:1/x", WithInsecureIssuerScheme())
		if err != nil && strings.Contains(err.Error(), "plaintext http") {
			t.Fatal("WithInsecureIssuerScheme did not permit the scheme")
		}
	})
	t.Run("a non-http scheme is refused", func(t *testing.T) {
		if _, err := NewVerifier(context.Background(), "file:///etc/passwd"); err == nil {
			t.Fatal("a file:// issuer was accepted")
		}
	})
}

// A redirect is the server choosing where the next request goes — and both of
// these requests decide which keys are trusted.
func TestDiscovery_RedirectsAreNotFollowed(t *testing.T) {
	target := newDiscovery(t, func(self string) map[string]any {
		return map[string]any{"issuer": self, "jwks_uri": self + "/jwks"}
	})
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()

	_, err := NewVerifier(context.Background(), redirector.URL)
	if err == nil {
		t.Fatal("discovery followed a redirect to another host")
	}
	if !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("wrong diagnosis: %v", err)
	}
}

// ── the key set ages, and the refresh is not caller-driven ────────────────

// Refreshing only on a cache miss leaves the decision of whether a revoked key
// is still honoured to whoever chooses the kid — the presenter of the token.
func TestJWKS_StaleKeySetIsRefetchedBeforeUse(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, err := NewVerifier(context.Background(), i.issuer,
		WithJWKSMaxAge(time.Nanosecond), WithJWKSMinRefreshInterval(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	before := v.fetchedAt
	time.Sleep(2 * time.Millisecond)
	if _, err := v.Verify(context.Background(), i.mint(t, i.stdClaims(nil))); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.fetchedAt.After(before) {
		t.Fatal("a stale key set was used without being refetched")
	}
}

// The cache-miss path is reachable by an unauthenticated caller: the kid is a
// field of the token, read before the signature is checked.
func TestJWKS_UnknownKidDoesNotFetchOncePerRequest(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	var fetches int
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": i.issuer, "jwks_uri": i.issuer + "/jwks"})
	})
	_ = mux

	v, err := NewVerifier(context.Background(), i.issuer, WithJWKSMinRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fetches = 0
	start := v.attemptedAt
	for n := 0; n < 50; n++ {
		junk := i.mintWithKid(t, "kid-"+strings.Repeat("x", n%7+1), i.stdClaims(nil))
		_, _ = v.Verify(context.Background(), junk)
	}
	if v.attemptedAt.After(start) {
		fetches++
	}
	if fetches > 1 {
		t.Fatalf("50 unknown-kid tokens produced %d refresh attempts", fetches)
	}
	// And the diagnosis distinguishes "throttled" from "unknown key".
	_, err = v.Verify(context.Background(), i.mintWithKid(t, "another-unknown", i.stdClaims(nil)))
	if err == nil || !strings.Contains(err.Error(), "minimum refresh interval") {
		t.Fatalf("a throttled refresh was not diagnosed as one: %v", err)
	}
}

// ── the JWKS exponent is refused, not repaired ────────────────────────────

func TestJWK_ExponentIsRefusedRatherThanGuessed(t *testing.T) {
	for _, c := range []struct{ name, e, want string }{
		{"empty", "", "1..8"},
		{"over-long", "AAAAAAAAAAAA", "1..8"},
		{"even", "Ag", "not a usable RSA public exponent"},
		{"one", "AQ", "not a usable RSA public exponent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := rsaFromJWK(jwk{Kty: "RSA", Kid: "k", N: "AQAB", E: c.e})
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("wrong diagnosis: %v", err)
			}
		})
	}
}
