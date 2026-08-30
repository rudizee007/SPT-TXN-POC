package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Auth0 conformance, hermetic.
//
// No tenant, no network, no credentials: a local server shaped like Auth0 and
// tokens shaped like Auth0's, so the claim "this bridge accepts Auth0" is
// something CI re-proves on every run rather than something a document asserts.
//
// The shapes are taken from Auth0's published access-token profiles:
//
//   - Auth0 profile (the DEFAULT): header typ "JWT"; claims iss, aud, azp, sub,
//     scope, gty. No client_id.
//   - RFC 9068 profile (opt-in per API): header typ "at+jwt"; claims iss, aud,
//     client_id, sub, scope, jti. No azp, no gty.
//
// Two Auth0 specifics drive most of what follows. The issuer carries a TRAILING
// SLASH (`https://tenant.eu.auth0.com/`) and so does the `iss` claim. And an
// Auth0 ID token's `aud` is the CLIENT ID, while an API access token's `aud` is
// the API identifier — which makes `SPT_IDP_AUDIENCE` the field that decides
// whether an ID token is exchangeable.

const (
	auth0APIIdentifier = "https://api.spt-txn.example/v1"
	auth0ClientID      = "auth0-test-client-id-NOT-A-REAL-TENANT"
	// ^ deliberately unmistakable. The previous fixture was a random
	// 32-char alnum string shaped exactly like a real Auth0 client ID, which
	// tripped gitleaks (generic-api-key, entropy 5.0) and blocked a commit.
	// A high-entropy fixture is indistinguishable from a leaked credential to
	// the scanner AND to a human reviewer, and allowlisting it would have
	// taught the scanner to ignore exactly the shape it exists to catch.
	// Nothing here validates client-id FORMAT, so the fixture is free to say
	// what it is.
	auth0UserSub = "auth0|6510f2c9b4a1e3d7c2f8a9b0"
)

// auth0IDP is a throwaway provider shaped like an Auth0 tenant: discovery
// declares an issuer WITH a trailing slash, and jwks_uri sits at Auth0's path
// on the same origin.
type auth0IDP struct {
	priv *rsa.PrivateKey
	kid  string
	srv  *httptest.Server
}

// origin is the tenant URL without the trailing slash — what an operator would
// put in SPT_IDP_OIDC_ISSUER.
func (a *auth0IDP) origin() string { return a.srv.URL }

// issuerClaim is what Auth0 actually puts in `iss` and in the discovery
// document: the origin plus a trailing slash.
func (a *auth0IDP) issuerClaim() string { return a.srv.URL + "/" }

func newAuth0IDP(t *testing.T) *auth0IDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	a := &auth0IDP{priv: priv, kid: "auth0-test-kid"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 a.issuerClaim(),
			"jwks_uri":               a.srv.URL + "/.well-known/jwks.json",
			"token_endpoint":         a.srv.URL + "/oauth/token",
			"authorization_endpoint": a.srv.URL + "/authorize",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "kid": a.kid, "alg": "RS256", "n": n, "e": e,
			}},
		})
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

// mint signs a token with an explicit header `typ`, so both Auth0 profiles can
// be produced.
func (a *auth0IDP) mint(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ, "kid": a.kid})
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (a *auth0IDP) times() (int64, int64) {
	now := time.Now()
	return now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix()
}

// m2mAccessToken is the Auth0-profile client-credentials token: the shape an AI
// agent or a Worker app presents. Note `sub` is PRESENT and ends "@clients".
func (a *auth0IDP) m2mAccessToken(t *testing.T, aud string) string {
	iat, exp := a.times()
	return a.mint(t, "JWT", map[string]any{
		"iss":   a.issuerClaim(),
		"sub":   auth0ClientID + "@clients",
		"aud":   aud,
		"azp":   auth0ClientID,
		"scope": "payments:execute",
		"gty":   "client-credentials",
		"iat":   iat,
		"exp":   exp,
	})
}

// userAccessToken is the Auth0-profile authorization-code token: a human login.
func (a *auth0IDP) userAccessToken(t *testing.T, aud string) string {
	iat, exp := a.times()
	return a.mint(t, "JWT", map[string]any{
		"iss":                a.issuerClaim(),
		"sub":                auth0UserSub,
		"aud":                aud,
		"azp":                auth0ClientID,
		"scope":              "openid profile payments:execute",
		"preferred_username": "rudi",
		"iat":                iat,
		"exp":                exp,
	})
}

// rfc9068AccessToken is the opt-in profile: typ "at+jwt", client_id in place of
// azp, no gty.
func (a *auth0IDP) rfc9068AccessToken(t *testing.T, aud string) string {
	iat, exp := a.times()
	return a.mint(t, "at+jwt", map[string]any{
		"iss":       a.issuerClaim(),
		"sub":       auth0ClientID + "@clients",
		"aud":       aud,
		"client_id": auth0ClientID,
		"scope":     "payments:execute",
		"jti":       "9f2c7a1e4b8d",
		"iat":       iat,
		"exp":       exp,
	})
}

// idToken is the artifact that must never be exchangeable. Its `aud` is the
// CLIENT ID, and in a browser deployment it is the token most widely handed to
// code that is not the client.
func (a *auth0IDP) idToken(t *testing.T) string {
	iat, exp := a.times()
	return a.mint(t, "JWT", map[string]any{
		"iss":   a.issuerClaim(),
		"sub":   auth0UserSub,
		"aud":   auth0ClientID,
		"azp":   auth0ClientID,
		"nonce": "n-0S6_WzA2Mj",
		"iat":   iat,
		"exp":   exp,
	})
}

func newAuth0Verifier(t *testing.T, a *auth0IDP, audience string) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), a.origin(),
		WithAudience(audience), WithInsecureIssuerScheme())
	if err != nil {
		t.Fatalf("NewVerifier against an Auth0-shaped tenant: %v", err)
	}
	return v
}

// The tenant issuer carries a trailing slash in both the discovery document and
// the `iss` claim; the operator configures it without one. Discovery must
// accept that, and so must the issuer check on every token.
func TestAuth0_TrailingSlashIssuerIsAccepted(t *testing.T) {
	a := newAuth0IDP(t)
	if !strings.HasSuffix(a.issuerClaim(), "/") {
		t.Fatal("fixture is not exercising the trailing slash")
	}
	v := newAuth0Verifier(t, a, auth0APIIdentifier)
	if _, err := v.Verify(context.Background(), a.userAccessToken(t, auth0APIIdentifier)); err != nil {
		t.Fatalf("a token whose iss carries Auth0's trailing slash was refused: %v", err)
	}
}

func TestAuth0_AccessTokensVerify(t *testing.T) {
	a := newAuth0IDP(t)
	v := newAuth0Verifier(t, a, auth0APIIdentifier)
	for name, tok := range map[string]string{
		"machine-to-machine, Auth0 profile": a.m2mAccessToken(t, auth0APIIdentifier),
		"user login, Auth0 profile":         a.userAccessToken(t, auth0APIIdentifier),
		"machine-to-machine, RFC 9068":      a.rfc9068AccessToken(t, auth0APIIdentifier),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tok); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// An Auth0 ID token's aud is the client id. Bound to the API identifier — the
// correct configuration — it is refused, which is the property the whole
// exchange rests on.
func TestAuth0_IDTokenIsNotExchangeable(t *testing.T) {
	a := newAuth0IDP(t)
	v := newAuth0Verifier(t, a, auth0APIIdentifier)
	if _, err := v.Verify(context.Background(), a.idToken(t)); err == nil {
		t.Fatal("an ID token was accepted as a subject token")
	}
}

// The same defect A-1 described, in Auth0 clothing: azp is present on every
// Auth0 token its client obtains, so if azp could satisfy the bound audience,
// one API's token would be exchangeable at another's endpoint.
func TestAuth0_AzpDoesNotSatisfyTheAudience(t *testing.T) {
	a := newAuth0IDP(t)
	// Bound to the client id — the value azp carries.
	v := newAuth0Verifier(t, a, auth0ClientID)
	tok := a.m2mAccessToken(t, "https://some-other-api.example/v1")
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a token for another API was accepted because its azp matched the bound audience")
	}
}

// The trap, asserted rather than left to be discovered in a deployment.
//
// SPT_IDP_AUDIENCE must be the Auth0 API IDENTIFIER. Set to the client id — a
// natural mistake, and the value azp and an ID token's aud both carry — the ID
// token becomes exchangeable and the guarantee above is silently gone. Nothing
// in the verifier can distinguish the two; only the operator can.
func TestAuth0_AudienceBoundToTheClientIDAdmitsTheIDToken(t *testing.T) {
	a := newAuth0IDP(t)
	v := newAuth0Verifier(t, a, auth0ClientID)
	if _, err := v.Verify(context.Background(), a.idToken(t)); err != nil {
		t.Skipf("misconfiguration no longer reachable (%v) — if this is now enforced, "+
			"delete this test and say so in the Auth0 runbook", err)
	}
	t.Log("documented: binding SPT_IDP_AUDIENCE to the Auth0 client id, rather than the " +
		"API identifier, makes the ID token exchangeable. The Auth0 runbook must say so.")
}

// The premise the bridge's human/machine discrimination has to rest on.
//
// cmd/idp-bridge currently reads: "A machine-to-machine or agent token minted
// via client_credentials has no `sub`". That is not true of Auth0 — the sub is
// present and ends "@clients" — so absence of sub cannot be the discriminator.
// gty (Auth0 profile) and client_id (RFC 9068 profile) can be.
func TestAuth0_M2MTokenCarriesSubSoAbsenceIsNotTheDiscriminator(t *testing.T) {
	a := newAuth0IDP(t)
	v := newAuth0Verifier(t, a, auth0APIIdentifier)

	m2m, err := v.Verify(context.Background(), a.m2mAccessToken(t, auth0APIIdentifier))
	if err != nil {
		t.Fatalf("m2m: %v", err)
	}
	if sub := m2m.Str("sub"); sub == "" {
		t.Fatal("fixture wrong: an Auth0 client-credentials token does carry sub")
	} else if !strings.HasSuffix(sub, "@clients") {
		t.Fatalf("sub = %q, want the Auth0 machine form ending @clients", sub)
	}
	if gty := m2m.Str("gty"); gty != "client-credentials" {
		t.Fatalf("gty = %q, want client-credentials — the Auth0-profile discriminator", gty)
	}

	user, err := v.Verify(context.Background(), a.userAccessToken(t, auth0APIIdentifier))
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if !strings.HasPrefix(user.Str("sub"), "auth0|") {
		t.Fatalf("user sub = %q, want the Auth0 human form", user.Str("sub"))
	}
	if user.Str("gty") != "" {
		t.Fatal("a user token must not carry gty")
	}

	nine, err := v.Verify(context.Background(), a.rfc9068AccessToken(t, auth0APIIdentifier))
	if err != nil {
		t.Fatalf("rfc9068: %v", err)
	}
	if nine.Str("client_id") != auth0ClientID {
		t.Fatal("the RFC 9068 profile carries client_id in place of azp")
	}
	if nine.Str("azp") != "" || nine.Str("gty") != "" {
		t.Fatal("the RFC 9068 profile carries neither azp nor gty")
	}
}

// Recorded, not asserted as safe: the header `typ` is not read anywhere. Both
// Auth0 profiles verify identically whatever it says, so `typ` is not today a
// defence and the RFC 9068 opt-in changes nothing about what is accepted.
func TestAuth0_HeaderTypIsNotInspected(t *testing.T) {
	a := newAuth0IDP(t)
	v := newAuth0Verifier(t, a, auth0APIIdentifier)
	iat, exp := a.times()
	tok := a.mint(t, "this-is-not-a-token-type", map[string]any{
		"iss": a.issuerClaim(), "sub": auth0UserSub, "aud": auth0APIIdentifier,
		"iat": iat, "exp": exp,
	})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Skipf("typ is now inspected (%v) — update the Auth0 runbook and delete this test", err)
	}
	t.Log("documented: the JWT header typ is not inspected; an at+jwt and a JWT are " +
		"treated identically. Discrimination is by claims, not by typ.")
}
