package main

// Fail-closed test matrix for the RFC 8693 IdP token-exchange endpoint. The
// external identity provider is a hermetic mock: an httptest TLS server that
// serves OIDC discovery + a JWKS whose RSA key signs the subject tokens. No
// live Keycloak/Okta is required.
//
// Invariants under test: deny-by-default on every malformed request or rejected
// subject token; the algorithm allowlist (RS256 only; alg:none rejected); exact
// issuer and (when configured) audience binding; a subject token with no `sub`
// yields no CAT; requested scope is a ceiling; and the raw IdP token is never
// logged.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/oidc"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

const testCATAudience = "spt-agents"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mintRS256(kid string, claims map[string]any, key *rsa.PrivateKey) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	si := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(si))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return si + "." + b64(sig)
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": b64(pub.N.Bytes()),
		"e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}
}

type idpEnv struct {
	handler   http.HandlerFunc
	issuer    string
	rsaPriv   *rsa.PrivateKey
	kid       string
	catPub    ed25519.PublicKey
	holderHex string
}

func newIDPEnv(t *testing.T) idpEnv {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "idp-k1"

	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(kid, &rsaPriv.PublicKey)}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	ver, err := oidc.NewVerifier(context.Background(), srv.URL,
		oidc.WithHTTPClient(srv.Client()),
		oidc.WithAudience(testCATAudience),
	)
	if err != nil {
		t.Fatalf("verifier setup: %v", err)
	}

	catPub, catPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)

	permitted := tbac.Scope{"action": "transfer", "max_amount": float64(10000), "currency": "USD"}
	return idpEnv{
		handler:   handleExchange(ver, catPriv, "domain-a.authorg", permitted),
		issuer:    srv.URL,
		rsaPriv:   rsaPriv,
		kid:       kid,
		catPub:    catPub,
		holderHex: hex.EncodeToString(holderPub),
	}
}

func (e idpEnv) token(claims map[string]any) string {
	base := map[string]any{
		"iss": e.issuer,
		"sub": "user-123",
		"aud": testCATAudience,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return mintRS256(e.kid, base, e.rsaPriv)
}

func (e idpEnv) validParams(tok string) map[string]string {
	return map[string]string{
		"grant_type":         grantTokenExchange,
		"subject_token":      tok,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"holder_key_hex":     e.holderHex,
	}
}

func (e idpEnv) post(params map[string]string) *httptest.ResponseRecorder {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.handler(rr, req)
	return rr
}

func body(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rr.Body.String())
	}
	return m
}

func assertDenied(t *testing.T, rr *httptest.ResponseRecorder, wantCode int) {
	t.Helper()
	if rr.Code != wantCode {
		t.Fatalf("status = %d, want %d (%s)", rr.Code, wantCode, rr.Body.String())
	}
	m := body(t, rr)
	if _, ok := m["access_token"]; ok {
		t.Fatalf("SECURITY: token issued on a denied request: %s", rr.Body.String())
	}
	if s, _ := m["error"].(string); s == "" {
		t.Fatalf("denied response carries no OAuth error: %s", rr.Body.String())
	}
}

func TestIDPExchange_Success(t *testing.T) {
	e := newIDPEnv(t)
	rr := e.post(e.validParams(e.token(nil)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	m := body(t, rr)
	access, _ := m["access_token"].(string)
	if access == "" {
		t.Fatal("no access_token on success")
	}
	if m["human_anchor"] == "" {
		t.Fatal("missing human_anchor")
	}
	claims, err := cattoken.Verify(access, e.catPub)
	if err != nil {
		t.Fatalf("issued CAT does not verify: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Fatalf("CAT sub = %v", claims["sub"])
	}
	if claims["holder_key"] != e.holderHex {
		t.Fatalf("holder binding lost: %v", claims["holder_key"])
	}
}

func TestIDPExchange_ScopePrecedence(t *testing.T) {
	e := newIDPEnv(t)

	t.Run("request_narrows_below_the_claim", func(t *testing.T) {
		// Request narrows max_amount to 100; the spt_scope claim asks for 5000.
		// The narrowest of policy (10000), entitlement (5000) and request (100)
		// wins, which is 100. Note this case does NOT test precedence: it gives
		// the same answer whether the entitlement bounds the grant or is merely a
		// fallback the request replaces. See
		// TestIDPExchange_EntitlementBoundsEvenWhenAScopeIsRequested for the
		// case that separates them.
		p := e.validParams(e.token(map[string]any{"spt_scope": map[string]any{"max_amount": float64(5000)}}))
		p["scope"] = `{"max_amount":100}`
		rr := e.post(p)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d (%s)", rr.Code, rr.Body.String())
		}
		claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
		if cs := claims["capability_scope"].(map[string]any); cs["max_amount"] != float64(100) {
			t.Fatalf("the narrowest bound did not win: %v", cs)
		}
	})

	t.Run("spt_scope_claim_fallback", func(t *testing.T) {
		p := e.validParams(e.token(map[string]any{"spt_scope": map[string]any{"max_amount": float64(2000)}}))
		rr := e.post(p)
		claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
		if cs := claims["capability_scope"].(map[string]any); cs["max_amount"] != float64(2000) {
			t.Fatalf("spt_scope claim not used: %v", cs)
		}
	})

	t.Run("conservative_default", func(t *testing.T) {
		// No request and no spt_scope: the grant is exactly the permitted ceiling.
		rr := e.post(e.validParams(e.token(nil)))
		claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
		if cs := claims["capability_scope"].(map[string]any); cs["action"] != "transfer" {
			t.Fatalf("default (ceiling) scope not applied: %v", cs)
		}
	})

	t.Run("request_exceeding_ceiling_denied", func(t *testing.T) {
		p := e.validParams(e.token(nil))
		p["scope"] = `{"action":"wire"}` // outside the permitted action
		assertDenied(t, e.post(p), http.StatusForbidden)
	})
}

func TestIDPExchange_FailClosed(t *testing.T) {
	e := newIDPEnv(t)

	t.Run("method_not_post", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rr := httptest.NewRecorder()
		e.handler(rr, req)
		assertDenied(t, rr, http.StatusMethodNotAllowed)
	})

	t.Run("wrong_grant_type", func(t *testing.T) {
		p := e.validParams(e.token(nil))
		p["grant_type"] = "client_credentials"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("missing_subject_token", func(t *testing.T) {
		p := e.validParams("")
		delete(p, "subject_token")
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("holder_key_malformed", func(t *testing.T) {
		p := e.validParams(e.token(nil))
		p["holder_key_hex"] = "nothex"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("garbage_subject_token", func(t *testing.T) {
		assertDenied(t, e.post(e.validParams("not.a.jwt")), http.StatusUnauthorized)
	})

	t.Run("wrong_signing_key", func(t *testing.T) {
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := mintRS256(e.kid, map[string]any{
			"iss": e.issuer, "sub": "user-123", "aud": testCATAudience,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}, otherKey)
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})

	t.Run("expired_token", func(t *testing.T) {
		tok := e.token(map[string]any{"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix()})
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})

	t.Run("wrong_issuer", func(t *testing.T) {
		tok := e.token(map[string]any{"iss": "https://evil.example"})
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})

	t.Run("wrong_audience", func(t *testing.T) {
		tok := e.token(map[string]any{"aud": "some-other-service"})
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})

	t.Run("alg_none_rejected", func(t *testing.T) {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": e.kid, "typ": "JWT"})
		c, _ := json.Marshal(map[string]any{"iss": e.issuer, "sub": "user-123", "aud": testCATAudience, "exp": time.Now().Add(time.Hour).Unix()})
		tok := b64(h) + "." + b64(c) + "."
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})

	t.Run("missing_sub", func(t *testing.T) {
		tok := e.token(map[string]any{"sub": nil})
		assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
	})
}

func TestIDPExchange_RawTokenNotLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	e := newIDPEnv(t)
	tok := e.token(nil)
	rr := e.post(e.validParams(tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(buf.String(), tok) {
		t.Fatal("SECURITY: raw IdP subject token leaked into logs")
	}
	if strings.Contains(rr.Body.String(), tok) {
		t.Fatal("SECURITY: raw IdP subject token echoed in the response")
	}
}

// The CAT must not outlive the IdP proof it was minted on: TTL is clamped down
// to the subject token's remaining life (remediation of the unbounded-TTL find).
func TestIDPExchange_TTLClampedToSubjectExp(t *testing.T) {
	e := newIDPEnv(t)
	subjExp := time.Now().Add(5 * time.Minute).Unix()
	tok := e.token(map[string]any{"exp": subjExp})
	p := e.validParams(tok)
	p["ttl_hours"] = "100" // request far longer than the proof lives

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
	catExp := int64(claims["exp"].(float64))
	if catExp > subjExp {
		t.Fatalf("SECURITY: CAT exp %d outlives subject-token exp %d", catExp, subjExp)
	}
}

// TTL is hard-capped even when the proof lives longer than the cap.
func TestIDPExchange_TTLCapped(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{"exp": time.Now().Add(48 * time.Hour).Unix()})
	p := e.validParams(tok)
	p["ttl_hours"] = "100000"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
	catExp := int64(claims["exp"].(float64))
	if catExp > time.Now().Add(maxCATTTL+time.Minute).Unix() {
		t.Fatalf("CAT exp %d exceeds the TTL cap", catExp)
	}
}

func TestIDPExchange_DelegationDepthCapped(t *testing.T) {
	e := newIDPEnv(t)
	p := e.validParams(e.token(nil))
	p["delegation_depth_max"] = "1000000"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(body(t, rr)["access_token"].(string), e.catPub)
	if depth := int(claims["delegation_depth_max"].(float64)); depth != maxDelegationDepth {
		t.Fatalf("delegation depth = %d, want clamp to %d", depth, maxDelegationDepth)
	}
}

// A subject token with no exp is rejected (oidc RequireExpiry remediation).
func TestIDPExchange_MissingExpRejected(t *testing.T) {
	e := newIDPEnv(t)
	tok := e.token(map[string]any{"exp": nil})
	assertDenied(t, e.post(e.validParams(tok)), http.StatusUnauthorized)
}

// Dry-run of a would-succeed IdP exchange: previews the decision, mints nothing.
func TestIDPExchange_DryRun_WouldIssue(t *testing.T) {
	e := newIDPEnv(t)
	p := e.validParams(e.token(nil))
	p["dry_run"] = "true"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	b := body(t, rr)
	if b["would_issue"] != true {
		t.Fatalf("would_issue = %v, want true", b["would_issue"])
	}
	if _, ok := b["access_token"]; ok {
		t.Fatal("SECURITY: dry-run produced an access_token")
	}
	if b["subject"] != "user-123" {
		t.Fatalf("subject = %v", b["subject"])
	}
}

// Dry-run of a would-deny IdP exchange: 200 preview, would_issue=false, no token.
func TestIDPExchange_DryRun_WouldDeny(t *testing.T) {
	e := newIDPEnv(t)
	p := e.validParams("not.a.jwt")
	p["dry_run"] = "true"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry-run should return a 200 preview, got %d (%s)", rr.Code, rr.Body.String())
	}
	b := body(t, rr)
	if b["would_issue"] != false {
		t.Fatalf("would_issue = %v, want false", b["would_issue"])
	}
	if _, ok := b["access_token"]; ok {
		t.Fatal("SECURITY: token present on a deny preview")
	}
	if b["decision_class"] != "violation" {
		t.Fatalf("decision_class = %v, want violation", b["decision_class"])
	}
}

// Ping OIDC compatibility — proves the bridge exchanges a real PingOne
// client_credentials (Worker app) token, the same OIDC + Token-Exchange flow
// already demonstrated against Keycloak and Auth0. The claim set below was
// captured from a live PingOne trial tenant. It exercises the Ping specifics:
//   - a JWKS carrying MULTIPLE keys (PingFederate duplicates the signing key
//     under different kids/algs), so the verifier must resolve strictly by kid;
//   - `aud` as an ARRAY and a PingOne-style issuer path (…/as);
//   - a machine/agent (M2M) token with NO `sub` — the authenticated principal is
//     the OAuth `client_id`, which the bridge uses as the subject.
//
// Hermetic: no live PingOne tenant needed. The live end-to-end runbook is in
// docs/PINGONE-IDP-INTEGRATION.md.
func TestIDPExchange_PingOneCompatibility(t *testing.T) {
	const sigKid = "ping-rs256"
	const decoyKid = "ping-legacy"
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	decoyKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/as/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	})
	mux.HandleFunc("/as/jwks", func(w http.ResponseWriter, _ *http.Request) {
		// Multiple keys, signing key NOT first — verifier must pick by kid.
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			rsaJWK(decoyKid, &decoyKey.PublicKey),
			rsaJWK(sigKid, &signKey.PublicKey),
		}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL + "/as" // PingOne-style issuer path

	ver, err := oidc.NewVerifier(context.Background(), issuer,
		oidc.WithHTTPClient(srv.Client()),
		oidc.WithAudience("https://api.pingone.com"), // the aud a PingOne token carries
	)
	if err != nil {
		t.Fatalf("verifier setup against Ping-shaped discovery failed: %v", err)
	}

	catPub, catPriv, _ := ed25519.GenerateKey(rand.Reader)
	holderPub, _, _ := ed25519.GenerateKey(rand.Reader)
	permitted := tbac.Scope{"action": "transfer", "max_amount": float64(10000), "currency": "USD"}
	h := handleExchange(ver, catPriv, "domain-a.authorg", permitted)

	// Real PingOne client_credentials (Worker app) token: NO `sub` — a machine /
	// agent identity carries `client_id`; `aud` is an array. RS256, kid = sigKid.
	const clientID = "128b7766-a360-4d1c-8838-daaab49e970a"
	tok := mintRS256(sigKid, map[string]any{
		"iss":       issuer,
		"client_id": clientID,
		"aud":       []any{"https://api.pingone.com"},
		"env":       "85430661-6d64-4256-b9ad-467e539124d4",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}, signKey)

	form := url.Values{}
	form.Set("grant_type", grantTokenExchange)
	form.Set("subject_token", tok)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("holder_key_hex", hex.EncodeToString(holderPub))
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("PingOne-shaped exchange failed: status %d (%s)", rr.Code, rr.Body.String())
	}
	access, _ := body(t, rr)["access_token"].(string)
	if access == "" {
		t.Fatal("no CAT issued for a valid PingOne-shaped token")
	}
	claims, err := cattoken.Verify(access, catPub)
	if err != nil {
		t.Fatalf("issued CAT does not verify: %v", err)
	}
	if claims["sub"] != clientID {
		t.Fatalf("CAT sub = %v, want the client_id (M2M subject)", claims["sub"])
	}
}
