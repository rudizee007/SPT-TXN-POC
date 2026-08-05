package main

// Fail-closed test matrix for the RFC 8693 workload token-exchange endpoint
// (SPT-Txn P4, spec docs/spec/NHI-ATTESTED-ISSUANCE.md). Every test is hermetic:
// SVID/SA/OIDC assertions are minted in-process and signed by a key registered
// in a StaticKeySource, so no SPIRE agent or cloud IdP is required.
//
// The invariants under test:
//   - deny-by-default: any malformed request, rejected attestation, or predicate
//     failure returns an OAuth error and issues NO token;
//   - audience is enforced twice — the endpoint audience (anti cross-service
//     replay of the request) AND the assertion's own aud (anti replay of a
//     workload assertion minted for another RP);
//   - a minted CAT never outlives the attestation it was sealed on (spec §4);
//   - the sealed evidence_digest is exactly SHA-256(tag||0x00||presented bytes);
//   - the raw workload assertion is never logged nor echoed downstream.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

const (
	testAudience  = "spt-txn-exchange"
	testIssuer    = "https://oidc.example"
	spiffeSubject = "spiffe://prod.example/ns/pay/sa/charger"
	ttSPIFFE      = "urn:violetsky:token-type:spiffe-jwt-svid"
	ttK8s         = "urn:violetsky:token-type:k8s-sa"
	ttAWS         = "urn:violetsky:token-type:aws-irsa"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signCompact builds a compact JWS from raw header/payload bytes (so tests can
// inject malformed payloads such as duplicate members).
func signCompact(headerJSON, payloadJSON []byte, priv ed25519.PrivateKey) string {
	si := b64(headerJSON) + "." + b64(payloadJSON)
	sig := ed25519.Sign(priv, []byte(si))
	return si + "." + b64(sig)
}

// mintJWT signs an EdDSA JWT with the given kid over the given claims.
func mintJWT(kid string, claims map[string]any, priv ed25519.PrivateKey) string {
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	return signCompact(h, c, priv)
}

// wantEvidenceDigest recomputes the spec §3 evidence digest for asserting the
// value the handler sealed into the CAT.
func wantEvidenceDigest(evidence string) string {
	h := sha256.New()
	h.Write([]byte("spt-txn-attest-v1"))
	h.Write([]byte{0x00})
	h.Write([]byte(evidence))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

type env struct {
	h         *handler
	kid       string
	svidPriv  ed25519.PrivateKey
	catPub    ed25519.PublicKey
	holderHex string
}

func newEnv(t *testing.T) env {
	t.Helper()
	svidPub, svidPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catPub, catPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "svid-k1"
	ks := attest.NewStaticKeySource(map[string]crypto.PublicKey{kid: svidPub})
	h := &handler{
		ks:             ks,
		priv:           catPriv,
		catIssuer:      "domain-a.authorg",
		expectedIssuer: testIssuer,
		audience:       testAudience,
		permitted:      tbac.Scope{"action": "transfer", "max_amount": float64(10000), "currency": "USD"},
	}
	return env{h: h, kid: kid, svidPriv: svidPriv, catPub: catPub, holderHex: hex.EncodeToString(holderPub)}
}

// spiffeSVID mints a SPIFFE JWT-SVID valid from ~now until exp, bound to aud.
func (e env) spiffeSVID(sub string, aud []string, iat, exp time.Time, priv ed25519.PrivateKey) string {
	return mintJWT(e.kid, map[string]any{
		"sub": sub,
		"aud": aud,
		"iat": iat.Unix(),
		"nbf": iat.Add(-time.Minute).Unix(),
		"exp": exp.Unix(),
	}, priv)
}

func (e env) validParams(svid string) map[string]string {
	return map[string]string{
		"grant_type":         grantTokenExchange,
		"subject_token":      svid,
		"subject_token_type": ttSPIFFE,
		"audience":           testAudience,
		"holder_key_hex":     e.holderHex,
	}
}

func (e env) post(params map[string]string) *httptest.ResponseRecorder {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.h.exchange(rr, req)
	return rr
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rr.Body.String())
	}
	return m
}

// assertDenied asserts a fail-closed outcome: non-2xx, an OAuth error, and
// crucially NO access_token in the body.
func assertDenied(t *testing.T, rr *httptest.ResponseRecorder, wantCode int) {
	t.Helper()
	if rr.Code != wantCode {
		t.Fatalf("status = %d, want %d (body %s)", rr.Code, wantCode, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if _, ok := body["access_token"]; ok {
		t.Fatalf("SECURITY: token issued on a denied request: %s", rr.Body.String())
	}
	if s, _ := body["error"].(string); s == "" {
		t.Fatalf("denied response carries no OAuth error: %s", rr.Body.String())
	}
}

func TestExchange_SPIFFE_Success(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)

	rr := e.post(e.validParams(svid))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatal("no access_token issued on success")
	}
	if body["attestation_method"] != "spiffe-jwt-svid" {
		t.Fatalf("attestation_method = %v", body["attestation_method"])
	}
	if body["attested_subject"] != spiffeSubject {
		t.Fatalf("attested_subject = %v", body["attested_subject"])
	}

	// The CAT verifies under the issuer key and carries a correct sealed seal.
	claims, err := cattoken.Verify(access, e.catPub)
	if err != nil {
		t.Fatalf("issued CAT does not verify: %v", err)
	}
	att, ok := claims["spt_attestation"].(map[string]any)
	if !ok {
		t.Fatal("CAT missing spt_attestation seal")
	}
	if att["method"] != "spiffe-jwt-svid" || att["subject"] != spiffeSubject {
		t.Fatalf("seal mismatch: %v", att)
	}
	if att["evidence_digest"] != wantEvidenceDigest(svid) {
		t.Fatalf("sealed evidence_digest is not SHA-256 of the presented SVID")
	}
	if att["trust_domain"] != "prod.example" {
		t.Fatalf("sealed trust_domain = %v", att["trust_domain"])
	}
	// Holder binding + subject namespacing.
	if claims["holder_key"] != e.holderHex {
		t.Fatalf("holder_key = %v, want %s", claims["holder_key"], e.holderHex)
	}
	if claims["sub"] != "workload:"+spiffeSubject {
		t.Fatalf("CAT sub = %v", claims["sub"])
	}
	// Default scope applied when none requested.
	if cs, _ := claims["capability_scope"].(map[string]any); cs["action"] != "transfer" {
		t.Fatalf("default scope not applied: %v", claims["capability_scope"])
	}
}

// The CAT must never outlive the attestation it was minted on (spec §4): the
// issuer clamps TTL down to the remaining attestation lifetime.
func TestExchange_CATNeverOutlivesAttestation(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	// Attestation expires in 5 min — well under the 15-min default CAT TTL.
	attExp := now.Add(5 * time.Minute)
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, attExp, e.svidPriv)

	rr := e.post(e.validParams(svid))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	access := decodeBody(t, rr)["access_token"].(string)
	claims, err := cattoken.Verify(access, e.catPub)
	if err != nil {
		t.Fatal(err)
	}
	catExp := int64(claims["exp"].(float64))
	if catExp > attExp.Unix() {
		t.Fatalf("SECURITY: CAT exp %d outlives attestation exp %d", catExp, attExp.Unix())
	}
}

// A request narrows within the permitted ceiling: max_amount 50 < 10000 is
// honored, and the dimensions the request omits (action, currency) are carried
// from the ceiling — the root must not drop them.
func TestExchange_RequestNarrowsWithinCeiling(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
	p := e.validParams(svid)
	p["scope"] = `{"max_amount":50}`

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(decodeBody(t, rr)["access_token"].(string), e.catPub)
	cs := claims["capability_scope"].(map[string]any)
	if cs["max_amount"] != float64(50) {
		t.Fatalf("max_amount not narrowed to request: %v", cs["max_amount"])
	}
	if cs["action"] != "transfer" || cs["currency"] != "USD" {
		t.Fatalf("root dropped a permitted ceiling dimension: %v", cs)
	}
}

// A request above a numeric ceiling is clamped down, never honored.
func TestExchange_RequestAboveCeilingClamped(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
	p := e.validParams(svid)
	p["scope"] = `{"max_amount":1000000000}`

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(decodeBody(t, rr)["access_token"].(string), e.catPub)
	if cs := claims["capability_scope"].(map[string]any); cs["max_amount"] != float64(10000) {
		t.Fatalf("SECURITY: request above ceiling not clamped: %v", cs["max_amount"])
	}
}

// A request for a dimension the policy does not permit, or a conflicting value
// on an equality dimension, is denied — the issuer will not grant unheld
// authority.
func TestExchange_ScopeExceedingPolicyDenied(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)

	t.Run("unpermitted_dimension", func(t *testing.T) {
		p := e.validParams(svid)
		p["scope"] = `{"admin":true}`
		assertDenied(t, e.post(p), http.StatusForbidden)
	})

	t.Run("conflicting_action", func(t *testing.T) {
		p := e.validParams(svid)
		p["scope"] = `{"action":"wire"}`
		assertDenied(t, e.post(p), http.StatusForbidden)
	})
}

func TestExchange_K8s_Success(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	tok := mintJWT(e.kid, map[string]any{
		"iss": testIssuer,
		"sub": "system:serviceaccount:pay:charger",
		"aud": []string{testAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}, e.svidPriv)
	p := e.validParams(tok)
	p["subject_token_type"] = ttK8s

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	if decodeBody(t, rr)["attestation_method"] != "k8s-sa" {
		t.Fatal("k8s method not sealed")
	}
}

func TestExchange_AWSIRSA_Success(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	tok := mintJWT(e.kid, map[string]any{
		"iss": testIssuer,
		"sub": "arn:aws:iam::123456789012:role/charger",
		"aud": []string{testAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}, e.svidPriv)
	p := e.validParams(tok)
	p["subject_token_type"] = ttAWS

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	if decodeBody(t, rr)["attestation_method"] != "aws-irsa" {
		t.Fatal("aws-irsa method not sealed")
	}
}

func TestExchange_FailClosed(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	goodSVID := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)

	t.Run("method_not_post", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rr := httptest.NewRecorder()
		e.h.exchange(rr, req)
		assertDenied(t, rr, http.StatusMethodNotAllowed)
	})

	t.Run("wrong_grant_type", func(t *testing.T) {
		p := e.validParams(goodSVID)
		p["grant_type"] = "authorization_code"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("endpoint_audience_mismatch", func(t *testing.T) {
		p := e.validParams(goodSVID)
		p["audience"] = "some-other-endpoint"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("holder_key_missing", func(t *testing.T) {
		p := e.validParams(goodSVID)
		delete(p, "holder_key_hex")
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("holder_key_malformed", func(t *testing.T) {
		p := e.validParams(goodSVID)
		p["holder_key_hex"] = "zzzz"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("holder_key_wrong_length", func(t *testing.T) {
		p := e.validParams(goodSVID)
		p["holder_key_hex"] = "abcd"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("unknown_subject_token_type", func(t *testing.T) {
		p := e.validParams(goodSVID)
		p["subject_token_type"] = "urn:violetsky:token-type:make-believe"
		assertDenied(t, e.post(p), http.StatusBadRequest)
	})

	t.Run("attestation_wrong_signing_key", func(t *testing.T) {
		_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
		svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), wrongPriv)
		assertDenied(t, e.post(e.validParams(svid)), http.StatusUnauthorized)
	})

	t.Run("assertion_audience_mismatch", func(t *testing.T) {
		// Endpoint audience is correct, but the SVID was minted for another RP.
		svid := e.spiffeSVID(spiffeSubject, []string{"some-other-rp"}, now, now.Add(time.Hour), e.svidPriv)
		assertDenied(t, e.post(e.validParams(svid)), http.StatusUnauthorized)
	})

	t.Run("attestation_expired", func(t *testing.T) {
		svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now.Add(-2*time.Hour), now.Add(-time.Hour), e.svidPriv)
		assertDenied(t, e.post(e.validParams(svid)), http.StatusUnauthorized)
	})

	t.Run("non_spiffe_subject", func(t *testing.T) {
		svid := e.spiffeSVID("https://not-spiffe.example/x", []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
		assertDenied(t, e.post(e.validParams(svid)), http.StatusUnauthorized)
	})

	t.Run("duplicate_json_member", func(t *testing.T) {
		// Two "sub" members: json.Unmarshal is last-wins, but VerifyJWT rejects
		// duplicates so the token can't mean different things to two parsers.
		hdr, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": e.kid, "typ": "JWT"})
		payload := []byte(`{"sub":"spiffe://prod.example/ns/pay/sa/a","sub":"spiffe://prod.example/ns/pay/sa/b","aud":["` + testAudience + `"],"iat":` +
			strconv.FormatInt(now.Unix(), 10) + `,"exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `}`)
		svid := signCompact(hdr, payload, e.svidPriv)
		assertDenied(t, e.post(e.validParams(svid)), http.StatusUnauthorized)
	})

	t.Run("stale_attestation_freshness", func(t *testing.T) {
		// Valid but issued an hour ago; a 60s freshness predicate must DENY.
		svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now.Add(-time.Hour), now.Add(time.Hour), e.svidPriv)
		p := e.validParams(svid)
		p["requested_max_age_s"] = "60"
		assertDenied(t, e.post(p), http.StatusForbidden)
	})

	t.Run("k8s_wrong_issuer", func(t *testing.T) {
		tok := mintJWT(e.kid, map[string]any{
			"iss": "https://evil.example",
			"sub": "system:serviceaccount:pay:charger",
			"aud": []string{testAudience},
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}, e.svidPriv)
		p := e.validParams(tok)
		p["subject_token_type"] = ttK8s
		assertDenied(t, e.post(p), http.StatusUnauthorized)
	})

	t.Run("generic_oidc_masquerading_as_k8s_sa", func(t *testing.T) {
		// Correct issuer/aud/sig, but sub is not a serviceaccount subject.
		tok := mintJWT(e.kid, map[string]any{
			"iss": testIssuer,
			"sub": "just-some-user",
			"aud": []string{testAudience},
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}, e.svidPriv)
		p := e.validParams(tok)
		p["subject_token_type"] = ttK8s
		assertDenied(t, e.post(p), http.StatusUnauthorized)
	})
}

// The raw workload assertion must never appear in logs or be echoed downstream —
// only its evidence digest is retained (spec §6).
func TestExchange_RawAssertionNotLeaked(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
	rr := e.post(e.validParams(svid))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(buf.String(), svid) {
		t.Fatal("SECURITY: raw SVID leaked into logs")
	}
	if strings.Contains(rr.Body.String(), svid) {
		t.Fatal("SECURITY: raw SVID echoed in the exchange response")
	}
}

// A caller cannot request an unbounded delegation fan-out — depth is clamped to
// maxDelegationDepth (remediation of the scope/depth-widening finding).
func TestExchange_DelegationDepthCapped(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
	p := e.validParams(svid)
	p["delegation_depth_max"] = "1000000"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	claims, _ := cattoken.Verify(decodeBody(t, rr)["access_token"].(string), e.catPub)
	depth := int(claims["delegation_depth_max"].(float64))
	if depth != maxDelegationDepth {
		t.Fatalf("delegation depth = %d, want clamp to %d", depth, maxDelegationDepth)
	}
}

// Dry-run of a would-succeed exchange: reports the decision and the scope it
// WOULD grant, but mints no token — structurally, the preview branch returns
// before cattoken.Issue is ever called.
func TestExchange_DryRun_WouldIssue(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), e.svidPriv)
	p := e.validParams(svid)
	p["dry_run"] = "true"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	b := decodeBody(t, rr)
	if b["would_issue"] != true {
		t.Fatalf("would_issue = %v, want true", b["would_issue"])
	}
	if _, ok := b["access_token"]; ok {
		t.Fatal("SECURITY: dry-run produced an access_token")
	}
	if b["attested_subject"] != spiffeSubject {
		t.Fatalf("attested_subject = %v", b["attested_subject"])
	}
	if b["granted_scope"] == nil {
		t.Fatal("preview missing granted_scope")
	}
}

// Dry-run of a would-deny exchange: 200 preview with would_issue=false and NO
// token, rather than a live 4xx.
func TestExchange_DryRun_WouldDeny(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	svid := e.spiffeSVID(spiffeSubject, []string{testAudience}, now, now.Add(time.Hour), wrongPriv)
	p := e.validParams(svid)
	p["dry_run"] = "true"

	rr := e.post(p)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry-run should return a 200 preview, got %d (%s)", rr.Code, rr.Body.String())
	}
	b := decodeBody(t, rr)
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
