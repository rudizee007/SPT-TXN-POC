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
	"testing"
	"time"
)

// idp is a throwaway OpenID provider: it serves discovery + JWKS and mints
// RS256 tokens, so the verifier can be tested with no external Keycloak.
type idp struct {
	priv   *rsa.PrivateKey
	kid    string
	issuer string
	srv    *httptest.Server
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{priv: priv, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": i.issuer, "jwks_uri": i.issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
		eb := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		e := base64.RawURLEncoding.EncodeToString(eb)
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "use": "sig", "kid": i.kid, "alg": "RS256", "n": n, "e": e}},
		})
	})
	i.srv = httptest.NewServer(mux)
	i.issuer = i.srv.URL
	return i
}

func (i *idp) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := map[string]string{"alg": "RS256", "typ": "JWT", "kid": i.kid}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mintWithKid mints a token whose header names an arbitrary kid, so the
// cache-miss path can be driven from the caller's side of the trust boundary.
func (i *idp) mintWithKid(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	real := i.kid
	i.kid = kid
	defer func() { i.kid = real }()
	return i.mint(t, claims)
}

func (i *idp) stdClaims(extra map[string]any) map[string]any {
	c := map[string]any{
		"iss": i.issuer,
		"sub": "alice-uuid",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
		"aud": "spt-agent",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestVerify_Valid(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, err := NewVerifier(context.Background(), i.issuer, WithAudience("spt-agent"))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	tok := i.mint(t, i.stdClaims(map[string]any{"preferred_username": "alice"}))
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if claims.Str("sub") != "alice-uuid" || claims.Str("preferred_username") != "alice" {
		t.Fatalf("unexpected claims: %v", claims)
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, _ := NewVerifier(context.Background(), i.issuer)
	tok := i.mint(t, i.stdClaims(nil))
	// flip a character in the payload segment
	bad := []byte(tok)
	mid := len(bad) / 2
	if bad[mid] == 'A' {
		bad[mid] = 'B'
	} else {
		bad[mid] = 'A'
	}
	if _, err := v.Verify(context.Background(), string(bad)); err == nil {
		t.Error("verify accepted a tampered token")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, _ := NewVerifier(context.Background(), i.issuer)
	tok := i.mint(t, i.stdClaims(map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix())}))
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("verify accepted an expired token")
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, _ := NewVerifier(context.Background(), i.issuer)
	tok := i.mint(t, i.stdClaims(map[string]any{"iss": "https://evil.example.com"}))
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("verify accepted a token from the wrong issuer")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, _ := NewVerifier(context.Background(), i.issuer, WithAudience("spt-agent"))
	tok := i.mint(t, i.stdClaims(map[string]any{"aud": "some-other-client"}))
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("verify accepted a token for the wrong audience")
	}
}

func TestVerify_RejectsWrongKeySigner(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()
	v, _ := NewVerifier(context.Background(), i.issuer)
	// sign with a DIFFERENT key but keep the advertised kid
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": i.kid})
	cb, _ := json.Marshal(i.stdClaims(nil))
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(si))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, sum[:])
	tok := si + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("verify accepted a token signed by an unregistered key")
	}
}
