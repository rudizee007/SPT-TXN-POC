package attest

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer serves a JWKS whose contents can be swapped to simulate key
// rotation, counting fetches to assert throttling.
type jwksServer struct {
	srv     *httptest.Server
	body    atomic.Value // []byte
	fetches int64
}

func edJWK(kid string, pub ed25519.PublicKey) jwk {
	return jwk{Kid: kid, Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
}

func newJWKSServer(t *testing.T, initial jwkSet) *jwksServer {
	t.Helper()
	js := &jwksServer{}
	b, _ := json.Marshal(initial)
	js.body.Store(b)
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&js.fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(js.body.Load().([]byte))
	}))
	t.Cleanup(js.srv.Close)
	return js
}

func (js *jwksServer) setKeys(set jwkSet) {
	b, _ := json.Marshal(set)
	js.body.Store(b)
}

func TestJWKSKeySource_FetchAndCache(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	js := newJWKSServer(t, jwkSet{Keys: []jwk{edJWK("k1", pub)}})

	src := NewJWKSKeySource(js.srv.URL, WithMinRefreshInterval(time.Hour))
	// First lookup fetches.
	got, err := src.Key(context.Background(), "k1", "EdDSA")
	if err != nil {
		t.Fatalf("k1 not resolved: %v", err)
	}
	if !got.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("wrong key returned")
	}
	// Second lookup is cached (no new fetch).
	if _, err := src.Key(context.Background(), "k1", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&js.fetches); n != 1 {
		t.Fatalf("expected 1 fetch (cached after), got %d", n)
	}
}

func TestJWKSKeySource_Rotation(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	js := newJWKSServer(t, jwkSet{Keys: []jwk{edJWK("k1", pub1)}})

	src := NewJWKSKeySource(js.srv.URL, WithMinRefreshInterval(0)) // no throttle for the test
	if _, err := src.Key(context.Background(), "k1", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	// Rotate: server now publishes k2; a lookup for the new kid triggers a
	// refresh and resolves.
	js.setKeys(jwkSet{Keys: []jwk{edJWK("k1", pub1), edJWK("k2", pub2)}})
	got, err := src.Key(context.Background(), "k2", "EdDSA")
	if err != nil {
		t.Fatalf("rotated key k2 not resolved: %v", err)
	}
	if !got.(ed25519.PublicKey).Equal(pub2) {
		t.Fatal("wrong rotated key")
	}
}

func TestJWKSKeySource_MissThrottled(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	js := newJWKSServer(t, jwkSet{Keys: []jwk{edJWK("k1", pub)}})

	src := NewJWKSKeySource(js.srv.URL, WithMinRefreshInterval(time.Hour))
	// Prime the cache (fetch #1).
	if _, err := src.Key(context.Background(), "k1", "EdDSA"); err != nil {
		t.Fatal(err)
	}
	// Repeated unknown-kid lookups must NOT each trigger a fetch (DoS guard).
	for i := 0; i < 5; i++ {
		if _, err := src.Key(context.Background(), "unknown", "EdDSA"); err == nil {
			t.Fatal("unknown kid resolved")
		}
	}
	if n := atomic.LoadInt64(&js.fetches); n != 1 {
		t.Fatalf("unknown-kid flood caused %d fetches; want 1 (throttled)", n)
	}
}

func TestJWKSKeySource_EndToEndSVID(t *testing.T) {
	// A JWKS-backed source verifies a real SPIFFE JWT-SVID.
	pub, priv, _ := ed25519.GenerateKey(nil)
	js := newJWKSServer(t, jwkSet{Keys: []jwk{edJWK("k1", pub)}})
	src := NewJWKSKeySource(js.srv.URL)

	tok := mintJWT(t, "EdDSA", "k1", priv, svidClaims(time.Now()))
	id, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, src)
	if err != nil {
		t.Fatalf("JWKS-backed SVID verification failed: %v", err)
	}
	if id.TrustDomain != "prod.example" {
		t.Fatalf("trust domain %q", id.TrustDomain)
	}
}
