package attest

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// ── JWT minting helpers (test-only) ─────────────────────────────────────

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mintJWT(t *testing.T, alg, kid string, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	hdr := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)

	var sig []byte
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(signingInput))
	case "RS256":
		sum := sha256.Sum256([]byte(signingInput))
		s, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	return signingInput + "." + b64(sig)
}

// mintRawJWT builds a token from pre-serialized header/payload JSON so tests
// can inject alg:none and duplicate keys that json.Marshal won't produce.
func mintRawJWT(headerJSON, payloadJSON string, sig []byte) string {
	return b64([]byte(headerJSON)) + "." + b64([]byte(payloadJSON)) + "." + b64(sig)
}

func edSource(t *testing.T, kid string) (ed25519.PrivateKey, KeySource) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, NewStaticKeySource(map[string]crypto.PublicKey{kid: pub})
}

func svidClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub": "spiffe://prod.example/ns/pay/sa/charger",
		"aud": []any{"spt-txn-exchange"},
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

// ── SPIFFE JWT-SVID ─────────────────────────────────────────────────────

func TestSPIFFEJWTSVID_Valid(t *testing.T) {
	now := time.Now()
	priv, ks := edSource(t, "k1")
	tok := mintJWT(t, "EdDSA", "k1", priv, svidClaims(now))

	id, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks)
	if err != nil {
		t.Fatalf("valid SVID rejected: %v", err)
	}
	if id.Subject != "spiffe://prod.example/ns/pay/sa/charger" {
		t.Fatalf("subject %q", id.Subject)
	}
	if id.TrustDomain != "prod.example" {
		t.Fatalf("trust domain %q", id.TrustDomain)
	}
	if id.EvidenceDigest == "" {
		t.Fatal("no evidence digest")
	}
	// Seal must be shaped and carry the digest, no raw token.
	seal := id.SealClaim()
	if seal["evidence_digest"] != id.EvidenceDigest || seal["method"] != string(MethodSPIFFEJWTSVID) {
		t.Fatalf("bad seal %v", seal)
	}
}

func TestSPIFFEJWTSVID_Rejections(t *testing.T) {
	now := time.Now()
	priv, ks := edSource(t, "k1")

	t.Run("alg none", func(t *testing.T) {
		// Unsigned token with alg:none must be rejected before key lookup.
		payload, _ := json.Marshal(svidClaims(now))
		tok := mintRawJWT(`{"alg":"none","typ":"JWT"}`, string(payload), nil)
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrAlg) {
			t.Fatalf("alg:none accepted (err=%v)", err)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		tok := mintJWT(t, "EdDSA", "k1", priv, svidClaims(now))
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"other-endpoint"}, ks); !errors.Is(err, ErrAudience) {
			t.Fatalf("wrong audience accepted (err=%v)", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := svidClaims(now)
		c["exp"] = now.Add(-10 * time.Minute).Unix()
		c["iat"] = now.Add(-20 * time.Minute).Unix()
		tok := mintJWT(t, "EdDSA", "k1", priv, c)
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired accepted (err=%v)", err)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		c := svidClaims(now)
		c["nbf"] = now.Add(10 * time.Minute).Unix()
		tok := mintJWT(t, "EdDSA", "k1", priv, c)
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("nbf-future accepted (err=%v)", err)
		}
	})

	t.Run("non-spiffe subject", func(t *testing.T) {
		c := svidClaims(now)
		c["sub"] = "not-a-spiffe-id"
		tok := mintJWT(t, "EdDSA", "k1", priv, c)
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrSubject) {
			t.Fatalf("non-spiffe subject accepted (err=%v)", err)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		_, otherKS := edSource(t, "k1") // different key under same kid
		tok := mintJWT(t, "EdDSA", "k1", priv, svidClaims(now))
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, otherKS); !errors.Is(err, ErrSignature) {
			t.Fatalf("bad signature accepted (err=%v)", err)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		tok := mintJWT(t, "EdDSA", "k99", priv, svidClaims(now))
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrKey) {
			t.Fatalf("unknown kid accepted (err=%v)", err)
		}
	})

	t.Run("audience required", func(t *testing.T) {
		tok := mintJWT(t, "EdDSA", "k1", priv, svidClaims(now))
		if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, nil, ks); !errors.Is(err, ErrAudience) {
			t.Fatalf("missing audience requirement accepted (err=%v)", err)
		}
	})
}

// TestAlgConfusion: an RS256 header verified against an Ed25519 key (or vice
// versa) must fail on the type check, not verify.
func TestAlgConfusion(t *testing.T) {
	now := time.Now()
	edPriv, edKS := edSource(t, "k1")
	// Token signed EdDSA but header claims RS256 → verifyJWS demands an RSA key
	// from the source (which holds an Ed key) → ErrAlg.
	payload, _ := json.Marshal(svidClaims(now))
	sig := ed25519.Sign(edPriv, []byte(b64([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))+"."+b64(payload)))
	tok := mintRawJWT(`{"alg":"RS256","kid":"k1","typ":"JWT"}`, string(payload), sig)
	if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, edKS); !errors.Is(err, ErrAlg) {
		t.Fatalf("alg-confusion accepted (err=%v)", err)
	}
}

func TestDuplicateClaimRejected(t *testing.T) {
	now := time.Now()
	priv, ks := edSource(t, "k1")
	// Two "aud" members: one valid, one not. Sign the raw payload as-is.
	payload := `{"sub":"spiffe://prod.example/x","aud":"spt-txn-exchange","aud":"evil","iat":` +
		itoa(now.Unix()) + `,"exp":` + itoa(now.Add(time.Minute).Unix()) + `}`
	sig := ed25519.Sign(priv, []byte(b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))+"."+b64([]byte(payload))))
	tok := mintRawJWT(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`, payload, sig)
	if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate claim accepted (err=%v)", err)
	}
}

// ── K8s SA + cloud ──────────────────────────────────────────────────────

func TestK8sSAToken(t *testing.T) {
	now := time.Now()
	priv, ks := edSource(t, "k1")
	iss := "https://kubernetes.default.svc"
	claims := map[string]any{
		"iss": iss, "sub": "system:serviceaccount:pay:charger",
		"aud": []any{"spt-txn-exchange"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	tok := mintJWT(t, "EdDSA", "k1", priv, claims)
	id, err := VerifyK8sSAToken(context.Background(), tok, iss, []string{"spt-txn-exchange"}, ks)
	if err != nil {
		t.Fatalf("valid SA token rejected: %v", err)
	}
	if id.Method != MethodK8sSA {
		t.Fatalf("method %s", id.Method)
	}

	// Wrong issuer.
	if _, err := VerifyK8sSAToken(context.Background(), tok, "https://evil", []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrIssuer) {
		t.Fatalf("wrong issuer accepted (err=%v)", err)
	}

	// Generic OIDC subject (not a serviceaccount) from same issuer must be
	// rejected as an SA.
	claims["sub"] = "some-user@example.com"
	tok2 := mintJWT(t, "EdDSA", "k1", priv, claims)
	if _, err := VerifyK8sSAToken(context.Background(), tok2, iss, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrSubject) {
		t.Fatalf("non-SA subject accepted as SA (err=%v)", err)
	}
}

func TestCloudWorkloadRS256(t *testing.T) {
	now := time.Now()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := NewStaticKeySource(map[string]crypto.PublicKey{"g1": &rk.PublicKey})
	iss := "https://accounts.google.com"
	claims := map[string]any{
		"iss": iss, "sub": "112233445566",
		"aud": "spt-txn-exchange", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	tok := mintJWT(t, "RS256", "g1", rk, claims)
	id, err := VerifyCloudWorkload(context.Background(), tok, MethodGCPWIF, iss, []string{"spt-txn-exchange"}, ks)
	if err != nil {
		t.Fatalf("valid GCP WIF token rejected: %v", err)
	}
	if id.Method != MethodGCPWIF {
		t.Fatalf("method %s", id.Method)
	}
}

// ── Freshness ───────────────────────────────────────────────────────────

func TestFreshness(t *testing.T) {
	now := time.Now()
	fresh := Identity{IssuedAt: now.Add(-10 * time.Second)}
	stale := Identity{IssuedAt: now.Add(-10 * time.Minute)}
	future := Identity{IssuedAt: now.Add(5 * time.Minute)}

	p := Freshness{MaxAge: 60 * time.Second}
	if err := p.Check(fresh, now); err != nil {
		t.Fatalf("fresh rejected: %v", err)
	}
	if err := p.Check(stale, now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale accepted (err=%v)", err)
	}
	if err := p.Check(future, now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("future-dated accepted (err=%v)", err)
	}
	// Zero policy imposes nothing.
	if err := (Freshness{}).Check(stale, now); err != nil {
		t.Fatalf("zero policy enforced: %v", err)
	}
}

func TestSealExpiryOK(t *testing.T) {
	now := time.Now()
	att := now.Add(1 * time.Minute)
	if !SealExpiryOK(now.Add(30*time.Second), att) {
		t.Fatal("token within attestation expiry rejected")
	}
	if SealExpiryOK(now.Add(2*time.Minute), att) {
		t.Fatal("token outliving attestation expiry accepted")
	}
}

// ── X.509-SVID ──────────────────────────────────────────────────────────

func TestX509SVID(t *testing.T) {
	now := time.Now()
	// CA.
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// Leaf SVID with a spiffe:// URI SAN.
	leafPub, _, _ := ed25519.GenerateKey(rand.Reader)
	spiffeURI, _ := url.Parse("spiffe://prod.example/ns/pay/sa/charger")
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{spiffeURI},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	id, err := VerifyX509SVID([][]byte{leafDER}, X509Bundle{Roots: roots}, now)
	if err != nil {
		t.Fatalf("valid X.509-SVID rejected: %v", err)
	}
	if id.Subject != "spiffe://prod.example/ns/pay/sa/charger" || id.TrustDomain != "prod.example" {
		t.Fatalf("bad identity %+v", id)
	}

	// Untrusted root.
	otherRoots := x509.NewCertPool()
	if _, err := VerifyX509SVID([][]byte{leafDER}, X509Bundle{Roots: otherRoots}, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("untrusted chain accepted (err=%v)", err)
	}

	// Expired leaf.
	if _, err := VerifyX509SVID([][]byte{leafDER}, X509Bundle{Roots: roots}, now.Add(48*time.Hour)); !errors.Is(err, ErrSignature) {
		t.Fatalf("expired leaf accepted (err=%v)", err)
	}
}

func TestMethodFromTokenType(t *testing.T) {
	if m, err := MethodFromTokenType("urn:violetsky:token-type:spiffe-jwt-svid"); err != nil || m != MethodSPIFFEJWTSVID {
		t.Fatalf("got %v %v", m, err)
	}
	if _, err := MethodFromTokenType("urn:unknown"); err == nil {
		t.Fatal("unknown token type accepted")
	}
}

// TestSPIFFETrustDomainParsing pins the hardened parser: crafted authorities
// (userinfo, port, empty host) must be rejected so a trust domain can never be
// misattributed.
func TestSPIFFETrustDomainParsing(t *testing.T) {
	ok := map[string]string{
		"spiffe://prod.example/ns/pay/sa/charger": "prod.example",
		"spiffe://trust-domain/x":                 "trust-domain",
		"spiffe://a.b.c":                          "a.b.c",
	}
	for in, want := range ok {
		got, err := spiffeTrustDomain(in)
		if err != nil || got != want {
			t.Errorf("spiffeTrustDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"spiffe://",                    // empty authority
		"spiffe:///path",               // empty host
		"spiffe://evil@good.example/x", // userinfo
		"spiffe://good.example:8443/x", // port
		"spiffe://good.example/x?q=1",  // query
		"spiffe://good.example/x#f",    // fragment
		"https://good.example/x",       // wrong scheme
		"not-a-uri",                    // no scheme
	}
	for _, in := range bad {
		if _, err := spiffeTrustDomain(in); err == nil {
			t.Errorf("spiffeTrustDomain(%q) accepted; want rejection", in)
		}
	}
}

// TestRequireExpiry: an SVID with no exp must be rejected, not treated as
// eternal.
func TestRequireExpiry(t *testing.T) {
	now := time.Now()
	priv, ks := edSource(t, "k1")
	c := svidClaims(now)
	delete(c, "exp")
	tok := mintJWT(t, "EdDSA", "k1", priv, c)
	if _, err := VerifySPIFFEJWTSVID(context.Background(), tok, []string{"spt-txn-exchange"}, ks); !errors.Is(err, ErrExpired) {
		t.Fatalf("exp-less SVID accepted (err=%v)", err)
	}
}

func itoa(n int64) string { return big.NewInt(n).String() }
