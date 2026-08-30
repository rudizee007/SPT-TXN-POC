package cattoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

// forgeCAT mints a compact JWT with caller-chosen claims, signed by key, for
// boundary tests that cattoken.Issue would not naturally produce.
func forgeCAT(t *testing.T, claims map[string]any, key ed25519.PrivateKey) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(key, []byte(si))
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pub, priv
}

func TestIssue_ValidCAT(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	req := cattoken.IssueRequest{
		Issuer:             "domain-a.authorg",
		Subject:            "alice",
		PrincipalName:      "alice",
		Scope:              cattoken.CapabilityScope{"action": "transfer", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3,
		TTL:                24 * time.Hour,
		HolderPublicKey:    holderPub,
	}

	cat, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Token has three parts.
	parts := strings.Split(cat.Token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	// humanAnchor is 32 bytes, hex-encoded = 64 chars.
	if len(cat.HumanAnchor.String()) != 64 {
		t.Errorf("humanAnchor hex length = %d, want 64", len(cat.HumanAnchor.String()))
	}

	// Claims are populated.
	if cat.Claims["txn_token_type"] != "CAT" {
		t.Errorf("txn_token_type = %v, want CAT", cat.Claims["txn_token_type"])
	}
	if cat.Claims["iss"] != "domain-a.authorg" {
		t.Errorf("iss = %v, want domain-a.authorg", cat.Claims["iss"])
	}
	if cat.Claims["human_anchor"] != cat.HumanAnchor.String() {
		t.Errorf("human_anchor claim mismatch")
	}

	// Signature verifies.
	claims, err := cattoken.Verify(cat.Token, issuerPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", claims["sub"])
	}
}

func TestIssue_HolderBinding(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	req := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "bob",
		PrincipalName: "bob", Scope: cattoken.CapabilityScope{"action": "read"},
		DelegationDepthMax: 1, HolderPublicKey: holderPub,
	}
	cat, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// holder_key claim matches the holder's public key.
	holderKeyHex := hex.EncodeToString(holderPub)
	if cat.Claims["holder_key"] != holderKeyHex {
		t.Errorf("holder_key claim = %v, want %v", cat.Claims["holder_key"], holderKeyHex)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	wrongPub, _ := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	req := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "carol",
		PrincipalName: "carol", Scope: cattoken.CapabilityScope{"action": "write"},
		DelegationDepthMax: 2, HolderPublicKey: holderPub,
	}
	cat, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = cattoken.Verify(cat.Token, wrongPub)
	if err == nil {
		t.Error("expected verification failure with wrong key, got nil")
	}
}

func TestVerify_Expired(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	req := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "dave",
		PrincipalName: "dave", Scope: cattoken.CapabilityScope{"action": "read"},
		DelegationDepthMax: 1, HolderPublicKey: holderPub,
		TTL: -1 * time.Second, // already expired
	}
	cat, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = cattoken.Verify(cat.Token, issuerPub)
	if err == nil {
		t.Error("expected expiry error, got nil")
	}
}

// VER-4: a CAT whose exp equals the current time is expired (now >= exp),
// matching cttoken/txntoken/engine and RFC 7519 intent. Before the fix cattoken
// used a strict `>` so now == exp incorrectly still verified.
func TestVerify_ExpiresAtExactBoundary(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)
	claims := map[string]any{
		"iss":                  "domain-a.authorg",
		"sub":                  "grace",
		"iat":                  time.Now().Add(-time.Minute).Unix(),
		"exp":                  time.Now().Unix(), // exp == now (boundary)
		"jti":                  "boundary-jti",
		"txn_token_type":       "CAT",
		"human_anchor":         hex.EncodeToString(make([]byte, 32)),
		"capability_scope":     map[string]any{"action": "read"},
		"delegation_depth_max": 1,
		"holder_key":           hex.EncodeToString(holderPub),
	}
	token := forgeCAT(t, claims, issuerPriv)
	if _, err := cattoken.Verify(token, issuerPub); err == nil {
		t.Error("expected exp==now to be treated as expired, got nil")
	}
}

func TestIssue_ValidationErrors(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	base := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "eve",
		PrincipalName: "eve", Scope: cattoken.CapabilityScope{"action": "read"},
		DelegationDepthMax: 1, HolderPublicKey: holderPub,
	}

	cases := []struct {
		name string
		mod  func(*cattoken.IssueRequest)
	}{
		{"empty issuer", func(r *cattoken.IssueRequest) { r.Issuer = "" }},
		{"empty subject", func(r *cattoken.IssueRequest) { r.Subject = "" }},
		{"empty principal", func(r *cattoken.IssueRequest) { r.PrincipalName = "" }},
		{"zero depth", func(r *cattoken.IssueRequest) { r.DelegationDepthMax = 0 }},
		{"nil holder key", func(r *cattoken.IssueRequest) { r.HolderPublicKey = nil }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := base
			c.mod(&req)
			_, err := cattoken.Issue(req, issuerPriv)
			if err == nil {
				t.Errorf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestHumanAnchor_Deterministic(t *testing.T) {
	// Same principal always produces the same identity material,
	// but different randomness produces different commitments.
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	req := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "frank",
		PrincipalName: "frank", Scope: cattoken.CapabilityScope{"action": "read"},
		DelegationDepthMax: 1, HolderPublicKey: holderPub,
	}

	cat1, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	cat2, err := cattoken.Issue(req, issuerPriv)
	if err != nil {
		t.Fatalf("Issue 2: %v", err)
	}

	// Each issuance uses fresh randomness — commitments must differ
	// (unlinkability property).
	if cat1.HumanAnchor == cat2.HumanAnchor {
		t.Error("expected different humanAnchor per issuance (fresh randomness), got identical")
	}
}
