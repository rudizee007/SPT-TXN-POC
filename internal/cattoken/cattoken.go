// Package cattoken implements Compliance Attestation Token (CAT) issuance
// for the SPT-Txn POC.
//
// A CAT is a signed JWT per Section 3.1 of draft-coetzee-oauth-spt-txn-tokens.
// It establishes the maximum capability grant for a principal and carries the
// humanAnchor commitment forward into all downstream tokens.
//
// Token structure (JWT claims):
//
//	{
//	  "iss":                 string,   // issuer DID / identifier
//	  "sub":                 string,   // subject (holder) identifier
//	  "iat":                 int64,    // issued-at (Unix seconds)
//	  "exp":                 int64,    // expiry (Unix seconds)
//	  "jti":                 string,   // unique token ID (UUID-style)
//	  "txn_token_type":      "CAT",
//	  "human_anchor":        string,   // hex-encoded 32-byte zkDID commitment
//	  "capability_scope":    object,   // max capability scope
//	  "delegation_depth_max": int,     // max delegation hops downstream
//	  "holder_key":          string,   // hex-encoded holder Ed25519 public key
//	}
//
// The JWT is signed with Ed25519 (alg: EdDSA) per Section 10.1 of the draft.
// Standard library only — no external JWT dependency.
package cattoken

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkdid"
)

// CapabilityScope defines the maximum scope for the CAT.
// Keys are scope dimensions; values are the permitted values/levels.
type CapabilityScope map[string]any

// IssueRequest is the input to the CAT issuer.
type IssueRequest struct {
	// Issuer is the registered issuer identifier (must match Trust Registry).
	Issuer string

	// Subject is the holder's identifier.
	Subject string

	// PrincipalName is the test principal name for zkDID commitment generation.
	// Production: replace with actual biometric template material.
	PrincipalName string

	// Scope is the maximum capability scope for this CAT.
	Scope CapabilityScope

	// DelegationDepthMax is the maximum number of downstream delegation hops.
	DelegationDepthMax int

	// TTL is how long the CAT is valid. Default: 24 hours.
	TTL time.Duration

	// HolderPublicKey is the Ed25519 public key of the CAT holder (32 bytes).
	// The holder must prove possession of the corresponding private key
	// when presenting the CAT (holder binding per Section 3.2).
	HolderPublicKey ed25519.PublicKey
}

// CAT is an issued Compliance Attestation Token.
type CAT struct {
	// Token is the compact JWT string (header.payload.signature).
	Token string

	// HumanAnchor is the zkDID commitment embedded in this CAT.
	// Propagated unchanged into all downstream Capability Tokens
	// and SPT-Txn Tokens.
	HumanAnchor zkdid.Commitment

	// Claims contains the decoded JWT claims for inspection/testing.
	Claims map[string]any

	// IssuedAt and ExpiresAt are the token's temporal bounds.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Issue creates and signs a new CAT.
//
// signingKey is the Ed25519 private key of the registered ct_issuer.
// The corresponding public key must be registered in the Trust Registry
// for the issuer identifier in req.Issuer.
func Issue(req IssueRequest, signingKey crypto.Signer) (*CAT, error) {
	if err := validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// ── 1. Compute humanAnchor ────────────────────────────────────────
	identityMaterial := zkdid.TestPrincipal(req.PrincipalName)
	randomness, err := zkdid.NewRandomness()
	if err != nil {
		return nil, fmt.Errorf("generate randomness: %w", err)
	}
	anchor := zkdid.Compute(identityMaterial, randomness[:])

	// ── 2. Build JWT claims ───────────────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	exp := now.Add(ttl)
	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}

	claims := map[string]any{
		"iss":                  req.Issuer,
		"sub":                  req.Subject,
		"iat":                  now.Unix(),
		"exp":                  exp.Unix(),
		"jti":                  jti,
		"txn_token_type":       "CAT",
		"human_anchor":         anchor.String(),
		"capability_scope":     req.Scope,
		"delegation_depth_max": req.DelegationDepthMax,
		"holder_key":           hex.EncodeToString(req.HolderPublicKey),
	}

	// ── 3. Build JWT (EdDSA / Ed25519) ───────────────────────────────
	header := map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	headerB64 := base64url(headerJSON)
	claimsB64 := base64url(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	sig, err := signingKey.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign CAT: %w", err)
	}
	token := signingInput + "." + base64url(sig)

	return &CAT{
		Token:       token,
		HumanAnchor: anchor,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// Verify checks the signature and basic claims of a CAT JWT.
// It does NOT check Trust Registry membership — that is the verifier's job
// (Step 2 of the eight-step enforcement engine, M5).
func Verify(tokenStr string, issuerPublicKey ed25519.PublicKey) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	} else {
		var h struct {
			Alg string `json:"alg"`
		}
		_ = json.Unmarshal(hb, &h)
		if h.Alg != "EdDSA" {
			return nil, fmt.Errorf("unexpected JWT alg %q, want EdDSA", h.Alg)
		}
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(issuerPublicKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	// Check expiry.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing exp claim")
	}
	// RFC 7519: valid only while now < exp; expired once now >= exp. Matches
	// cttoken, txntoken, and the engine (VER-4).
	if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("token expired")
	}

	// Check token type.
	if tt, _ := claims["txn_token_type"].(string); tt != "CAT" {
		return nil, fmt.Errorf("expected txn_token_type=CAT, got %q", tt)
	}

	return claims, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Format as UUID v4.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func validateRequest(req IssueRequest) error {
	if req.Issuer == "" {
		return fmt.Errorf("issuer required")
	}
	if req.Subject == "" {
		return fmt.Errorf("subject required")
	}
	if req.PrincipalName == "" {
		return fmt.Errorf("principal name required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.DelegationDepthMax < 1 {
		return fmt.Errorf("delegation_depth_max must be >= 1")
	}
	return nil
}
