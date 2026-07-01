// Package cttoken implements Capability Token (CT) issuance for the SPT-Txn
// POC — Milestone 3.
//
// A Capability Token is a scope-attenuated child of a Compliance Attestation
// Token (CAT, see internal/cattoken). Per Section 3.4 of
// draft-coetzee-oauth-spt-txn-tokens, the issuer:
//
//  1. verifies the parent CAT signature and basic claims,
//  2. checks the requested scope is contained within the CAT's capability_scope
//     (internal/tbac), and
//  3. issues a CT that carries the humanAnchor forward unchanged, decrements
//     the remaining delegation depth, and references the parent CAT.
//
// Token structure (JWT claims):
//
//	{
//	  "iss":                       string,   // ct_issuer identifier
//	  "sub":                       string,   // subject, carried from the CAT
//	  "iat":                       int64,
//	  "exp":                       int64,
//	  "jti":                       string,
//	  "txn_token_type":            "CT",
//	  "human_anchor":              string,   // propagated unchanged from the CAT
//	  "capability_scope":          object,   // attenuated scope (<= parent)
//	  "delegation_depth_remaining": int,     // parent max - 1
//	  "holder_key":                string,   // hex Ed25519 key of this holder
//	  "spt_cat_ref":               string,   // parent CAT jti
//	  "spt_parent_hash":           string,   // base64url(SHA-256(parent CAT))
//	}
//
// Signed with Ed25519 (alg EdDSA). The signing key is the registered
// ct_issuer key (Role ct_issuer also signs CATs — same role, Section 8.1).
// Standard library only.
package cttoken

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
)

// DefaultTTL is the Capability Token lifetime when IssueRequest.TTL is zero.
// CTs are short-lived relative to CATs but longer-lived than SPT-Txn Tokens.
const DefaultTTL = 10 * time.Minute

// IssueRequest is the input to the Capability Token issuer.
type IssueRequest struct {
	// Issuer is the registered ct_issuer identifier (Trust Registry).
	Issuer string

	// ParentCAT is the compact JWT of the parent Compliance Attestation Token.
	ParentCAT string

	// ParentIssuerKey is the public key the parent CAT was signed with. In the
	// running service this comes from a Trust Registry lookup for
	// (CAT.iss, role=ct_issuer).
	ParentIssuerKey ed25519.PublicKey

	// RequestedScope is the (narrower) scope the holder is requesting. It MUST
	// be contained within the parent CAT's capability_scope.
	RequestedScope tbac.Scope

	// HolderPublicKey is the Ed25519 key bound to this Capability Token. It may
	// be the same agent key as the CAT holder, or a delegated subkey.
	HolderPublicKey ed25519.PublicKey

	// TTL overrides DefaultTTL when non-zero.
	TTL time.Duration
}

// CT is an issued Capability Token.
type CT struct {
	Token       string
	HumanAnchor string // hex humanAnchor, propagated from the parent CAT
	Claims      map[string]any
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Issue verifies the parent CAT, attenuates scope, and signs a Capability
// Token. signingKey is the ct_issuer Ed25519 private key.
func Issue(req IssueRequest, signingKey crypto.Signer) (*CT, error) {
	if req.Issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.RequestedScope == nil {
		return nil, fmt.Errorf("requested scope required")
	}

	// ── 1. Verify the parent CAT ──────────────────────────────────────
	parent, err := cattoken.Verify(req.ParentCAT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CAT invalid: %w", err)
	}

	// ── 2. Extract parent fields ──────────────────────────────────────
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	humanAnchor, ok := parent["human_anchor"].(string)
	if !ok || humanAnchor == "" {
		return nil, fmt.Errorf("parent CAT missing human_anchor")
	}
	sub, _ := parent["sub"].(string)
	parentJTI, _ := parent["jti"].(string)

	// delegation_depth_max arrives as float64 after JSON decoding.
	depthMaxF, ok := parent["delegation_depth_max"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing delegation_depth_max")
	}
	remaining := int(depthMaxF) - 1
	if remaining < 0 {
		return nil, fmt.Errorf("delegation depth exhausted: parent permits no further delegation")
	}

	// ── 3. Attenuate scope (containment check) ────────────────────────
	attenuated, err := tbac.Attenuate(parentScope, req.RequestedScope)
	if err != nil {
		return nil, err
	}

	// ── 4. Build claims ───────────────────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	parentHash := sha256.Sum256([]byte(req.ParentCAT))

	claims := map[string]any{
		"iss":                        req.Issuer,
		"sub":                        sub,
		"iat":                        now.Unix(),
		"exp":                        exp.Unix(),
		"jti":                        jti,
		"txn_token_type":             "CT",
		"human_anchor":               humanAnchor,
		"capability_scope":           map[string]any(attenuated),
		"delegation_depth_remaining": remaining,
		"holder_key":                 hex.EncodeToString(req.HolderPublicKey),
		"spt_cat_ref":                parentJTI,
		"spt_parent_hash":            base64url(parentHash[:]),
	}

	token, err := signJWT(claims, signingKey)
	if err != nil {
		return nil, err
	}

	return &CT{
		Token:       token,
		HumanAnchor: humanAnchor,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// DelegateRequest is the input to CT→CT delegation (Milestone 7, agentic
// authorization). An agent that holds a Capability Token hands a strictly
// narrower capability to a sub-agent or tool. Unlike IssueRequest (whose parent
// is a CAT), the parent here is itself a CT, so the chain can extend to multiple
// hops while remaining monotonically attenuating and depth-bounded.
type DelegateRequest struct {
	// Issuer is the registered ct_issuer identifier signing THIS delegation. In
	// a multi-agent deployment the delegating party is itself a registered
	// issuer, so revoking its key collapses every capability it delegated
	// downstream without touching its own parent capability.
	Issuer string

	// ParentCT is the compact JWT of the parent Capability Token.
	ParentCT string

	// ParentIssuerKey is the public key the parent CT was signed with. In the
	// running service this comes from a Trust Registry lookup for
	// (parentCT.iss, role=ct_issuer).
	ParentIssuerKey ed25519.PublicKey

	// RequestedScope is the (narrower) scope for the sub-agent. It MUST be
	// contained within the parent CT's capability_scope.
	RequestedScope tbac.Scope

	// HolderPublicKey is the Ed25519 key of the sub-agent this CT is bound to.
	HolderPublicKey ed25519.PublicKey

	// TTL overrides DefaultTTL when non-zero. A delegated CT SHOULD NOT outlive
	// its parent; callers SHOULD pass a TTL no longer than the parent's
	// remaining life.
	TTL time.Duration
}

// Delegate verifies the parent CT, attenuates its scope, decrements the
// remaining delegation depth, and signs a child Capability Token bound to the
// sub-agent's key. signingKey is the delegating ct_issuer's Ed25519 private key.
//
// The child commits to its immediate parent by hash (spt_parent_hash) and by
// jti (spt_parent_ref), and carries the root CAT reference (spt_cat_ref) and the
// humanAnchor forward unchanged, so a verifier can re-walk the whole chain
// offline from the root CAT to the leaf without contacting any issuer.
func Delegate(req DelegateRequest, signingKey crypto.Signer) (*CT, error) {
	if req.Issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.RequestedScope == nil {
		return nil, fmt.Errorf("requested scope required")
	}

	// ── 1. Verify the parent CT ───────────────────────────────────────
	parent, err := Verify(req.ParentCT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CT invalid: %w", err)
	}

	// ── 2. Extract parent fields ──────────────────────────────────────
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	humanAnchor, ok := parent["human_anchor"].(string)
	if !ok || humanAnchor == "" {
		return nil, fmt.Errorf("parent CT missing human_anchor")
	}
	sub, _ := parent["sub"].(string)
	parentJTI, _ := parent["jti"].(string)
	// Root CAT reference, propagated unchanged down every hop so the leaf still
	// names the human's root authority.
	rootCATRef, _ := parent["spt_cat_ref"].(string)

	// delegation_depth_remaining arrives as float64 after JSON decoding.
	remF, ok := parent["delegation_depth_remaining"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CT missing delegation_depth_remaining")
	}
	remaining := int(remF) - 1
	if remaining < 0 {
		return nil, fmt.Errorf("delegation depth exhausted: parent CT permits no further delegation")
	}

	// ── 3. Attenuate scope (containment check) ────────────────────────
	attenuated, err := tbac.Attenuate(parentScope, req.RequestedScope)
	if err != nil {
		return nil, err
	}

	// ── 4. Build claims ───────────────────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	parentHash := sha256.Sum256([]byte(req.ParentCT))

	claims := map[string]any{
		"iss":                        req.Issuer,
		"sub":                        sub,
		"iat":                        now.Unix(),
		"exp":                        exp.Unix(),
		"jti":                        jti,
		"txn_token_type":             "CT",
		"human_anchor":               humanAnchor,
		"capability_scope":           map[string]any(attenuated),
		"delegation_depth_remaining": remaining,
		"holder_key":                 hex.EncodeToString(req.HolderPublicKey),
		"spt_cat_ref":                rootCATRef,                // root CAT, unchanged
		"spt_parent_ref":             parentJTI,                 // immediate parent CT
		"spt_parent_hash":            base64url(parentHash[:]),  // hash of immediate parent
	}

	token, err := signJWT(claims, signingKey)
	if err != nil {
		return nil, err
	}

	return &CT{
		Token:       token,
		HumanAnchor: humanAnchor,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// Verify checks the signature and basic claims of a Capability Token. Like
// cattoken.Verify it does not consult the Trust Registry — that is the
// verifier's job (M5).
func Verify(tokenStr string, issuerPublicKey ed25519.PublicKey) (map[string]any, error) {
	claims, err := verifyJWT(tokenStr, issuerPublicKey)
	if err != nil {
		return nil, err
	}
	if tt, _ := claims["txn_token_type"].(string); tt != "CT" {
		return nil, fmt.Errorf("expected txn_token_type=CT, got %q", tt)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing exp claim")
	}
	// RFC 7519: valid only while now < exp; expired once now >= exp.
	if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}

// ── shared JWT helpers (EdDSA, stdlib) ───────────────────────────────────────

func signJWT(claims map[string]any, key crypto.Signer) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64url(headerJSON) + "." + base64url(claimsJSON)
	sig, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64url(sig), nil
}

func verifyJWT(tokenStr string, pub ed25519.PublicKey) (map[string]any, error) {
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
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
