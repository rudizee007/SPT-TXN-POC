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
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
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

	// Attestation optionally seals a verified attested-workload identity into
	// the CAT as the signed `spt_attestation` claim (SPT-Txn P4, spec
	// docs/spec/NHI-ATTESTED-ISSUANCE.md §4). Build it from
	// attest.Identity.SealClaim(). When present, the CAT's exp MUST NOT exceed
	// the attestation's sealed exp — Issue enforces this and rejects a request
	// that would outlive the proof it was minted on. nil for human-issued CATs.
	Attestation map[string]any

	// Status optionally sets the signed `status` claim binding this CAT to a
	// Token Status List entry for scalable revocation (docs/spec/STATUS-LIST.md
	// §4), e.g. {"status_list": {"idx": 42, "uri": "https://…/sl/9"}}. nil
	// leaves the CAT out of status-list scope (key-cascade + TTL only).
	Status map[string]any

	// IdentityAnchor optionally supplies a pre-computed 32-byte zkDID commitment
	// to use as the humanAnchor, instead of deriving one from PrincipalName.
	// This is the integration seam a zkDID/personhood provider fills — the mock
	// provider in internal/zkdidmock, and in production Toby Bolton's .zkdid™
	// initiative. Empty means "derive from the test principal" (POC default);
	// a non-empty value that is not exactly 32 bytes is rejected.
	IdentityAnchor []byte

	// SubbandGroupRoot, when non-empty, commits this CAT to ONE pre-division of
	// its max_cumulative budget (§7.2 / SUBBAND-GROUP-ROOT-DESIGN). It is the
	// 32-byte Merkle root over the slice tuples from tbac.CommitBandDivision. The
	// CAT's Scope MUST declare a max_cumulative budget. Downstream, only slices
	// proving membership in this root may carry a share of the budget, so the
	// cumulative total is bounded by construction and the budget cannot be
	// re-divided — a second division would need a different root, i.e. a
	// different CAT the human's authority never signed.
	SubbandGroupRoot []byte
	SubbandGroupSize uint32
	SubbandHashSuite tbac.HashSuite
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

	// ── 1. Obtain the humanAnchor ─────────────────────────────────────
	// If the caller supplies an externally-produced 32-byte anchor (the seam a
	// zkDID provider fills — see internal/zkdidmock, and in production Toby
	// Bolton's .zkdid™ initiative), use it as the humanAnchor. Otherwise, for
	// the POC, derive one from a deterministic test principal.
	var anchor zkdid.Commitment
	if len(req.IdentityAnchor) == 32 {
		copy(anchor[:], req.IdentityAnchor)
	} else if len(req.IdentityAnchor) != 0 {
		return nil, fmt.Errorf("identity anchor must be 32 bytes, got %d", len(req.IdentityAnchor))
	} else {
		identityMaterial := zkdid.TestPrincipal(req.PrincipalName)
		randomness, err := zkdid.NewRandomness()
		if err != nil {
			return nil, fmt.Errorf("generate randomness: %w", err)
		}
		anchor = zkdid.Compute(identityMaterial, randomness[:])
	}

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

	// P4: seal a verified attestation, if supplied. The CAT must not outlive
	// the attestation it was minted on (spec §4) — reject rather than clamp,
	// because an over-long request here signals a caller bug, not a default.
	if req.Attestation != nil {
		if attExp, ok := numClaim(req.Attestation["exp"]); ok && exp.Unix() > attExp {
			return nil, fmt.Errorf("CAT exp %d would outlive sealed attestation exp %d", exp.Unix(), attExp)
		}
		claims["spt_attestation"] = req.Attestation
	}
	if req.Status != nil {
		claims["status"] = req.Status
	}

	// §7.2: a signed commitment to ONE pre-division of this CAT's cumulative
	// budget. Signed as part of the CAT so a verifier trusts that the human's
	// authority — not a downstream party — fixed the division. Only slices that
	// prove membership in this root may carry a share of the budget.
	if len(req.SubbandGroupRoot) > 0 {
		if len(req.SubbandGroupRoot) != 32 {
			return nil, fmt.Errorf("subband group root must be 32 bytes, got %d", len(req.SubbandGroupRoot))
		}
		if req.SubbandGroupSize == 0 {
			return nil, fmt.Errorf("subband group size must be > 0")
		}
		if !tbac.IsKnownHashSuite(req.SubbandHashSuite) {
			return nil, fmt.Errorf("subband hash suite %q is not known", req.SubbandHashSuite)
		}
		if !tbac.DeclaresCumulativeBudget(tbac.Scope(req.Scope)) {
			return nil, fmt.Errorf("subband commitment requires the CAT scope to declare a max_cumulative budget")
		}
		claims["subband_group_root"] = hex.EncodeToString(req.SubbandGroupRoot)
		claims["subband_group_size"] = req.SubbandGroupSize
		claims["subband_hash_suite"] = string(req.SubbandHashSuite)
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

// numClaim reads a numeric claim value across the encodings it may arrive in
// (a Go int64 when built in-process via SealClaim, float64 after a JSON
// round-trip, or json.Number).
func numClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}

// degenerateHolderKeys are Ed25519 public-key encodings under which one fixed
// 64-byte constant verifies as a signature without anyone holding a private
// key. A credential sealed to one of them is a bearer token wearing a sender
// constraint: it constrains nobody.
//
// The rate differs by the point's order and it is worth stating exactly, because
// "any message" would be wrong for the second entry. Measured on this toolchain
// over 2000 messages with R = the neutral element and S = 0:
//
//	the neutral element (order 1)   2000/2000  (100%)
//	the all-zero encoding (order 4)  513/2000  (~25%, i.e. 1 in 4)
//
// One in four is not a weaker problem than one in one; it is a forgery that
// needs at most a handful of attempts. Both are refused.
//
// Both entries were verified empirically rather than copied from a table — see
// TestHolderKey_DegenerateEncodingsAreRefused, which demonstrates the forgery
// before asserting the refusal. Go's crypto/ed25519 performs no low-order check
// of its own (RFC 8032 does not require one), so nothing else rejects these.
//
// RESIDUAL, stated rather than hidden: this refuses the two encodings that were
// demonstrated, NOT the full set of low-order points. Rejecting all of them
// means clearing the cofactor, which needs a library that exposes point
// arithmetic; the project's own rule is audited libraries only, so adding one is
// a dependency decision for the maintainer and not something to hand-roll here.
// Until then this is a mitigation, not a proof.
var degenerateHolderKeys = [][]byte{
	// The neutral element.
	{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	// The all-zero encoding, a point of order 4.
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

// checkHolderKey refuses a holder key that cannot function as a sender
// constraint. It lives here, beside the length check, so every caller of Issue
// gets it — a guard in one HTTP handler is a guard the next caller does not have.
func checkHolderKey(pub ed25519.PublicKey) error {
	for _, bad := range degenerateHolderKeys {
		if subtle.ConstantTimeCompare(pub, bad) == 1 {
			return fmt.Errorf("holder public key is a degenerate Ed25519 encoding: a fixed " +
				"constant verifies as a signature over any message under it, so it constrains nobody")
		}
	}
	return nil
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
	if err := checkHolderKey(req.HolderPublicKey); err != nil {
		return err
	}
	if req.DelegationDepthMax < 1 {
		return fmt.Errorf("delegation_depth_max must be >= 1")
	}
	// A monetary ceiling with no currency beside it is not a ceiling: TxnScope
	// asserts `currency` only where the scope declares it, so max_amount alone
	// bounds the amount in every currency at once. Refuse to seal it.
	// See tbac.ValidateIssuance.
	if err := tbac.ValidateIssuance(tbac.Scope(req.Scope)); err != nil {
		return fmt.Errorf("capability scope: %w", err)
	}
	return nil
}
