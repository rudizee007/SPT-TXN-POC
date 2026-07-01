// Package txntoken implements SPT-Txn Token issuance for the POC — Milestone 4.
//
// An SPT-Txn Token is the short-lived, transaction-bound leaf of the chain
// CAT -> CT -> SPT-Txn. Per Section 3 and Section 7 of
// draft-coetzee-oauth-spt-txn-tokens, the Transaction Token Service (TTS):
//
//  1. verifies the parent Capability Token (internal/cttoken),
//  2. confirms the presenting holder key matches the capability's holder
//     (sender-constraint chain),
//  3. checks the concrete transaction is within the capability's scope
//     (internal/tbac),
//  4. binds the token to that transaction via spt_txn_context_hash, computed
//     through the blockchain-agnostic ledger adapter (internal/ledger), and
//  5. issues a 30-second token whose cnf.jkt commits to the holder key for
//     DPoP proof-of-possession at the verifier (internal/dpop).
//
// The token is chain-agnostic: it records the chain name and a context hash,
// never a chain-specific payload. XRPL is just one adapter behind ledger.Ledger.
//
// Token structure (JWT claims):
//
//	{
//	  "iss":                  string,   // tts_issuer identifier
//	  "sub":                  string,   // subject, carried from the CT
//	  "aud":                  string,   // executing domain identifier
//	  "iat":                  int64,
//	  "exp":                  int64,    // iat + 30s
//	  "jti":                  string,
//	  "txn_token_type":       "TXN",
//	  "human_anchor":         string,   // propagated unchanged
//	  "spt_ct_ref":           string,   // parent CT jti
//	  "spt_txn_chain":        string,   // ledger adapter name ("xrpl", "none", ...)
//	  "spt_txn_context_hash": string,   // hex SHA-256 of the canonical txn context
//	  "cnf":                  {"jkt": string}, // holder-key thumbprint (DPoP)
//	}
//
// Signed with the registered tts_issuer Ed25519 key. Standard library only.
package txntoken

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

	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
)

// DefaultTTL is the SPT-Txn Token lifetime: deliberately short (30 seconds) to
// limit the window in which a transaction authorization is replayable.
const DefaultTTL = 30 * time.Second

// IssueRequest is the input to the TTS.
type IssueRequest struct {
	// Issuer is the registered tts_issuer identifier.
	Issuer string

	// Audience is the executing domain (Domain B) identifier.
	Audience string

	// ParentCT is the compact JWT of the parent Capability Token.
	ParentCT string

	// ParentIssuerKey is the ct_issuer public key the CT was signed with
	// (from a Trust Registry lookup in the running service).
	ParentIssuerKey ed25519.PublicKey

	// HolderPublicKey is the agent key presenting the request. It MUST equal
	// the CT's holder_key — the SPT-Txn Token inherits the sender constraint.
	HolderPublicKey ed25519.PublicKey

	// Ledger is the chain adapter used to canonicalize and hash the
	// transaction context. Select via ledger.Get(Txn.Chain).
	Ledger ledger.Ledger

	// Txn is the concrete transaction being authorized.
	Txn ledger.TxnContext

	// TTL overrides DefaultTTL when non-zero.
	TTL time.Duration
}

// TXN is an issued SPT-Txn Token.
type TXN struct {
	Token       string
	ContextHash string // hex spt_txn_context_hash
	Claims      map[string]any
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Issue verifies the parent CT, binds the transaction, and signs a 30-second
// SPT-Txn Token. signingKey is the tts_issuer Ed25519 private key.
func Issue(req IssueRequest, signingKey crypto.Signer) (*TXN, error) {
	if req.Issuer == "" || req.Audience == "" {
		return nil, fmt.Errorf("issuer and audience required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.Ledger == nil {
		return nil, fmt.Errorf("ledger adapter required")
	}

	// ── 1. Verify the parent CT ──────────────────────────────────────
	parent, err := cttoken.Verify(req.ParentCT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CT invalid: %w", err)
	}

	// ── 2. Sender-constraint chain: holder must match the CT holder ──
	ctHolder, _ := parent["holder_key"].(string)
	if ctHolder == "" {
		return nil, fmt.Errorf("parent CT missing holder_key")
	}
	if !strings.EqualFold(ctHolder, hex.EncodeToString(req.HolderPublicKey)) {
		return nil, fmt.Errorf("holder key does not match the capability's holder (sender-constraint broken)")
	}

	humanAnchor, _ := parent["human_anchor"].(string)
	sub, _ := parent["sub"].(string)
	ctJTI, _ := parent["jti"].(string)
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	// ── 3. Transaction must be within capability scope ────────────────
	txnScope, err := tbac.TxnScope(parentScope, req.Txn)
	if err != nil {
		return nil, err
	}
	if err := tbac.Contains(parentScope, txnScope); err != nil {
		return nil, fmt.Errorf("transaction exceeds capability: %w", err)
	}

	// ── 4. Bind the transaction context (chain-agnostic) ──────────────
	_, ctxHash, err := ledger.ContextHash(req.Ledger, req.Txn)
	if err != nil {
		return nil, err
	}

	// ── 5. Build and sign the token ───────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	jti, err := newJTI()
	if err != nil {
		return nil, err
	}

	claims := map[string]any{
		"iss":                  req.Issuer,
		"sub":                  sub,
		"aud":                  req.Audience,
		"iat":                  now.Unix(),
		"exp":                  exp.Unix(),
		"jti":                  jti,
		"txn_token_type":       "TXN",
		"human_anchor":         humanAnchor,
		"spt_ct_ref":           ctJTI,
		"spt_txn_chain":        req.Ledger.Name(),
		"spt_txn_context_hash": ctxHash,
		"cnf":                  map[string]any{"jkt": dpop.Thumbprint(req.HolderPublicKey)},
	}

	token, err := signJWT(claims, signingKey)
	if err != nil {
		return nil, err
	}
	return &TXN{
		Token:       token,
		ContextHash: ctxHash,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// ParseVerify checks the signature and type of an SPT-Txn Token and returns its
// claims, WITHOUT checking expiry. The M5 engine uses this so signature failures
// (step 1) and expiry failures (step 2) are attributed to distinct steps.
func ParseVerify(tokenStr string, ttsPublicKey ed25519.PublicKey) (map[string]any, error) {
	claims, err := verifyJWT(tokenStr, ttsPublicKey)
	if err != nil {
		return nil, err
	}
	if tt, _ := claims["txn_token_type"].(string); tt != "TXN" {
		return nil, fmt.Errorf("expected txn_token_type=TXN, got %q", tt)
	}
	return claims, nil
}

// Verify checks the signature, type, and expiry of an SPT-Txn Token. It does
// not consult the Trust Registry, recompute the context hash, or verify DPoP —
// those are the executing domain's steps (M5). Use VerifyContextHash and
// CheckSenderConstraint for the latter two.
func Verify(tokenStr string, ttsPublicKey ed25519.PublicKey) (map[string]any, error) {
	claims, err := ParseVerify(tokenStr, ttsPublicKey)
	if err != nil {
		return nil, err
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing exp claim")
	}
	// RFC 7519: a token is valid only while the current time is strictly
	// before exp, so it is expired once now >= exp.
	if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("SPT-Txn Token expired")
	}
	return claims, nil
}

// VerifyContextHash recomputes the context hash for tc using the adapter named
// in the token's spt_txn_chain claim and reports whether it matches
// spt_txn_context_hash. This is M5 Step 8 (transaction binding).
func VerifyContextHash(claims map[string]any, tc ledger.TxnContext) error {
	want, _ := claims["spt_txn_context_hash"].(string)
	chain, _ := claims["spt_txn_chain"].(string)
	if want == "" || chain == "" {
		return fmt.Errorf("token missing context-hash binding claims")
	}
	l, err := ledger.Get(chain)
	if err != nil {
		return err
	}
	_, got, err := ledger.ContextHash(l, tc)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("transaction context hash mismatch: token=%s computed=%s", want, got)
	}
	return nil
}

// CheckSenderConstraint compares the token's cnf.jkt to a thumbprint obtained
// from a verified DPoP proof (dpop.Verify). This is M5 Step 5.
func CheckSenderConstraint(claims map[string]any, dpopThumbprint string) error {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return fmt.Errorf("token missing cnf claim")
	}
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return fmt.Errorf("token missing cnf.jkt")
	}
	if jkt != dpopThumbprint {
		return fmt.Errorf("sender constraint failed: cnf.jkt=%s proof=%s", jkt, dpopThumbprint)
	}
	return nil
}

// ── shared JWT helpers (EdDSA, stdlib) ───────────────────────────────────────

func signJWT(claims map[string]any, key crypto.Signer) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sig, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
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
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

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
