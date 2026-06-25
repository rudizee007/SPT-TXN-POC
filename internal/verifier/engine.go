// Package verifier implements the SPT-Txn eight-step enforcement engine
// (Section 3.3 of draft-coetzee-oauth-spt-txn-tokens) — Milestone 5.
//
// This is the executing domain's (Domain B's) reference verifier. Given a
// presented SPT-Txn Token, a DPoP proof, the parent capability chain, and the
// concrete transaction, it runs eight checks in order and returns allow/deny
// plus the step that decided. Each step is a separate function so failures are
// attributable and unit-testable with golden vectors.
//
// It lives in its own package (not internal/tbac) because it imports the token
// packages, which in turn import tbac — putting the engine in tbac would create
// an import cycle. Nothing imports this package except the Domain B service.
package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/txntoken"
)

// Decision is the engine's verdict. On deny, Step (1-8) and StepName identify
// which check failed and Reason explains why. On allow, Step is 0.
type Decision struct {
	Allow    bool
	Step     int
	StepName string
	Reason   string
}

var stepNames = map[int]string{
	1: "signature", 2: "expiry", 3: "audience", 4: "revocation",
	5: "dpop", 6: "chain", 7: "scope", 8: "context",
}

func deny(step int, err error) Decision {
	return Decision{Allow: false, Step: step, StepName: stepNames[step], Reason: err.Error()}
}

// Input is everything the verifier needs to evaluate a presentation.
type Input struct {
	TxnToken  string            // the SPT-Txn Token (compact JWT)
	DPoPProof string            // DPoP proof of possession of the holder key
	HTM, HTU  string            // HTTP method and URI the DPoP proof must bind
	CT       string            // parent Capability Token (for chain + scope)
	CAT       string            // grandparent CAT (optional; full-chain check)
	Txn       ledger.TxnContext // the concrete transaction being authorized
	Audience  string            // this domain's identifier (expected aud)
}

// Engine runs the eight-step enforcement using a Trust Registry for key
// resolution and revocation.
type Engine struct {
	Registry trustregistry.Registry
	replay   *replayCache
}

// New returns an engine bound to a registry.
func New(reg trustregistry.Registry) *Engine {
	return &Engine{Registry: reg, replay: newReplayCache()}
}

// replayCache records DPoP proof jtis that have been accepted, so the same proof
// cannot be presented twice within its freshness window (review H1).
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
}

func newReplayCache() *replayCache { return &replayCache{seen: make(map[string]time.Time)} }

// checkAndAdd returns false if jti was already recorded and is still within its
// window (a replay); otherwise it records jti for ttl and returns true. Expired
// entries are pruned opportunistically.
func (c *replayCache) checkAndAdd(jti string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return false
	}
	c.seen[jti] = now.Add(ttl)
	return true
}

// Verify runs the eight steps in order, short-circuiting on the first failure.
func (e *Engine) Verify(ctx context.Context, in Input) Decision {
	// Step 1 — signature against the Trust Registry's TTS-issuer key.
	txClaims, err := e.step1Signature(ctx, in.TxnToken)
	if err != nil {
		return deny(1, err)
	}
	// Step 2 — expiry.
	if err := step2Expiry(txClaims); err != nil {
		return deny(2, err)
	}
	// Step 3 — audience.
	if err := step3Audience(txClaims, in.Audience); err != nil {
		return deny(3, err)
	}
	// Step 4 — revocation (issuer key still active in the registry).
	if err := e.step4Revocation(ctx, txClaims); err != nil {
		return deny(4, err)
	}
	// Step 5 — DPoP sender constraint (with token binding + replay protection).
	if err := e.step5DPoP(txClaims, in.TxnToken, in.DPoPProof, in.HTM, in.HTU); err != nil {
		return deny(5, err)
	}
	// Step 6 — capability chain CAT -> CT -> SPT-Txn. Returns CT claims.
	ctClaims, err := e.step6Chain(ctx, txClaims, in.CT, in.CAT)
	if err != nil {
		return deny(6, err)
	}
	// Step 7 — scope containment of the transaction within the capability.
	if err := step7Scope(ctClaims, in.Txn); err != nil {
		return deny(7, err)
	}
	// Step 8 — transaction context-hash binding.
	if err := step8Context(txClaims, in.Txn); err != nil {
		return deny(8, err)
	}
	return Decision{Allow: true}
}

// ── steps ────────────────────────────────────────────────────────────────────

func (e *Engine) step1Signature(ctx context.Context, token string) (map[string]any, error) {
	// Read the issuer from the unverified token only to route the key lookup;
	// the signature check below is what establishes trust.
	routing, err := unverifiedClaims(token)
	if err != nil {
		return nil, err
	}
	iss, _ := routing["iss"].(string)
	if iss == "" {
		return nil, fmt.Errorf("token has no iss")
	}
	key, err := e.resolveKey(ctx, iss, trustregistry.RoleTTSIssuer)
	if err != nil {
		return nil, fmt.Errorf("resolve TTS issuer %q: %w", iss, err)
	}
	claims, err := txntoken.ParseVerify(token, key)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func step2Expiry(txClaims map[string]any) error {
	exp, ok := txClaims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing exp claim")
	}
	if time.Now().Unix() >= int64(exp) {
		return fmt.Errorf("SPT-Txn Token expired")
	}
	return nil
}

func step3Audience(txClaims map[string]any, expected string) error {
	aud, _ := txClaims["aud"].(string)
	if aud != expected {
		return fmt.Errorf("audience %q does not match this domain %q", aud, expected)
	}
	return nil
}

// step4Revocation confirms the TTS issuer key — the one the SPT-Txn signature
// was just verified against in step 1 — is still active in the registry.
//
// Review H2: the previous version also looked up the CT issuer using an
// UNVERIFIED iss field read from the CT token, making a trust decision on
// attacker-controllable input. The CT/CAT issuer active-status is instead
// enforced in step 6, where each key is resolved via Lookup (which returns only
// active records) and the signature is then verified against it — so the
// decision is always tied to a signature-bound issuer.
func (e *Engine) step4Revocation(ctx context.Context, txClaims map[string]any) error {
	iss, _ := txClaims["iss"].(string)
	if _, err := e.resolveKey(ctx, iss, trustregistry.RoleTTSIssuer); err != nil {
		return fmt.Errorf("TTS issuer key not active: %w", err)
	}
	return nil
}

func (e *Engine) step5DPoP(txClaims map[string]any, token, proof, htm, htu string) error {
	// Bind the proof to this specific token (ath) and reject replays (jti).
	ath := dpop.ATH(token)
	jkt, jti, err := dpop.Verify(proof, htm, htu, ath, 0)
	if err != nil {
		return fmt.Errorf("DPoP proof: %w", err)
	}
	if !e.replay.checkAndAdd(jti, dpop.DefaultMaxAge) {
		return fmt.Errorf("DPoP proof replayed (jti already presented)")
	}
	return txntoken.CheckSenderConstraint(txClaims, jkt)
}

// step6Chain verifies the full capability chain CAT -> CT -> SPT-Txn and
// returns the CT claims for the scope check. The executing domain re-derives
// every guarantee from the presented tokens rather than trusting that issuance
// performed them (review H3): it verifies both signatures against registry keys,
// checks the jti/anchor linkage, binds the SPT-Txn holder to the CT holder key,
// and independently re-enforces scope monotonicity (CT scope contained in CAT
// scope) and delegation depth. The CAT must be presented — attenuation cannot be
// verified without the parent.
func (e *Engine) step6Chain(ctx context.Context, txClaims map[string]any, ctToken, catToken string) (map[string]any, error) {
	if ctToken == "" || catToken == "" {
		return nil, fmt.Errorf("the full capability chain (CAT and CT) must be presented")
	}

	ctClaims, err := e.verifyChainToken(ctx, ctToken, cttoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("CT: %w", err)
	}
	catClaims, err := e.verifyChainToken(ctx, catToken, cattoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("CAT: %w", err)
	}

	// Linkage: jti references and humanAnchor propagation across the chain.
	if txClaims["spt_ct_ref"] != ctClaims["jti"] {
		return nil, fmt.Errorf("spt_ct_ref does not reference the presented CT")
	}
	if ctClaims["spt_cat_ref"] != catClaims["jti"] {
		return nil, fmt.Errorf("CT spt_cat_ref does not reference the presented CAT")
	}
	anchor := txClaims["human_anchor"]
	if anchor == nil || anchor != ctClaims["human_anchor"] || anchor != catClaims["human_anchor"] {
		return nil, fmt.Errorf("humanAnchor not propagated unchanged across the chain")
	}

	// Holder binding: the SPT-Txn cnf.jkt must commit to the CT holder key.
	if err := checkHolderBinding(txClaims, ctClaims); err != nil {
		return nil, err
	}

	// Attenuation monotonicity: CT scope must be contained in CAT scope.
	catScope, err := scopeOf(catClaims)
	if err != nil {
		return nil, fmt.Errorf("CAT scope: %w", err)
	}
	ctScope, err := scopeOf(ctClaims)
	if err != nil {
		return nil, fmt.Errorf("CT scope: %w", err)
	}
	if err := tbac.Contains(catScope, ctScope); err != nil {
		return nil, fmt.Errorf("CT scope exceeds CAT scope: %w", err)
	}

	// Delegation depth: CT remaining must be exactly CAT max minus one, >= 0.
	catMax, ok1 := intClaim(catClaims, "delegation_depth_max")
	ctRem, ok2 := intClaim(ctClaims, "delegation_depth_remaining")
	if !ok1 || !ok2 || ctRem != catMax-1 || ctRem < 0 {
		return nil, fmt.Errorf("delegation depth violated (cat_max=%d cap_remaining=%d)", catMax, ctRem)
	}

	return ctClaims, nil
}

// verifyChainToken resolves the token's CT issuer key from the registry and
// verifies the token's signature against it. verify is cttoken.Verify or
// cattoken.Verify.
func (e *Engine) verifyChainToken(ctx context.Context, token string, verify func(string, ed25519.PublicKey) (map[string]any, error)) (map[string]any, error) {
	routing, err := unverifiedClaims(token)
	if err != nil {
		return nil, err
	}
	iss, _ := routing["iss"].(string)
	key, err := e.resolveKey(ctx, iss, trustregistry.RoleCTIssuer)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer %q: %w", iss, err)
	}
	return verify(token, key)
}

// checkHolderBinding confirms the SPT-Txn cnf.jkt is the thumbprint of the CT
// holder key, tying the sender-constrained token to the capability's holder.
func checkHolderBinding(txClaims, ctClaims map[string]any) error {
	ctHolderHex, _ := ctClaims["holder_key"].(string)
	b, err := hex.DecodeString(ctHolderHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("CT holder_key malformed")
	}
	want := dpop.Thumbprint(ed25519.PublicKey(b))
	cnf, _ := txClaims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	if jkt != want {
		return fmt.Errorf("SPT-Txn cnf.jkt does not commit to the CT holder key")
	}
	return nil
}

func scopeOf(claims map[string]any) (tbac.Scope, error) {
	raw, ok := claims["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing capability_scope")
	}
	return tbac.Scope(raw), nil
}

func intClaim(claims map[string]any, name string) (int, bool) {
	f, ok := claims[name].(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

func step7Scope(ctClaims map[string]any, tc ledger.TxnContext) error {
	raw, ok := ctClaims["capability_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("CT missing capability_scope")
	}
	parent := tbac.Scope(raw)
	txnScope, err := tbac.TxnScope(parent, tc)
	if err != nil {
		return err
	}
	return tbac.Contains(parent, txnScope)
}

func step8Context(txClaims map[string]any, tc ledger.TxnContext) error {
	return txntoken.VerifyContextHash(txClaims, tc)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (e *Engine) resolveKey(ctx context.Context, iss string, role trustregistry.Role) (ed25519.PublicKey, error) {
	rec, err := e.Registry.Lookup(ctx, iss, role)
	if err != nil {
		return nil, err
	}
	if rec.KeyType != "Ed25519" || len(rec.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("registry key for %s/%s is not a usable Ed25519 key", iss, role)
	}
	// Defense-in-depth (review C2): refuse a degenerate all-zero public key even
	// if the registry has one marked active, so a seed/placeholder key can never
	// be used to accept a token.
	if isAllZero(rec.PublicKey) {
		return nil, fmt.Errorf("registry key for %s/%s is a degenerate all-zero key", iss, role)
	}
	return ed25519.PublicKey(rec.PublicKey), nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// unverifiedClaims decodes a compact JWT's payload WITHOUT verifying the
// signature. Used only to read the issuer for key routing; every value it
// returns is re-checked against a verified token before it is trusted.
func unverifiedClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return m, nil
}
