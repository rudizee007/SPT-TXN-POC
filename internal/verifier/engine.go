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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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
	CT       string            // single parent Capability Token (one-hop; legacy)
	CTChain   []string          // ordered CT delegation chain, root→leaf (multi-hop)
	CAT       string            // root CAT (required; full-chain check)
	Txn       ledger.TxnContext // the concrete transaction being authorized
	Audience  string            // this domain's identifier (expected aud)

	// Optional privacy-preserving N-hop mode. Instead of presenting the cleartext
	// intermediate CT chain, the holder presents a ZK proof that a valid
	// attenuating, depth-bounded chain links the CAT to the leaf CT — so the
	// intermediate delegation scopes stay hidden. The CAT (root) and leaf CT
	// (CT field) are still presented so the SPT-Txn binds to the leaf. Active only
	// when ChainProof != nil AND Engine.ChainVerifier is set.
	ChainProof []byte   // serialized ChainCircuit Groth16 proof
	ChainH0    *big.Int // human-anchor commitment the proof was made against
	ChainCLeaf *big.Int // leaf-scope commitment the proof was made against
	ChainDepth uint64   // declared maximum delegation depth (D)
}

// ChainVerifierFunc plugs a ZK delegation-chain verifier (e.g.
// zkproof.Artifacts.VerifyChain) into the engine WITHOUT this package importing
// gnark — the caller injects it. The lightweight offline verifier stays
// gnark-free; ZK chain verification is strictly opt-in.
type ChainVerifierFunc func(proof []byte, h0, cleaf *big.Int, maxDepth uint64) error

// Engine runs the eight-step enforcement using a Trust Registry for key
// resolution and revocation.
type Engine struct {
	Registry trustregistry.Registry
	replay   *replayCache

	// ChainVerifier, if set, enables the optional ZK N-hop mode (Input.ChainProof).
	// Left nil, the engine is gnark-free and uses the cleartext chain walk only.
	ChainVerifier ChainVerifierFunc
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
	// Step 6 — capability chain CAT -> CT[…] -> SPT-Txn. Returns leaf CT claims.
	// A presented ZK chain proof selects the privacy-preserving variant; otherwise
	// the cleartext chain walk runs (unchanged).
	var ctClaims map[string]any
	if in.ChainProof != nil {
		ctClaims, err = e.step6ChainZK(ctx, txClaims, in)
	} else {
		ctClaims, err = e.step6Chain(ctx, txClaims, in.CT, in.CAT, in.CTChain)
	}
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

// iatSkew is the tolerance allowed when checking that a token's iat is not in
// the future, accommodating modest clock drift between issuer and verifier.
const iatSkew = 60 // seconds

func step2Expiry(txClaims map[string]any) error {
	exp, ok := txClaims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing exp claim")
	}
	now := time.Now().Unix()
	if now >= int64(exp) {
		return fmt.Errorf("SPT-Txn Token expired")
	}
	// VER-3: reject a token whose iat is in the future beyond a small skew. exp
	// alone does not catch a token issued (or back-/forward-dated) with a future
	// iat. Lenient by iatSkew to avoid clock-skew false rejects.
	if iat, ok := txClaims["iat"].(float64); ok {
		if int64(iat) > now+iatSkew {
			return fmt.Errorf("SPT-Txn Token iat is in the future")
		}
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

// step6Chain verifies the full capability chain CAT -> CT[0] -> … -> CT[n-1] ->
// SPT-Txn and returns the leaf CT claims for the scope check. It supports both a
// single-hop chain (in.CT) and a multi-hop agentic delegation chain (in.CTChain,
// ordered root→leaf); the chain logic is identical, a one-hop chain is just the
// degenerate case.
//
// The executing domain re-derives every guarantee from the presented tokens
// rather than trusting that issuance performed them (review H3). At EVERY link it
// verifies the signature against a registry key, binds the child to its immediate
// parent by hash (so a CT cannot be paired with a different parent than the one
// it was delegated from), re-enforces scope monotonicity (each hop ⊆ its parent)
// and the depth decrement (exactly one per hop, never below zero — this is what
// bounds the delegation depth), and confirms the humanAnchor is propagated
// unchanged. Finally it binds the SPT-Txn to the LEAF CT (jti + holder key). The
// root CAT must be presented — attenuation cannot be verified without it.
func (e *Engine) step6Chain(ctx context.Context, txClaims map[string]any, ctToken, catToken string, ctChain []string) (map[string]any, error) {
	// Normalize the CT list: an explicit chain wins; otherwise fall back to the
	// single-hop CT for backward compatibility.
	cts := ctChain
	if len(cts) == 0 {
		if ctToken == "" {
			return nil, fmt.Errorf("the capability chain (CAT and at least one CT) must be presented")
		}
		cts = []string{ctToken}
	}
	if catToken == "" {
		return nil, fmt.Errorf("the full capability chain (root CAT) must be presented")
	}

	// Root CAT.
	catClaims, err := e.verifyChainToken(ctx, catToken, cattoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("CAT: %w", err)
	}
	catJTI, _ := catClaims["jti"].(string)
	// VER-2: humanAnchor read as a string and required non-empty; everything
	// downstream is compared against this root value.
	anchor, ok := catClaims["human_anchor"].(string)
	if !ok || anchor == "" {
		return nil, fmt.Errorf("CAT missing humanAnchor")
	}
	catMax, ok := intClaim(catClaims, "delegation_depth_max")
	if !ok {
		return nil, fmt.Errorf("CAT missing delegation_depth_max")
	}

	// Walk the CT chain root→leaf. The "parent budget" starts at the CAT's max
	// and must decrease by exactly one at each hop.
	parentClaims := catClaims
	parentToken := catToken
	parentBudget := catMax
	var leaf map[string]any

	for i, ctTok := range cts {
		ctClaims, err := e.verifyChainToken(ctx, ctTok, cttoken.Verify)
		if err != nil {
			return nil, fmt.Errorf("CT[%d]: %w", i, err)
		}

		// VER-1: each CT commits to the compact bytes of its ACTUAL immediate
		// parent (the CAT for the first hop, the prior CT after). Re-derive the
		// hash and require an exact match, so no validly-signed CT can be spliced
		// in under a parent it was not delegated from.
		pSum := sha256.Sum256([]byte(parentToken))
		if ctClaims["spt_parent_hash"] != base64.RawURLEncoding.EncodeToString(pSum[:]) {
			return nil, fmt.Errorf("CT[%d] spt_parent_hash does not match its presented parent", i)
		}

		// jti linkage: first hop references the root CAT; later hops reference
		// their immediate parent CT AND still carry the root CAT ref unchanged.
		if i == 0 {
			if ctClaims["spt_cat_ref"] != catJTI {
				return nil, fmt.Errorf("CT[0] spt_cat_ref does not reference the presented CAT")
			}
		} else {
			parentJTI, _ := parentClaims["jti"].(string)
			if ctClaims["spt_parent_ref"] != parentJTI {
				return nil, fmt.Errorf("CT[%d] spt_parent_ref does not reference its parent CT", i)
			}
			if ctClaims["spt_cat_ref"] != catJTI {
				return nil, fmt.Errorf("CT[%d] spt_cat_ref does not reference the root CAT", i)
			}
		}

		// VER-2: humanAnchor unchanged at this hop (type-asserted to avoid a
		// panic on an uncomparable value in a signature-verified token).
		a, ok := ctClaims["human_anchor"].(string)
		if !ok || a == "" || a != anchor {
			return nil, fmt.Errorf("humanAnchor not propagated unchanged at CT[%d]", i)
		}

		// Attenuation monotonicity: this hop's scope ⊆ its parent's scope.
		parentScope, err := scopeOf(parentClaims)
		if err != nil {
			return nil, fmt.Errorf("parent scope at CT[%d]: %w", i, err)
		}
		ctScope, err := scopeOf(ctClaims)
		if err != nil {
			return nil, fmt.Errorf("CT[%d] scope: %w", i, err)
		}
		if err := tbac.Contains(parentScope, ctScope); err != nil {
			return nil, fmt.Errorf("CT[%d] scope exceeds its parent: %w", i, err)
		}

		// Delegation depth: remaining must be exactly the parent's budget minus
		// one, and never negative. Enforced per hop, this caps the chain length.
		ctRem, ok := intClaim(ctClaims, "delegation_depth_remaining")
		if !ok || ctRem != parentBudget-1 || ctRem < 0 {
			return nil, fmt.Errorf("delegation depth violated at CT[%d] (parent_budget=%d this_remaining=%d)", i, parentBudget, ctRem)
		}

		// Advance to the next hop.
		parentClaims = ctClaims
		parentToken = ctTok
		parentBudget = ctRem
		leaf = ctClaims
	}

	// Bind the SPT-Txn to the LEAF capability: jti reference, humanAnchor, and
	// the holder key (DPoP cnf.jkt) all commit to the final delegated CT.
	if txClaims["spt_ct_ref"] != leaf["jti"] {
		return nil, fmt.Errorf("spt_ct_ref does not reference the leaf CT")
	}
	txAnchor, ok := txClaims["human_anchor"].(string)
	if !ok || txAnchor == "" || txAnchor != anchor {
		return nil, fmt.Errorf("SPT-Txn humanAnchor does not match the chain")
	}
	if err := checkHolderBinding(txClaims, leaf); err != nil {
		return nil, err
	}

	return leaf, nil
}

// step6ChainZK is the privacy-preserving variant of step 6: the intermediate
// delegation chain is proven in zero knowledge (Input.ChainProof) instead of
// being presented in clear, so the verifier never sees the intermediate scopes.
// The CAT (root) and the leaf CT (Input.CT) are still presented so the SPT-Txn
// can be bound to the leaf and the human-anchor checked end to end. The ZK proof
// attests the hidden middle: a valid attenuating, depth-bounded chain links the
// CAT's authority to the leaf's scope.
//
// Integration seam: H0/CLeaf are the public inputs the proof was made against.
// Cryptographically binding H0 to the CAT's human_anchor and CLeaf to the leaf
// CT's declared scope requires the token format to carry the Poseidon2
// commitments (the planned human_anchor migration). Until then this path proves
// such a chain EXISTS for (H0, CLeaf, D) and verifies the endpoints in clear; it
// is gated behind an explicit, operator-opted-in ChainVerifier.
func (e *Engine) step6ChainZK(ctx context.Context, txClaims map[string]any, in Input) (map[string]any, error) {
	if e.ChainVerifier == nil {
		return nil, fmt.Errorf("a ZK chain proof was presented but no ChainVerifier is configured")
	}
	if in.ChainH0 == nil || in.ChainCLeaf == nil {
		return nil, fmt.Errorf("ZK chain mode requires the H0 and CLeaf public inputs")
	}
	if in.CAT == "" || in.CT == "" {
		return nil, fmt.Errorf("ZK chain mode still requires the root CAT and the leaf CT to be presented")
	}

	// Endpoints: verify the CAT and the leaf CT signatures against the registry.
	catClaims, err := e.verifyChainToken(ctx, in.CAT, cattoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("CAT: %w", err)
	}
	anchor, ok := catClaims["human_anchor"].(string)
	if !ok || anchor == "" {
		return nil, fmt.Errorf("CAT missing humanAnchor")
	}
	leaf, err := e.verifyChainToken(ctx, in.CT, cttoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("leaf CT: %w", err)
	}

	// ZK proof: a valid attenuating, depth-bounded chain links CAT -> leaf.
	if err := e.ChainVerifier(in.ChainProof, in.ChainH0, in.ChainCLeaf, in.ChainDepth); err != nil {
		return nil, fmt.Errorf("ZK chain proof invalid: %w", err)
	}

	// Endpoint human-anchor consistency: CAT == leaf == SPT-Txn.
	la, ok := leaf["human_anchor"].(string)
	if !ok || la != anchor {
		return nil, fmt.Errorf("humanAnchor not propagated to the leaf CT")
	}
	// Bind the SPT-Txn to the leaf CT (jti reference, humanAnchor, holder key).
	if txClaims["spt_ct_ref"] != leaf["jti"] {
		return nil, fmt.Errorf("spt_ct_ref does not reference the leaf CT")
	}
	txAnchor, ok := txClaims["human_anchor"].(string)
	if !ok || txAnchor == "" || txAnchor != anchor {
		return nil, fmt.Errorf("SPT-Txn humanAnchor does not match the chain")
	}
	if err := checkHolderBinding(txClaims, leaf); err != nil {
		return nil, err
	}
	return leaf, nil
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
