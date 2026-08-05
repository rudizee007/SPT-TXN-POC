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

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
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
	CT        string            // single parent Capability Token (one-hop; legacy)
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
	ChainH0    *big.Int // anchor commitment the proof was made against (carried with the proof)
}

// ChainVerifierFunc plugs a ZK delegation-chain verifier (e.g. one wrapping
// zkproof.Artifacts.VerifyChain) into the engine WITHOUT this package importing
// gnark — the caller injects it. The engine passes the leaf scope (maxAmount +
// currency) and max depth taken from the PRESENTED tokens; the injected verifier
// derives the leaf-scope commitment (CLeaf) from them and verifies, so the proof
// is bound to the leaf CT actually presented. The lightweight offline verifier
// stays gnark-free; ZK chain verification is strictly opt-in.
type ChainVerifierFunc func(proof []byte, h0 *big.Int, leafMaxAmount uint64, leafCurrency string, maxDepth uint64) error

// Engine runs the eight-step enforcement using a Trust Registry for key
// resolution and revocation.
type Engine struct {
	Registry trustregistry.Registry
	replay   *replayCache

	// ChainVerifier, if set, enables the optional ZK N-hop mode (Input.ChainProof).
	// Left nil, the engine is gnark-free and uses the cleartext chain walk only.
	ChainVerifier ChainVerifierFunc

	// StatusResolver, if set, enables per-token status-list revocation
	// (docs/spec/STATUS-LIST.md). It holds verified, cached Status Lists and is
	// consulted OFFLINE for every chain/txn token that carries a `status`
	// claim. Left nil, status-list checking is disabled (no regression) and
	// revocation relies on issuer-key cascade + short TTL alone. Populate it
	// out of band from signed Status List Tokens, never in the hot path.
	StatusResolver *statuslist.Resolver
}

// checkStatus consults the status-list resolver for a token, if both the
// resolver is configured and the token carries a status claim. A malformed
// status claim, an unavailable list, a revoked/suspended entry, or an unknown
// status all fail closed. Absence of a status claim (or of a resolver) is not
// an error — such a token simply is not in scope for status-list revocation.
func (e *Engine) checkStatus(claims map[string]any) error {
	if e.StatusResolver == nil {
		return nil
	}
	ref, ok, err := statuslist.ReferenceFromClaims(claims)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return e.StatusResolver.Check(ref)
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
	// Step 4 — revocation: issuer key still active in the registry, AND
	// (if a StatusResolver is configured) the SPT-Txn token is not revoked or
	// suspended via its status-list entry. Both fail closed.
	if err := e.step4Revocation(ctx, txClaims); err != nil {
		return deny(4, err)
	}
	if err := e.checkStatus(txClaims); err != nil {
		return deny(4, fmt.Errorf("SPT-Txn status: %w", err))
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
	// Per-token status-list revocation for the root CAT (no-op unless a
	// StatusResolver is configured and the CAT carries a status claim).
	if err := e.checkStatus(catClaims); err != nil {
		return nil, fmt.Errorf("CAT status: %w", err)
	}

	// Walk the CT chain root→leaf. The "parent budget" starts at the CAT's max
	// and must decrease by exactly one at each hop.
	parentClaims := catClaims
	parentToken := catToken
	parentBudget := catMax
	var leaf map[string]any

	// Effective scope = the INTERSECTION of every scope from the root CAT to
	// the leaf. Per-hop Contains(parent, child) only inspects the child's
	// declared dimensions, so a hop that DROPS a ceiling/equality dimension
	// (e.g. omits max_amount or currency) would otherwise leave that axis
	// unconstrained at transaction time — a widening disguised as attenuation
	// (docs/THREAT-MODEL.md §4.2). We defeat that here, at the enforcement
	// point: start from the root's scope and overlay each hop. Because a hop
	// can only tighten or drop a dimension it inherited (Contains rejects any
	// dimension not present in the parent), overlaying present dimensions and
	// RETAINING dropped ones yields the tightest constraint on every axis the
	// chain ever declared. The transaction is checked against THIS in step 7.
	effective := tbac.Scope{}
	if rootScope, err := scopeOf(catClaims); err == nil {
		for k, v := range rootScope {
			effective[k] = v
		}
	}

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

		// TTL monotonicity, re-verified at validation (defense in depth against
		// a delegator whose construction-time check was bypassed): each hop's
		// validity window must sit inside its parent's. A hop that outlives its
		// parent is a lifetime escalation, exactly like a scope widening.
		ctExp, ok := intClaim(ctClaims, "exp")
		if !ok {
			return nil, fmt.Errorf("CT[%d] missing exp", i)
		}
		parentExp, ok := intClaim(parentClaims, "exp")
		if !ok {
			return nil, fmt.Errorf("parent of CT[%d] missing exp", i)
		}
		if ctExp > parentExp {
			return nil, fmt.Errorf("CT[%d] outlives its parent (exp %d > %d): TTL must attenuate", i, ctExp, parentExp)
		}

		// Per-token status-list revocation for this hop: a revoked intermediate
		// invalidates the whole chain, not just the leaf.
		if err := e.checkStatus(ctClaims); err != nil {
			return nil, fmt.Errorf("CT[%d] status: %w", i, err)
		}

		// Overlay this hop's declared dimensions onto the effective scope.
		// Every dimension present here is ⊆ its parent (checked just above)
		// and was already present in `effective`, so this only ever tightens;
		// dimensions this hop dropped keep their tighter ancestor value.
		for k, v := range ctScope {
			effective[k] = v
		}

		// Advance to the next hop.
		parentClaims = ctClaims
		parentToken = ctTok
		parentBudget = ctRem
		leaf = ctClaims
	}

	// Hand the accumulated effective scope to step 7 without disturbing the
	// leaf's own claims (binding checks below rely on the leaf as-presented).
	leaf[effectiveScopeClaim] = map[string]any(effective)

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
// Endpoint binding (both public inputs are now cryptographically bound to the
// presented tokens, closing the adversarial-review gap):
//   - H0 (the proof's root commitment) MUST equal the field element of the
//     presented CAT's humanAnchor — enforced below — so the proof cannot be a
//     valid chain rooted at a different anchor. This requires Poseidon2-committed
//     anchors (zkdid.Compute equals zkproof's commitment over the same inputs).
//   - CLeaf (the leaf-scope commitment) is derived by the injected ChainVerifier
//     from the presented leaf CT's own scope, so the proof only verifies for the
//     exact leaf scope presented (see TestChainVerifierFunc_Injection).
//   - D (max depth) is taken from the presented CAT.
//
// The intermediate hop scopes remain hidden; only the endpoints are in clear.
// Still gated behind an explicit, operator-opted-in ChainVerifier.
func (e *Engine) step6ChainZK(ctx context.Context, txClaims map[string]any, in Input) (map[string]any, error) {
	if e.ChainVerifier == nil {
		return nil, fmt.Errorf("a ZK chain proof was presented but no ChainVerifier is configured")
	}
	if in.ChainH0 == nil {
		return nil, fmt.Errorf("ZK chain mode requires the H0 public input")
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
	// Bind H0 to THIS CAT's humanAnchor. The proof's root public input (H0) is
	// carried with the proof; without this check a holder could present a valid
	// proof rooted at a DIFFERENT (attacker-controlled) anchor together with an
	// unrelated CAT, since the endpoint-equality checks below only compare the
	// presented tokens' anchors to each other, not to the proof's root. The
	// CAT humanAnchor is the hex of the 32-byte field element that H0 also
	// represents (zkdid.Commitment.BigInt() == SetBytes(anchor-bytes)), so an
	// exact equality binds the proof to this root. This closes the ZK-path gap
	// noted in the adversarial review; it is a verifier-side check requiring no
	// circuit change. ZK mode therefore requires Poseidon2-committed anchors.
	anchorBytes, err := hex.DecodeString(anchor)
	if err != nil || len(anchorBytes) != 32 {
		return nil, fmt.Errorf("CAT humanAnchor is not a 32-byte commitment (ZK mode requires a Poseidon2-committed anchor)")
	}
	if new(big.Int).SetBytes(anchorBytes).Cmp(in.ChainH0) != 0 {
		return nil, fmt.Errorf("ZK chain H0 does not equal the presented CAT humanAnchor: proof is rooted at a different anchor")
	}
	leaf, err := e.verifyChainToken(ctx, in.CT, cttoken.Verify)
	if err != nil {
		return nil, fmt.Errorf("leaf CT: %w", err)
	}

	// Bind the proof to the PRESENTED tokens: the leaf-scope commitment (CLeaf) is
	// derived (by the injected verifier) from the leaf CT's own scope, and the max
	// depth (D) from the CAT — so the proof cannot claim a different leaf scope or
	// a deeper chain than what is presented. H0 was bound to the CAT humanAnchor
	// above, so all three public inputs are now pinned to the presented tokens.
	scope, ok := leaf["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("leaf CT missing capability_scope")
	}
	maxAmt, ok := scope["max_amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("leaf CT scope missing max_amount")
	}
	currency, ok := scope["currency"].(string)
	if !ok {
		return nil, fmt.Errorf("leaf CT scope missing currency")
	}
	catMax, ok := intClaim(catClaims, "delegation_depth_max")
	if !ok {
		return nil, fmt.Errorf("CAT missing delegation_depth_max")
	}
	if err := e.ChainVerifier(in.ChainProof, in.ChainH0, uint64(maxAmt), currency, uint64(catMax)); err != nil {
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
	// The ZK proof validated the transaction ceilings against the LEAF scope
	// (maxAmt/currency above). Set the effective-scope claim explicitly to the
	// leaf's own capability_scope so step7Scope enforces the same scope the
	// proof was checked against — and never reads a stale or attacker value.
	// (verifyChainToken has already stripped any reserved-prefix claim that
	// arrived on the token, so this assignment is the sole writer.)
	if ls, ok := leaf["capability_scope"].(map[string]any); ok {
		leaf[effectiveScopeClaim] = ls
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
	claims, err := verify(token, key)
	if err != nil {
		return nil, err
	}
	// Reserved-namespace hygiene: the verifier stashes synthetic, internal
	// values (e.g. __spt_effective_scope) on claim maps AFTER verification.
	// Strip any reservedClaimPrefix key that arrived ON a real token so a
	// signed token can never pre-populate the synthetic namespace and have it
	// survive into step 7 — closing the ZK-path self-poisoning gap
	// structurally rather than by convention.
	for k := range claims {
		if strings.HasPrefix(k, reservedClaimPrefix) {
			delete(claims, k)
		}
	}
	return claims, nil
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

// reservedClaimPrefix namespaces synthetic, verifier-internal claims. Any
// token claim with this prefix is stripped at verification (verifyChainToken)
// so it can only ever be set by the verifier, never by a token issuer.
const reservedClaimPrefix = "__spt_"

// effectiveScopeClaim is a synthetic, verifier-internal claim: step6Chain
// stashes the chain-intersection scope here for step7Scope to enforce. It is
// never signed, never emitted, and never present on a real token.
const effectiveScopeClaim = reservedClaimPrefix + "effective_scope"

func step7Scope(ctClaims map[string]any, tc ledger.TxnContext) error {
	// Prefer the chain-intersection scope computed in step 6; fall back to the
	// leaf's own scope only if it is absent (e.g. the ZK chain path, which does
	// not expose intermediate scopes). Checking the transaction against the
	// intersection is what makes a dropped-ceiling hop non-exploitable.
	raw, ok := ctClaims[effectiveScopeClaim].(map[string]any)
	if !ok {
		raw, ok = ctClaims["capability_scope"].(map[string]any)
		if !ok {
			return fmt.Errorf("CT missing capability_scope")
		}
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
