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
	"math"
	"math/big"
	"strconv"
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
// regRoot is the Merkle root of the verifier's OWN registered-CT-issuer set. It
// is the second security-critical binding on this seam and it used to be
// invisible: the parameter did not exist, so the closure had to capture a root
// from somewhere, and nothing here could supply, inspect or assert it. An
// implementation that bound the proof to a root the PROVER produced would accept
// a chain whose hops were signed by keys of the prover's choosing — a soundness
// failure, not a freshness one — and it would look identical from this package.
// Both in-repo examples of the call sequence (cmd/zk-bench, cmd/loadbench) feed
// ProveChain's returned root straight back into VerifyChain, which is correct for
// a benchmark and is the shape a reader copies.
//
// Passing it explicitly is a nudge, not a guarantee — a closure may ignore a
// parameter. EnableChainZK is what turns it into an assertion.
type ChainVerifierFunc func(proof []byte, h0, regRoot *big.Int, leafMaxAmount uint64, leafCurrency string, maxDepth uint64) error

// ChainSelfTestVector is a known-good chain proof together with the public
// inputs it was produced for.
//
// The OPERATOR supplies it, because only they know which artifacts their
// injected verifier was built against; a vector shipped with this package would
// not verify against a deployment that built its own circuit, and "skip with a
// warning" is the shape that decays into never running. The engine supplies the
// discipline: which perturbations to try and what each one proves.
type ChainSelfTestVector struct {
	Proof         []byte
	H0            *big.Int
	LeafMaxAmount uint64
	LeafCurrency  string
	MaxDepth      uint64
}

// EnableChainZK turns on the optional ZK N-hop mode, and refuses to do so unless
// the injected verifier demonstrably binds every public input.
//
// WHY THIS IS A CONSTRUCTOR AND NOT A FIELD. The binding lives inside a closure
// this package cannot read. Documenting the requirement puts the security
// property in a comment an integrator may not reach — and the type's own comment
// previously explained the CLeaf binding in detail while never mentioning the
// registry root at all. So the property is asserted instead: the verifier is
// exercised against a known-good vector, then once per public input with that
// input perturbed, and every perturbation MUST fail. A closure that ignores an
// input passes the baseline and fails its perturbation, here, at startup, rather
// than in production against a chain it should have rejected.
//
// This is the runtime form of what scripts/mutate-*.sh do in CI: a guard that
// has never been observed failing is indistinguishable from one that cannot.
//
// Groth16 verification is exact in its public inputs, so any perturbation breaks
// the pairing check for a correctly-wired verifier. A perturbation that still
// verifies means that input is not reaching the verification equation.
// # maxLeafWindow bounds a known gap, and is required
//
// The ZK path hides intermediate hops, so it checks NEITHER their expiry NOR
// their revocation status — the cleartext walk does both. That gap is tracked
// privately and is not closed by this parameter.
//
// What this parameter does is BOUND it. Without a bound, a revoked intermediate
// keeps granting authority until the ORIGINAL grant expires, which may be
// months. With one, the exposure is capped at the window: the holder must
// re-present a leaf whose lifetime fits inside it.
//
// Set it at or below the status-list TTL. Revocation is not instantaneous on
// the cleartext path either — it is only as fresh as the cached status list —
// so matching the two makes the paths comparable rather than making one
// perfect. That comparison is the honest way to describe this to an operator.
//
// Required, with no default. A zero value would mean "unbounded", which is the
// state this exists to prevent, and a default would let a deployment inherit a
// number nobody chose for their revocation cadence.
func (e *Engine) EnableChainZK(cv ChainVerifierFunc, trustedIssuerRoot *big.Int, maxLeafWindow time.Duration, vec ChainSelfTestVector) error {
	if cv == nil {
		return fmt.Errorf("EnableChainZK: nil ChainVerifierFunc")
	}
	if trustedIssuerRoot == nil {
		return fmt.Errorf("EnableChainZK: no trusted issuer root — ZK mode cannot be enabled " +
			"without the verifier's own registered-CT-issuer set to bind proofs against")
	}
	if maxLeafWindow <= 0 {
		return fmt.Errorf("EnableChainZK: maxLeafWindow must be positive. The ZK path does not " +
			"check intermediate hops for expiry or revocation, so an unbounded leaf lifetime " +
			"means a revoked intermediate keeps granting authority until the original grant " +
			"expires. Set this at or below your status-list TTL")
	}
	if len(vec.Proof) == 0 || vec.H0 == nil {
		return fmt.Errorf("EnableChainZK: self-test vector is incomplete (proof and H0 are required)")
	}

	if err := cv(vec.Proof, vec.H0, trustedIssuerRoot, vec.LeafMaxAmount, vec.LeafCurrency, vec.MaxDepth); err != nil {
		return fmt.Errorf("EnableChainZK: the self-test vector does not verify through the injected "+
			"verifier: %w. The vector and the verifier disagree — wrong artifacts, a stale "+
			"verifying key, or a root that is not the one the vector was proved against", err)
	}

	bump := func(x *big.Int) *big.Int { return new(big.Int).Add(x, big.NewInt(1)) }
	badProof := append([]byte(nil), vec.Proof...)
	badProof[len(badProof)/2] ^= 0x01

	probes := []struct {
		binding string
		proves  string
		err     error
	}{
		{"H0", "the proof is bound to the presented CAT's human anchor",
			cv(vec.Proof, bump(vec.H0), trustedIssuerRoot, vec.LeafMaxAmount, vec.LeafCurrency, vec.MaxDepth)},
		{"RegRoot", "the proof is bound to THIS verifier's issuer set, not one the prover chose",
			cv(vec.Proof, vec.H0, bump(trustedIssuerRoot), vec.LeafMaxAmount, vec.LeafCurrency, vec.MaxDepth)},
		{"leafMaxAmount", "CLeaf is derived from the presented leaf's amount ceiling",
			cv(vec.Proof, vec.H0, trustedIssuerRoot, vec.LeafMaxAmount+1, vec.LeafCurrency, vec.MaxDepth)},
		{"leafCurrency", "CLeaf is derived from the presented leaf's currency",
			cv(vec.Proof, vec.H0, trustedIssuerRoot, vec.LeafMaxAmount, vec.LeafCurrency+"X", vec.MaxDepth)},
		{"maxDepth", "the chain length is bounded by D taken from the CAT",
			cv(vec.Proof, vec.H0, trustedIssuerRoot, vec.LeafMaxAmount, vec.LeafCurrency, vec.MaxDepth+1)},
		{"proof bytes", "the proof itself is checked rather than assumed",
			cv(badProof, vec.H0, trustedIssuerRoot, vec.LeafMaxAmount, vec.LeafCurrency, vec.MaxDepth)},
	}
	for _, p := range probes {
		if p.err == nil {
			return fmt.Errorf("EnableChainZK: REFUSING to enable ZK chain mode — the injected "+
				"verifier accepted a proof with %s perturbed, so it does not bind that input. "+
				"It should establish that %s. Until it does, a ZK-mode chain proves less than "+
				"the cleartext walk it replaces", p.binding, p.proves)
		}
	}

	e.chainVerifier = cv
	e.trustedIssuerRoot = trustedIssuerRoot
	e.maxZKLeafWindow = maxLeafWindow
	return nil
}

// Engine runs the eight-step enforcement using a Trust Registry for key
// resolution and revocation.
type Engine struct {
	Registry trustregistry.Registry
	replay   *replayCache

	// UNEXPORTED, deliberately: set only through EnableChainZK, which refuses
	// unless the injected verifier demonstrably binds every public input. An
	// assignable field would let a deployment enable ZK mode with a closure that
	// binds nothing, and nothing here could tell. Left unset, the engine is
	// gnark-free and uses the cleartext chain walk only.
	chainVerifier     ChainVerifierFunc
	trustedIssuerRoot *big.Int
	maxZKLeafWindow   time.Duration

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
// status claim, an unavailable list, a STALE list, a revoked/suspended entry, or
// an unknown status all fail closed. Absence of a status claim (or of a resolver) is not
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
	return e.StatusResolver.Check(ref, time.Now())
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
	// Monotonic TTL, final hop (DELEGATION-INTENT-MCP.md §1.2 invariant 2).
	//
	// step6Chain enforces exp(CT[i]) ≤ exp(parent) inside its loop, but the
	// SPT-Txn is itself a child of the leaf CT and that last hop was checked
	// nowhere in the verifier. `txntoken.Issue` enforces it and the verifier
	// trusted that it had — which is precisely the asymmetry step 6 exists to
	// remove, and which invariant 2 names outright: a child that outlives its
	// parent MUST be rejected at construction AND at verification, so that a
	// malicious issuer cannot extend a lifetime.
	//
	// Deliberately placed HERE rather than inside each step-6 variant. Both
	// variants return the leaf, so one check on the shared return value is one
	// implementation. Two copies would be two implementations of one invariant,
	// which is the arrangement the canonicalization rule in the spec exists to
	// forbid: two implementations of one thing diverge over time, and a
	// divergence in an authorization invariant is a bypass.
	if err := checkTxnLifetime(txClaims, ctClaims); err != nil {
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

// SettlementFacts are the authorization facts a SETTLER needs, extracted from
// tokens the engine has verified. Every field here comes from an issuer-signed
// token, not from any caller-supplied summary — that is the entire point of
// returning them.
type SettlementFacts struct {
	HumanAnchor string // the CAT's human_anchor, hex — who is accountable
	MaxAmount   string // the leaf CT's max_amount ceiling, decimal — the granted limit
	Currency    string // the leaf CT's currency, if the scope pins one
}

// VerifyForSettlement runs the enforcement engine WITHOUT step 5 (DPoP
// proof-of-possession) and returns the signed authorization facts.
//
// # Why step 5 is skipped, and why that is correct rather than a shortcut
//
// Step 5 proves the PRESENTER holds the holder key bound in the token. That is
// the payer-side GATE's obligation at decision time: it holds the key and
// proves possession when it decides. A SETTLER is not re-presenting the token;
// it is checking that a valid authorization was issued and binds THIS payment.
// Settlement additionally requires the payer's own on-chain signature, which no
// captured token can supply — so proof-of-possession grants a settler nothing,
// while authenticity of the delegation (steps 1-4, 6, 7, 8) is exactly what the
// settler must not take on trust from a JSON summary.
//
// This is the verification that lets a settler derive the ceiling and the
// humanAnchor from issuer-signed tokens instead of an editable document —
// closing the "unsigned decision" gap (review #6 A1) using the authorization
// object the spec already defines, with no new signing key.
//
// It runs the SAME step functions as Verify, in the same order, minus step 5.
// One implementation of each step; this is not a second verifier.
func (e *Engine) VerifyForSettlement(ctx context.Context, in Input) (SettlementFacts, Decision) {
	var facts SettlementFacts

	txClaims, err := e.step1Signature(ctx, in.TxnToken)
	if err != nil {
		return facts, deny(1, err)
	}
	if err := step2Expiry(txClaims); err != nil {
		return facts, deny(2, err)
	}
	if err := step3Audience(txClaims, in.Audience); err != nil {
		return facts, deny(3, err)
	}
	if err := e.step4Revocation(ctx, txClaims); err != nil {
		return facts, deny(4, err)
	}
	if err := e.checkStatus(txClaims); err != nil {
		return facts, deny(4, fmt.Errorf("SPT-Txn status: %w", err))
	}
	// Step 5 (DPoP) deliberately omitted — see the doc comment.
	var ctClaims map[string]any
	if in.ChainProof != nil {
		ctClaims, err = e.step6ChainZK(ctx, txClaims, in)
	} else {
		ctClaims, err = e.step6Chain(ctx, txClaims, in.CT, in.CAT, in.CTChain)
	}
	if err != nil {
		return facts, deny(6, err)
	}
	if err := checkTxnLifetime(txClaims, ctClaims); err != nil {
		return facts, deny(6, err)
	}
	if err := step7Scope(ctClaims, in.Txn); err != nil {
		return facts, deny(7, err)
	}
	if err := step8Context(txClaims, in.Txn); err != nil {
		return facts, deny(8, err)
	}

	// Facts, extracted only after every check above passed. The anchor comes
	// from the SPT-Txn token (bound in step 6 to equal the CAT's); the ceiling
	// from the leaf CT scope that step 7 checked the payment against.
	if a, ok := txClaims["human_anchor"].(string); ok {
		facts.HumanAnchor = a
	}
	scope, _ := ctClaims[effectiveScopeClaim].(map[string]any)
	if scope == nil {
		scope, _ = ctClaims["capability_scope"].(map[string]any)
	}
	if scope != nil {
		if m, ok := scope["max_amount"]; ok {
			facts.MaxAmount = decimalString(m)
		}
		if c, ok := scope["currency"].(string); ok {
			facts.Currency = c
		}
	}
	return facts, Decision{Allow: true}
}

// decimalString renders a JSON-decoded numeric ceiling as a plain base-10
// string, never scientific notation. A ceiling that arrives as float64 (JSON
// numbers do, without UseNumber) would otherwise render as "5e+06" under %v and
// be rejected by the settler's decimal parser — a fail-closed availability bug
// for large ceilings. json.Number and string forms pass through unchanged.
func decimalString(v any) string {
	switch n := v.(type) {
	case json.Number:
		return n.String()
	case string:
		return n
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
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
	// iat is REQUIRED, not optional.
	//
	// This check previously ran only `if iat, ok := ...; ok`, so omitting the
	// claim — or sending it as a string — made it silently not run. A check that
	// an attacker can switch off by leaving a field out is not a check. All
	// three issuers always set iat, and `-03` §Verification step 2 requires
	// rejecting a token outside its `iat`/`exp` bounds, so absence is malformed
	// rather than permissive.
	iat, ok := txClaims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing or non-numeric iat claim")
	}

	// exp MUST be strictly after iat (DELEGATION-INTENT-MCP.md §1.2 invariant 2).
	// Enforced with no skew allowance: this is a relationship between two fields
	// of one token, not a comparison against a clock, so no amount of drift makes
	// an inverted or zero-length window legitimate.
	if int64(exp) <= int64(iat) {
		return fmt.Errorf("SPT-Txn Token exp %d is not after iat %d", int64(exp), int64(iat))
	}

	// VER-3: reject a token whose iat is in the future beyond a small skew. exp
	// alone does not catch a token issued (or back-/forward-dated) with a future
	// iat.
	//
	// iatSkew is applied ASYMMETRICALLY and deliberately: it widens tolerance for
	// a forward-dated iat and is never added to exp. Skew may cause a verifier to
	// reject early; it must never let one accept late.
	if int64(iat) > now+iatSkew {
		return fmt.Errorf("SPT-Txn Token iat is in the future")
	}
	return nil
}

// step3Audience binds the token to THIS deployment.
//
// Both halves fail closed, and neither did before.
//
// An UNSET expected audience is a configuration error, not "no audience
// policy". Previously `expected` defaulted to "" and a token carrying no `aud`
// also read as "", so `"" != ""` was false and the step passed: an operator who
// forgot to configure Audience accepted tokens minted for anybody. That is the
// worst shape of fail-open — it appears only in the deployment that skipped a
// setting, so it never shows up in a test suite that always sets one.
//
// A MISSING or non-string `aud` is likewise rejected rather than coerced. The
// old `aud, _ := ...(string)` silently produced "" for an absent claim and for
// a JSON array (RFC 7519 permits an array audience), so an array-valued `aud`
// was treated as empty. Rejecting is correct here: this engine states a single
// audience, and an array is a shape it has not been specified to interpret.
// Accepting one by accident is how a token minted for a different member of
// that array gets honoured.
func step3Audience(txClaims map[string]any, expected string) error {
	if expected == "" {
		return fmt.Errorf("verifier has no configured audience: refusing to evaluate " +
			"audience binding. Set Engine.Audience to this deployment's identifier — an " +
			"unset audience would accept a token minted for any relying party")
	}
	raw, present := txClaims["aud"]
	if !present {
		return fmt.Errorf("SPT-Txn Token has no aud claim; this domain is %q", expected)
	}
	aud, ok := raw.(string)
	if !ok {
		return fmt.Errorf("aud claim is %T, not a string; this engine binds a single audience", raw)
	}
	if aud != expected {
		return fmt.Errorf("audience %q does not match this domain %q", aud, expected)
	}
	return nil
}

// checkChainTokenTemporal applies to a CAT or CT the same intra-token temporal
// rules step2Expiry applies to the SPT-Txn token.
//
// The chain previously checked only RELATIVE lifetime — exp(child) <= exp(parent)
// — plus signature, parent-hash binding, status and scope. `iat` was written by
// both issuers and read by neither during verification.
//
// Expiry against the clock is already covered transitively and is deliberately
// not re-checked here: step2Expiry gives txn.exp > now, checkTxnLifetime gives
// txn.exp <= leaf.exp, and each hop gives ct.exp <= parent.exp, so a live
// transaction token implies every ancestor is unexpired.
//
// What was NOT covered is a token used before it was issued. A capability
// minted with a forward-dated iat — a grant intended to become valid next month
// — is usable immediately today, because nothing looks. The same asymmetric
// skew rule as step2Expiry applies: tolerance widens for a forward-dated iat and
// is never added to exp, so drift can make a verifier reject early but never
// accept late.
func checkChainTokenTemporal(label string, claims map[string]any) error {
	iat, ok := intClaim(claims, "iat")
	if !ok {
		return fmt.Errorf("%s missing or non-numeric iat", label)
	}
	exp, ok := intClaim(claims, "exp")
	if !ok {
		return fmt.Errorf("%s missing or non-numeric exp", label)
	}
	// Intra-token relationship, so no skew allowance: no amount of clock drift
	// makes an inverted or zero-length validity window legitimate.
	if exp <= iat {
		return fmt.Errorf("%s exp %d is not after iat %d", label, exp, iat)
	}
	if iat > time.Now().Unix()+iatSkew {
		return fmt.Errorf("%s iat is in the future: the capability is not yet valid", label)
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
	// dpop.Verify checks ath only when it is given one — correct for that package,
	// which also serves flows with no access token. This engine is never in one of
	// those flows: a token is being presented, so the proof must be bound to it.
	// Assert that rather than assume it, here where the assumption is true.
	if ath == "" {
		return fmt.Errorf("cannot bind the DPoP proof to the presented token")
	}
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
	if err := checkChainTokenTemporal("CAT", catClaims); err != nil {
		return nil, err
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
		if err := checkChainTokenTemporal(fmt.Sprintf("CT[%d]", i), ctClaims); err != nil {
			return nil, err
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
		//
		// The overlay recurses into nested objects. A shallow assignment would
		// replace a whole nested object with the hop's version, and Contains
		// inspects only the CHILD's keys inside an object — so a hop could drop
		// a key *inside* an object and the ancestor's value for it would be
		// discarded. That is the same dropped-dimension widening this block
		// exists to defeat, one level down, and the comment above would have
		// been false at any depth greater than zero.
		overlayScope(effective, ctScope)

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
	if e.chainVerifier == nil {
		return nil, fmt.Errorf("a ZK chain proof was presented but ZK chain mode is not enabled " +
			"(see Engine.EnableChainZK, which self-tests the injected verifier before enabling it)")
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
	// The endpoints are the only hops this path sees in clear, so they get the
	// same intra-token temporal rules as the non-ZK walk. This does NOT give the
	// ZK path parity: the INTERMEDIATE hops remain unchecked for lifetime and
	// revocation because they are hidden, which is a known open finding tracked
	// privately. Checking what is visible is not a substitute for it.
	if err := checkChainTokenTemporal("CAT", catClaims); err != nil {
		return nil, err
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
	if err := checkChainTokenTemporal("leaf CT", leaf); err != nil {
		return nil, err
	}
	// BOUND THE HIDDEN-HOP GAP.
	//
	// This path verifies neither the expiry nor the revocation status of the
	// intermediate hops, because they are hidden. That is a known open finding
	// and this check does not close it.
	//
	// It caps it. A revoked intermediate would otherwise keep granting authority
	// until the ORIGINAL grant expired — potentially months — because nothing on
	// this path ever consults its status. Capping the leaf's remaining lifetime
	// forces the holder back for a fresh leaf within the window, which is the
	// point at which a revocation the publisher has since distributed can bite.
	//
	// Checked against the LEAF, not the transaction token, deliberately: the
	// leaf is the capability the hidden chain terminates in, and it is what a
	// compromised intermediate would mint. Bounding the transaction token would
	// bound the wrong thing — it is already short-lived by construction.
	leafExp, ok := intClaim(leaf, "exp")
	if !ok {
		return nil, fmt.Errorf("leaf CT missing exp")
	}
	if remaining := time.Until(time.Unix(leafExp, 0)); remaining > e.maxZKLeafWindow {
		return nil, fmt.Errorf(
			"ZK chain mode: leaf CT has %s remaining, over the %s bound. This path does not "+
				"check hidden hops for revocation, so a long-lived leaf extends the window in "+
				"which a revoked intermediate still grants authority. Issue a shorter leaf, or "+
				"present the cleartext chain",
			remaining.Round(time.Second), e.maxZKLeafWindow)
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
	// The ceiling becomes a uint64 PUBLIC INPUT to the proof, and that conversion
	// is the only thing binding the proof to the presented leaf's ceiling. A bare
	// uint64(float64) here is unsafe in three separate ways, so it is not used:
	//
	//   - Out of range is IMPLEMENTATION-DEFINED in Go. A wei-scale ceiling above
	//     2^64 yields 2^63 on amd64 and saturates to 2^64-1 on arm64, so every
	//     large ceiling collapses onto one constant and a proof for a legitimately
	//     attenuated chain would verify against a much larger presented ceiling.
	//   - A negative ceiling converts to the MAXIMUM uint64 on amd64 and to 0 on
	//     arm64: the same signed token, opposite verdicts per architecture.
	//   - A fractional ceiling truncates silently, so the proof is checked against
	//     a number that is not the number in the token.
	//
	// Refusing is strictly better than substituting: the circuit range-checks the
	// ceiling to 64 bits anyway, so a ceiling that does not fit is unprovable.
	maxAmt, err := uint64Ceiling(scope["max_amount"])
	if err != nil {
		return nil, fmt.Errorf("leaf CT scope max_amount: %w", err)
	}
	currency, ok := scope["currency"].(string)
	if !ok {
		return nil, fmt.Errorf("leaf CT scope missing currency")
	}
	catMax, ok := intClaim(catClaims, "delegation_depth_max")
	if !ok {
		return nil, fmt.Errorf("CAT missing delegation_depth_max")
	}
	depth, err := uint64Depth(catMax)
	if err != nil {
		return nil, fmt.Errorf("CAT delegation_depth_max: %w", err)
	}
	if err := e.chainVerifier(in.ChainProof, in.ChainH0, e.trustedIssuerRoot, maxAmt, currency, depth); err != nil {
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

// intClaim reads an integral JSON claim.
//
// Returns int64, not int. `exp` is a Unix timestamp, and on a 32-bit build
// `int(f)` for any exp at or beyond 2038-01-19 is an out-of-range float→int
// conversion — implementation-defined in Go, and typically negative on the
// targets that have it. A negative parent exp makes `child > parent` false, so
// a child could outlive its parent by decades while the comparison reported
// attenuation. No 32-bit target is built today (CI has no GOARCH matrix), which
// is why this was latent rather than live; int64 removes the hazard rather than
// relying on the build matrix never changing.
func intClaim(claims map[string]any, name string) (int64, bool) {
	f, ok := claims[name].(float64)
	if !ok {
		return 0, false
	}
	// int64(f) is IMPLEMENTATION-DEFINED when f is out of range: an exp of 1e30
	// becomes -2^63 on amd64 (reads as long expired — safe) and saturates to
	// +2^63-1 on arm64 (reads as valid for the next 292 billion years — NOT
	// safe). A claim that cannot be represented is not a claim this engine can
	// evaluate, so it fails closed on both machines instead of one.
	if math.IsNaN(f) || math.IsInf(f, 0) || f < math.MinInt64 || f >= math.MaxInt64 {
		return 0, false
	}
	return int64(f), true
}

// checkTxnLifetime enforces exp(SPT-Txn) ≤ exp(leaf CT).
//
// The transaction token is the final hop of the delegation chain. It MUST NOT
// outlive the capability that authorized it, or authority persists after the
// grant conferring it has expired.
//
// Both halves fail closed on an absent or non-integral exp. A missing exp is
// not "no constraint": it is a lifetime that cannot be bounded, and this engine
// does not proceed on a bound it cannot compute.
//
// Those two branches are currently UNREACHABLE through Verify: step2Expiry
// already requires the SPT-Txn's exp to be a float, and cttoken.Verify requires
// the leaf CT's. They are kept because that reachability is a property of the
// current step ordering, not of this function, and a reordering that removed it
// would otherwise turn an unusable exp into an unbounded lifetime silently.
// Pinned by TestCheckTxnLifetime, which is white-box for exactly this reason —
// an end-to-end test of these branches passes because step 2 denied first, and
// is worth nothing.
func checkTxnLifetime(txClaims, leaf map[string]any) error {
	txExp, ok := intClaim(txClaims, "exp")
	if !ok {
		return fmt.Errorf("SPT-Txn missing or non-integral exp")
	}
	leafExp, ok := intClaim(leaf, "exp")
	if !ok {
		return fmt.Errorf("leaf CT missing or non-integral exp")
	}
	if txExp > leafExp {
		return fmt.Errorf("SPT-Txn outlives its leaf capability (exp %d > %d): TTL must attenuate", txExp, leafExp)
	}
	return nil
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

// uint64Ceiling converts a scope ceiling into the uint64 the ZK circuit takes as
// a public input, refusing every value the conversion cannot carry faithfully.
//
// It exists because Go's float-to-unsigned conversion is implementation-defined
// out of range and silent on truncation, and this particular conversion is the
// binding between a proof and the ceiling in the token it is presented with. A
// value that does not survive it exactly is not a ceiling this verifier can
// enforce, and saying so is the only safe answer.
func uint64Ceiling(v any) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("missing")
	}
	r, ok := ratOf(v)
	if !ok {
		return 0, fmt.Errorf("is %T, not a number", v)
	}
	// Negative only. Zero is a legitimate maximally-narrow ceiling (it authorizes
	// nothing), and refusing it here while issuance allows it would be exactly
	// the issuer/verifier divergence this conversion is supposed to avoid.
	if r.Sign() < 0 {
		return 0, fmt.Errorf("must not be negative, got %s", r.RatString())
	}
	if !r.IsInt() {
		return 0, fmt.Errorf("must be a whole number of base units, got %s", r.RatString())
	}
	n := r.Num()
	if n.BitLen() > 64 {
		return 0, fmt.Errorf("does not fit in the 64-bit public input the circuit range-checks (%s)", r.RatString())
	}
	return n.Uint64(), nil
}

// ratOf converts the numeric shapes a JWT claim can arrive as into an exact
// rational. json.Number is parsed strictly as a decimal integer or decimal
// fraction: big.Rat.SetString would otherwise accept hex, exponent and fraction
// forms, which is the wide grammar ledger.ParseAmount exists to exclude.
func ratOf(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case float64:
		r := new(big.Rat)
		if r.SetFloat64(n) == nil {
			return nil, false // NaN or Inf
		}
		return r, true
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	case uint64:
		return new(big.Rat).SetUint64(n), true
	case json.Number:
		if _, err := ledger.ParseAmount(n.String()); err != nil {
			return nil, false
		}
		r, ok := new(big.Rat).SetString(n.String())
		return r, ok
	}
	return nil, false
}

// uint64Depth converts the CAT's delegation-depth budget into the uint64 public
// input the ZK circuit takes.
//
// The cleartext chain path range-checks the budget at every hop (ctRem < 0); the
// ZK path had no equivalent, and int64(-1) converted to uint64 is a
// well-defined 2^64-1 — so a negative delegation_depth_max made the proof's
// depth bound meaningless rather than refusing it. The ZK path exists precisely
// so that hidden hops are not trusted, which is the last place to trust that the
// issuer wrote a sane budget.
func uint64Depth(n int64) (uint64, error) {
	if n < 1 {
		return 0, fmt.Errorf("must be >= 1, got %d", n)
	}
	return uint64(n), nil
}

// overlayScope writes src's dimensions onto dst, recursing into nested objects
// so a dimension dropped inside an object keeps its tighter ancestor value.
// Only dimensions src actually declares are replaced; everything else in dst
// survives, which is what makes the result the intersection over the chain
// rather than the leaf's own scope.
func overlayScope(dst, src tbac.Scope) {
	for k, v := range src {
		sn, srcIsObj := asScopeObject(v)
		dn, dstIsObj := asScopeObject(dst[k])
		if srcIsObj && dstIsObj {
			merged := tbac.Scope{}
			for dk, dv := range dn {
				merged[dk] = dv
			}
			overlayScope(merged, sn)
			// Written back as map[string]any: tbac's containment algebra
			// type-asserts nested objects to that, and a tbac.Scope there would
			// read as a type mismatch.
			dst[k] = map[string]any(merged)
			continue
		}
		dst[k] = v
	}
}

func asScopeObject(v any) (tbac.Scope, bool) {
	switch t := v.(type) {
	case tbac.Scope:
		return t, true
	case map[string]any:
		return tbac.Scope(t), true
	}
	return nil, false
}
