// Package decision is the single decision core behind every SPT-Txn gateway
// skin (Envoy ext_authz, OPA-compatible API, MCP middleware). Spec:
// docs/spec/GATEWAY-PROFILES.md.
//
// Structural deny-by-default: Decision has unexported fields and can only be
// produced by Engine.Decide. A skin cannot fabricate a permit, and the zero
// value denies with class "unavailable" — an error path that loses the
// decision object has nothing to forward. It is impossible to construct a
// request that "passed through" without a decision attached (CLAUDE.md §2:
// enforce structurally, not by convention).
//
// Every decision — permit and deny — emits a signed Transaction Receipt
// BEFORE the decision is returned. If the receipt cannot be emitted, the
// decision is DENY (unavailable): enforcement without evidence is not
// enforcement (docs/spec/RECEIPT-FORMAT.md §1.3).
package decision

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// Decision is the opaque result of Engine.Decide. The zero value denies.
type Decision struct {
	permit      bool
	class       string // receipt.ClassOK / ClassViolation / ClassUnavailable
	rule        string
	receiptHash string
}

// Permit reports whether the action is authorized. Zero value: false.
func (d Decision) Permit() bool { return d.permit }

// Class returns the decision class; the zero value reports
// receipt.ClassUnavailable so an undecided object never reads as a clean deny.
func (d Decision) Class() string {
	if d.class == "" {
		return receipt.ClassUnavailable
	}
	return d.class
}

// Rule returns the rule path that fired ("decision.unset" for the zero value).
func (d Decision) Rule() string {
	if d.rule == "" {
		return "decision.unset"
	}
	return d.rule
}

// ReceiptHash references the emitted receipt ("" only for the zero value,
// which never leaves the engine on a normal path).
func (d Decision) ReceiptHash() string { return d.receiptHash }

// UnavailableError marks a verifier failure as infrastructure unavailability
// rather than a check violation, so the receipt records `unavailable` and an
// operator can tell an outage from an attack.
type UnavailableError struct{ Err error }

func (u UnavailableError) Error() string { return "unavailable: " + u.Err.Error() }
func (u UnavailableError) Unwrap() error { return u.Err }

// TokenVerifier verifies a presented compact token offline and returns its
// claims. Return an UnavailableError when a required dependency (status list,
// registry snapshot) is unreachable; any other error is treated as a violation.
//
// # What an implementation is required to check, and what it is not
//
// An implementation MUST verify the signature and MUST reject an expired token.
// Everything beyond that is profile-dependent, and this comment previously
// claimed otherwise — it said every verifier performs a "chain walk" and a
// "revocation/status" check. The three shipped gateway skins do neither: they
// are presented with one token and hold no registry, so they rely on the TTS
// having walked the chain at issuance (GATEWAY-PROFILES.md §1.1).
//
// That reliance is legitimate, and it is why Config.MaxTokenTTL exists. A PEP
// that does not consult revocation has a revocation gap equal to the token's
// remaining lifetime, so the engine bounds that lifetime itself rather than
// assuming a verifier did.
type TokenVerifier func(ctx context.Context, token string) (map[string]any, error)

// Emitter signs the receipt with the log key, appends it to the transparency
// log, and returns the receipt hash. Must be atomic from the caller's view:
// an error means "not durably logged".
type Emitter func(r *receipt.Receipt) (string, error)

// Config assembles an Engine. All fields are required.
type Config struct {
	PEP          string // this PEP's trust-registry identity
	PolicyHash   string // hash of the loaded policy bundle version
	Jurisdiction string // jurisdiction profile identifier
	Verify       TokenVerifier
	Emit         Emitter
	// MaxTokenTTL is the longest remaining lifetime this PEP will accept on a
	// presented token. Required — there is no default, because the safe value
	// depends on how much revocation latency the deployment tolerates and
	// guessing it on an operator's behalf is how a 30-second design ends up
	// accepting 24-hour tokens.
	//
	// A gateway PEP does not walk the chain, so revoking the CT, the CAT or the
	// issuer key does not invalidate an already-minted token. This bound IS the
	// revocation latency for that form factor (GATEWAY-PROFILES.md §1.1).
	MaxTokenTTL time.Duration

	// ReplayWindow bounds how long a jti is remembered. It MUST be ≥
	// MaxTokenTTL and New refuses to construct an Engine where it is not: a
	// token that outlives the memory of its own jti is replayable once the slot
	// is pruned, which turns single use into single-use-per-window. Zero uses
	// 10 minutes, which is only accepted if MaxTokenTTL is 10 minutes or less.
	ReplayWindow time.Duration
	// ReplayCapacity bounds the replay cache. A full cache DENIES new
	// tokens (unavailable) — it never evicts-and-hopes. Zero uses 65536.
	ReplayCapacity int
}

// Engine is the decision core. Safe for concurrent use.
type Engine struct {
	cfg    Config
	mu     sync.Mutex
	replay map[string]int64 // jti -> unix expiry of the cache slot
}

// New validates the configuration. A nil verifier or emitter is a
// construction error, not a runtime fallback — there is no mode without
// verification or without evidence.
func New(cfg Config) (*Engine, error) {
	if cfg.PEP == "" {
		return nil, errors.New("decision: PEP identity required")
	}
	if cfg.PolicyHash == "" {
		return nil, errors.New("decision: policy hash required")
	}
	if cfg.Verify == nil {
		return nil, errors.New("decision: token verifier required")
	}
	if cfg.Emit == nil {
		return nil, errors.New("decision: receipt emitter required")
	}
	if cfg.MaxTokenTTL <= 0 {
		return nil, errors.New("decision: MaxTokenTTL required — a PEP that does not " +
			"walk the chain has a revocation gap equal to the token lifetime it accepts, " +
			"so that lifetime must be a declared bound and not whatever the issuer chose")
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 10 * time.Minute
	}
	// Refuse rather than warn. These are one property written twice, and when
	// they disagree the failure is silent: the jti slot is pruned while the
	// token is still valid, the same token is accepted again, and nothing
	// anywhere reports that single use stopped being single use.
	if cfg.ReplayWindow < cfg.MaxTokenTTL {
		return nil, fmt.Errorf("decision: ReplayWindow (%s) is shorter than MaxTokenTTL (%s) — "+
			"a token would outlive the memory of its own jti and replay once the slot is pruned",
			cfg.ReplayWindow, cfg.MaxTokenTTL)
	}
	if cfg.ReplayCapacity <= 0 {
		cfg.ReplayCapacity = 65536
	}
	return &Engine{cfg: cfg, replay: make(map[string]int64)}, nil
}

// Input is one authorization question: this token, for this actual call.
type Input struct {
	Token  string
	Intent intent.Intent
}

// Decide runs the decision path. It always returns a decision and always
// emits a receipt; every error branch denies.
func (e *Engine) Decide(ctx context.Context, in Input) Decision {
	if in.Token == "" {
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "token.absent", "", "")
	}
	tokenHash := receipt.TokenHash(in.Token)

	claims, err := e.cfg.Verify(ctx, in.Token)
	if err != nil {
		var u UnavailableError
		if errors.As(err, &u) {
			return e.finish(receipt.DecisionDeny, receipt.ClassUnavailable, "token.verify-unavailable", tokenHash, "")
		}
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "token.verify", tokenHash, "")
	}

	// Single use: one jti, one acceptance, within the replay window.
	// The replay slot is consumed BEFORE the intent check, deliberately: this
	// prevents an attacker who holds a token from probing many candidate
	// intents against it to find one the PEP will accept. The cost is a
	// fail-closed DoS (a wrong-intent presentation burns the jti), which is
	// the correct trade for an authorization engine — a burned token denies;
	// it never escalates.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "token.jti-absent", tokenHash, "")
	}

	// Lifetime bound. A gateway PEP does not walk the chain, so revoking the
	// CT, the CAT or the issuer key cannot withdraw a token already minted:
	// the remaining lifetime IS the revocation gap (GATEWAY-PROFILES.md §1.1).
	// The verifier proved the token is not yet expired; it did not prove the
	// window is one this PEP is willing to be blind for.
	//
	// Checked BEFORE the replay slot is consumed, unlike the intent check. An
	// over-long token can never be accepted here, so burning a slot for it
	// would let an attacker fill a bounded cache with tokens that were never
	// acceptable — and a full cache denies every token as unavailable.
	expF, ok := claims["exp"].(float64)
	if !ok {
		// Fail closed: without exp there is no lifetime to bound. The verifier
		// contract requires rejecting expired tokens, so a verifier that does
		// not surface exp is one whose expiry behaviour cannot be checked here.
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "token.exp-absent", tokenHash, "")
	}
	if remaining := time.Until(time.Unix(int64(expF), 0)); remaining > e.cfg.MaxTokenTTL {
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "token.ttl-excessive", tokenHash, "")
	}

	switch e.replayCheck(jti) {
	case replayDuplicate:
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "replay.duplicate", tokenHash, "")
	case replayUnavailable:
		return e.finish(receipt.DecisionDeny, receipt.ClassUnavailable, "replay.cache-unavailable", tokenHash, "")
	}

	// Intent binding: the actual call must match the declared action.
	bound := intent.BoundDigestFromClaims(claims)
	if err := intent.Match(bound, in.Intent); err != nil {
		return e.finish(receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch", tokenHash, bound)
	}

	return e.finish(receipt.DecisionPermit, receipt.ClassOK, "authorize.ok", tokenHash, bound)
}

// RecordDeny lets a skin record a transport-level rejection (malformed
// JSON-RPC, unparseable envelope) as a receipt-backed deny. This is the ONLY
// decision a skin may originate: a skin can always deny, and can never
// permit — a compromised skin can deny service but cannot mint authority.
func (e *Engine) RecordDeny(rule string, unavailable bool, token string) Decision {
	class := receipt.ClassViolation
	if unavailable {
		class = receipt.ClassUnavailable
	}
	return e.finish(receipt.DecisionDeny, class, rule, receipt.TokenHash(token), "")
}

// RecordObserved records a receipt for traffic the PEP passes through without
// authorization (e.g. MCP initialize/tools/list). The receipt's rule path
// marks it as observation, not enforcement.
func (e *Engine) RecordObserved(rule string) Decision {
	return e.finish(receipt.DecisionPermit, receipt.ClassOK, rule, "", "")
}

type replayResult int

const (
	replayFresh replayResult = iota
	replayDuplicate
	replayUnavailable
)

// replayCheck records jti and reports whether it was already seen. A full
// cache is unavailability, never a wave-through.
func (e *Engine) replayCheck(jti string) replayResult {
	now := time.Now().Unix()
	e.mu.Lock()
	defer e.mu.Unlock()
	// Opportunistic prune of expired slots.
	for k, exp := range e.replay {
		if exp <= now {
			delete(e.replay, k)
		}
	}
	if _, seen := e.replay[jti]; seen {
		return replayDuplicate
	}
	if len(e.replay) >= e.cfg.ReplayCapacity {
		return replayUnavailable
	}
	e.replay[jti] = now + int64(e.cfg.ReplayWindow/time.Second)
	return replayFresh
}

// finish emits the receipt and materializes the Decision. Receipt emission
// failure converts ANY outcome — including a would-be permit — into a deny
// with class unavailable.
func (e *Engine) finish(dec, class, rule, tokenHash, intentDigest string) Decision {
	r, err := receipt.New(e.cfg.PEP, dec, class, rule, tokenHash, e.cfg.PolicyHash)
	if err != nil {
		return Decision{permit: false, class: receipt.ClassUnavailable, rule: "receipt.construct-failed"}
	}
	r.IntentDigest = intentDigest
	r.Jurisdiction = e.cfg.Jurisdiction
	hash, err := e.cfg.Emit(r)
	if err != nil {
		return Decision{permit: false, class: receipt.ClassUnavailable, rule: "receipt.emit-failed"}
	}
	return Decision{
		permit:      dec == receipt.DecisionPermit,
		class:       class,
		rule:        rule,
		receiptHash: hash,
	}
}
