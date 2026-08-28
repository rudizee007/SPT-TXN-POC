// Package payergate defines the decision document the payer-side x402 gate
// emits and a settlement client consumes.
//
// ─────────────────────────────────────────────────────────────────────────────
// # What this is
//
// The payer-side gate (cmd/x402gate) mints a real CAT → CT → SPT-Txn chain for
// one concrete payment and runs the eight-step verifier. Its answer — ALLOW or
// DENY, the payment it decided about, the capability ceiling it enforced, and
// the humanAnchor of the accountable person — crosses a process boundary to
// the settlement client, which signs only on ALLOW.
//
// This package is that answer's ONE definition. The emitter and the consumer
// are different modules; give each its own struct and they drift — a field
// renamed on one side arrives zero on the other, and a zero anchor or a zero
// amount is exactly the input every downstream check refuses. Three defects on
// 2026-08-27 were this same shape (an unwired comparison, a second rendering
// of the anchor, a second copy of a key); this package exists so the decision
// document cannot become the fourth.
//
// # What this is NOT
//
// It is not an authorization. Holding a Decision file authorizes nothing: the
// settlement still requires the payer's key (another process), and an anchored
// settlement still requires an attestation from the issuing authority (a third
// process), which checks the anchor↔payer binding against its own registry.
// The Decision is the gate's ANSWER, carried between processes that each
// enforce their own part.
//
// Consumers MUST re-derive the context hash from Context's fields with
// pkg/ledger rather than trusting ContextHash — the field is the gate's claim,
// and the comparison against an independent derivation is the control. The
// same rule as everywhere else in this project: two parties computing one
// value separately is a check; one party computing it twice is not.
//
// # Status
//
// POC seam. In the target architecture the gate's decision reaches the
// issuing authority directly (the authority derives the anchor and ceiling
// from the verified chain itself, and no file crosses a trust boundary); see
// PAYER-GATE-PLACEMENT-ADR-2026-08-27.md, Option B. This document is the
// interim contract and is versioned so that convergence is visible when it
// happens.
// ─────────────────────────────────────────────────────────────────────────────
package payergate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/ledger"
)

// FormatVersion is bumped when the document's meaning changes, never silently.
const FormatVersion = 1

// Outcome is the gate's verdict.
type Outcome string

const (
	Allow Outcome = "ALLOW"
	Deny  Outcome = "DENY"
)

var (
	// ErrNotAllow reports a consumer trying to settle on a decision that is
	// not ALLOW. Checked here so every consumer refuses the same way.
	ErrNotAllow = errors.New("payergate: decision is not ALLOW — nothing may be signed")

	// ErrBadVersion reports a document written by a different format version.
	ErrBadVersion = errors.New("payergate: unrecognised decision format version")

	// ErrStale reports a decision older than the consumer's freshness bound.
	ErrStale = errors.New("payergate: decision is stale")

	// ErrContextHashMismatch reports that the context hash re-derived from the
	// document's own fields differs from the one the gate recorded. Either the
	// fields were altered after the decision, or the two sides canonicalize
	// differently — both are grounds to stop.
	ErrContextHashMismatch = errors.New("payergate: context hash does not re-derive from the decision's own fields")
)

// Context names the concrete payment the gate decided about. Field names and
// meanings match pkg/ledger.TxnContext; the timestamp is the gate's issue
// time and travels with the decision so every later party hashes the SAME
// payment rather than inventing its own.
type Context struct {
	Chain       string            `json:"chain"`
	Originator  string            `json:"originator"`
	Beneficiary string            `json:"beneficiary"`
	Amount      string            `json:"amount"`
	Currency    string            `json:"currency"`
	Timestamp   int64             `json:"timestamp"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// Chain is the token chain the decision rests on, carried as evidence. It is
// NOT re-verified by consumers in the POC — the gate verified it and says so
// in Verified — but carrying it means an auditor can re-run the eight-step
// verifier later against the same material.
type Chain struct {
	CAT string   `json:"cat,omitempty"`
	CTs []string `json:"cts,omitempty"`
	TXN string   `json:"txn,omitempty"`

	// Audience is the domain the SPT-Txn token was minted for. A settler that
	// re-verifies the chain supplies it (step 3 checks the token's signed aud
	// against it).
	//
	// Carrying it in the decision is SAFE but provides no independent
	// protection at the settler: an attacker who edits the decision simply
	// names the token's real, signed aud and step 3 passes. It fails closed on
	// a WRONG value (DENY) and never widens what a forged decision can do — the
	// payment is still bound by scope (step 7) and context (step 8) — but do
	// not read step 3 as a settler-side authenticity check. It is not one.
	Audience string `json:"audience,omitempty"`
}

// Decision is the gate's answer for one payment.
type Decision struct {
	Version int     `json:"version"`
	Outcome Outcome `json:"outcome"`

	// Reason is human-readable. On DENY it names the failing step; on ALLOW it
	// is informational.
	Reason string `json:"reason,omitempty"`

	// Step and StepName identify where an eight-step verification stopped.
	// Zero / empty on ALLOW.
	Step     int    `json:"step,omitempty"`
	StepName string `json:"step_name,omitempty"`

	// Anchor is the humanAnchor from the CAT, hex, 64 characters — the
	// accountable person's commitment. Empty on DENY.
	Anchor string `json:"anchor,omitempty"`

	// Ceiling is the capability ceiling the chain granted, as the decimal
	// string the scope carries. The gate enforced Amount <= Ceiling at mint;
	// it is carried so the consumer can display and re-check it.
	Ceiling string `json:"ceiling,omitempty"`

	// Context is the payment decided about.
	Context Context `json:"context"`

	// ContextHash is spt_txn_context_hash as the gate computed it, hex.
	// Consumers re-derive; see the package comment.
	ContextHash string `json:"context_hash,omitempty"`

	// Chain carries the token material as evidence.
	Chain Chain `json:"chain_evidence,omitempty"`

	// IssuedAt is when the gate decided, unix seconds.
	IssuedAt int64 `json:"issued_at"`

	// Verified records that the gate ran the full eight-step verification on
	// the chain before answering. It is a statement by the gate, not a proof;
	// the proof is re-running the verifier against Chain.
	Verified bool `json:"verified"`
}

// ReDeriveContextHash recomputes the context hash from the decision's own
// fields and compares it to the recorded one.
func (d Decision) ReDeriveContextHash() error {
	l, err := ledger.Get(d.Context.Chain)
	if err != nil {
		return err
	}
	_, got, err := ledger.ContextHash(l, ledger.TxnContext{
		Chain:       d.Context.Chain,
		Originator:  d.Context.Originator,
		Beneficiary: d.Context.Beneficiary,
		Amount:      d.Context.Amount,
		Currency:    d.Context.Currency,
		Timestamp:   d.Context.Timestamp,
		Extra:       d.Context.Extra,
	})
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, d.ContextHash) {
		return fmt.Errorf("%w: fields hash to %s, decision records %s",
			ErrContextHashMismatch, got, d.ContextHash)
	}
	return nil
}

// CheckSettleable is every refusal a settlement client must apply before
// acting on a decision, in one place so no consumer forgets one:
// the version is known, the outcome is ALLOW, the decision is fresh, and the
// context hash re-derives from the fields.
//
// maxAge <= 0 disables the freshness check — for replaying an old decision
// against an auditor's question, never for settling.
func (d Decision) CheckSettleable(now time.Time, maxAge time.Duration) error {
	if d.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrBadVersion, d.Version)
	}
	if d.Outcome != Allow {
		return fmt.Errorf("%w (outcome %q, reason %q)", ErrNotAllow, d.Outcome, d.Reason)
	}
	if maxAge > 0 {
		age := now.Sub(time.Unix(d.IssuedAt, 0))
		if age > maxAge {
			return fmt.Errorf("%w: issued %s ago, bound %s", ErrStale, age.Round(time.Second), maxAge)
		}
	}
	return d.ReDeriveContextHash()
}

// Write stores the decision, 0600.
//
// Unlike a disclosure record this is not key material — the anchor is a public
// commitment and the tokens are holder-bound — but it is an input to a signing
// decision, and an input to a signing decision readable by every process on
// the machine is wider than it needs to be.
func Write(path string, d Decision) error {
	if d.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrBadVersion, d.Version)
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Read loads a decision. It does NOT check settleability — that is the
// consumer's explicit act, with its own clock and freshness bound.
func Read(path string) (Decision, error) {
	var d Decision
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	if d.Version != FormatVersion {
		return d, fmt.Errorf("%w: %d", ErrBadVersion, d.Version)
	}
	return d, nil
}
