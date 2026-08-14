// Package pepevidence adapts this engine's receipt path to the
// evidence.Emitter interface published by github.com/rudizee007/spt-txn-pep,
// so an enforcement point can record spec Transaction Receipts without
// depending on this module's internals.
//
// # Direction of the dependency
//
// spt-txn-pep defines the interface and takes no dependencies at all; this
// module implements it. The receipt implementation and the JCS canonicalizer
// stay here, next to the verifier, deliberately: the canonicalizer is the
// primary bypass surface, and issuer and verifier must be the same version by
// construction rather than by convention. See spt-txn-pep/evidence for the
// full argument.
//
// This package is the compile-time proof that the two halves fit. Before it
// existed, the seam was asserted in documentation and checked by nobody.
package pepevidence

import (
	"crypto/ed25519"
	"errors"

	"github.com/rudizee007/spt-txn-pep/evidence"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// Emitter signs each decision as a Transaction Receipt and appends it to the
// hash-chained audit log, returning the receipt hash as the locator.
//
// Emit returns an error unless the receipt is durably recorded. Per the
// evidence.Emitter contract a PEP MUST convert that into DENY/unavailable
// rather than serving the request: evidence is a precondition of the decision,
// not a side effect of it.
type Emitter struct {
	inner *receiptlog.LogEmitter
}

// Compile-time proof that this type satisfies both the required interface and
// the optional durability capability. If either contract moves, the build
// breaks here rather than at a deployment that quietly stops being conformant.
var (
	_ evidence.Emitter = (*Emitter)(nil)
	_ evidence.Durable = (*Emitter)(nil)
)

// New wires an open audit log and the log signing key.
func New(log *audit.Log, logKey ed25519.PrivateKey) (*Emitter, error) {
	inner, err := receiptlog.NewLogEmitter(log, logKey)
	if err != nil {
		return nil, err
	}
	return &Emitter{inner: inner}, nil
}

// Emit builds, signs and durably records the receipt, returning its hash.
//
// The decision/class pairing is validated at construction by receipt.New —
// PERMIT must be class "ok", DENY must be "violation" or "unavailable" — so a
// mislabeled receipt is refused rather than written. An empty PEP identity or
// rule path is refused for the same reason. In every one of those cases Emit
// returns an error, and the PEP denies; there is no path where a malformed
// receipt results in a served request.
func (e *Emitter) Emit(er evidence.Receipt) (string, error) {
	if e == nil || e.inner == nil {
		return "", errors.New("pepevidence: nil emitter")
	}
	// Field-for-field pass-through. The two modules use identical decision and
	// class vocabularies (asserted in the tests), so nothing is mapped here —
	// a mapping layer is where an equivalence nobody agreed to gets invented.
	r, err := receipt.New(er.PEP, er.Decision, er.Class, er.RulePath, er.TokenHash, er.PolicyHash)
	if err != nil {
		return "", err
	}
	r.IntentDigest = er.IntentDigest
	r.Jurisdiction = er.Jurisdiction
	return e.inner.Emit(r)
}

// Durable reports true: audit.Log.Append fsyncs the record before returning,
// so a nil error from Emit means the receipt is on disk rather than buffered.
// An emitter that ever becomes asynchronous or buffered MUST change this to
// false — the fail-closed guarantee is only as strong as this answer.
func (e *Emitter) Durable() bool { return true }
