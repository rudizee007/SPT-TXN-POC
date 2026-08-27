// Package ledger is the public face of spt_txn_context_hash: the canonical
// transaction-context encoding and its SHA-256 digest.
//
// ─────────────────────────────────────────────────────────────────────────────
// This package contains no logic. It is a facade over internal/ledger, which
// stays the one and only implementation.
//
// # Why it exists
//
// The Base settlement client (spt-txn-x402-base/clients/basepay) is a separate
// module. It must compute a context hash to bind a humanAnchor attestation to
// one specific payment — and an attestation is only bound to a payment if the
// spender computes that hash ITSELF. A spender that accepts the hash from the
// party issuing the attestation has bound nothing: the mismatch check would be
// comparing a value against where it came from.
//
// internal/ledger cannot be imported from another module. The three ways out
// were: re-implement the canonicalization there, accept the hash from the
// issuer, or expose the existing implementation. The first two are the
// canonicalization-mismatch bug class and a vacuous check respectively — this
// project's two named worst outcomes — so it is the third.
//
// # Why a facade rather than moving the code
//
// Moving files touches every caller across 280 Go files and puts the
// conformance vectors at risk for no behavioural gain. A facade is provably
// inert: it adds an import path and changes nothing that already runs. Go's
// internal rule constrains import PATHS, not types, so a type alias to an
// internal type is legal and transparent — callers outside the module build
// TxnContext values with the same field names and get the same bytes, because
// they ARE the same type.
//
// Nothing here may grow logic. If a future change needs behaviour that is not
// in internal/ledger, it goes in internal/ledger.
// ─────────────────────────────────────────────────────────────────────────────
package ledger

import (
	internalledger "github.com/rudizee007/spt-txn-poc/internal/ledger"
)

// TxnContext is the transaction context that gets canonicalized and hashed.
//
// An ALIAS, not a definition. A distinct struct here would be a second shape
// that has to be kept in step with the first, and the field that gets forgotten
// is the field that stops being covered by the hash.
type TxnContext = internalledger.TxnContext

// Ledger is the per-chain adapter boundary.
type Ledger = internalledger.Ledger

// ContextHash computes spt_txn_context_hash = SHA-256(l.Canonicalize(tc)),
// returning the raw 32-byte digest and its hex encoding. It validates first.
//
// The raw digest is what an anchor attestation binds to. The hex form is what
// travels in a Memo, a receipt or an HTTP field.
func ContextHash(l Ledger, tc TxnContext) ([]byte, string, error) {
	return internalledger.ContextHash(l, tc)
}

// Get returns the registered adapter for a chain name — "base", "xrpl",
// "ethereum" and so on — matching TxnContext.Chain.
//
// Adapters register themselves from init() in internal/ledger, and importing
// this package pulls that in, so every adapter the binary could use is present
// without the caller naming any of them.
//
// Register is deliberately NOT re-exported. An adapter supplied from outside
// the module would be a chain definition nobody reviewed, and chain tags are
// what keep two chains' context hashes from colliding.
func Get(name string) (Ledger, error) {
	return internalledger.Get(name)
}
