// Package ledger is the blockchain-agnostic adapter boundary for SPT-Txn.
//
// SPT-Txn is a self-sovereign, ledger-independent authorization capability.
// XRPL is a target integration, NOT a dependency. M4 binds an SPT-Txn Token to
// a specific value transfer via spt_txn_context_hash, but it must never import
// a concrete chain package. Instead it depends only on the Ledger interface
// defined here; concrete chains (XRPL today, others later) register adapters.
//
// The contract is deliberately small:
//
//   - TxnContext describes a value transfer in chain-neutral terms.
//   - Ledger.Canonicalize turns a TxnContext into deterministic bytes — the
//     preimage of spt_txn_context_hash. Determinism across processes and hosts
//     is the only hard requirement; a verifier on another machine MUST be able
//     to recompute the identical hash from the same TxnContext.
//   - Ledger.Validate enforces chain-specific field requirements.
//
// This package has no third-party dependencies and no knowledge of any chain.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// TxnContext is a chain-neutral description of the transaction an SPT-Txn Token
// authorizes. Amount is a decimal string (never a float) to avoid rounding and
// to keep canonicalization byte-exact across languages and platforms.
type TxnContext struct {
	Chain       string            // adapter name, e.g. "xrpl" or "none"
	Originator  string            // source account/address (chain-specific form)
	Beneficiary string            // destination account/address
	Amount      string            // decimal string, e.g. "5000.00"
	Currency    string            // e.g. "USD", "XRP", "RLUSD"
	Timestamp   int64             // unix seconds
	Extra       map[string]string // chain-specific params (e.g. DestinationTag)
}

// Ledger is the adapter boundary. Each supported chain provides exactly one
// implementation. M4 depends only on this interface.
type Ledger interface {
	// Name is the adapter identifier, matching TxnContext.Chain.
	Name() string

	// Validate checks chain-specific field requirements (required fields,
	// address shape, currency support). It does not touch the network.
	Validate(tc TxnContext) error

	// Canonicalize returns the deterministic preimage bytes for tc. The same
	// TxnContext MUST always produce identical bytes, on any host, in any
	// process — this is what makes spt_txn_context_hash verifiable
	// cross-domain (M5 Step 8).
	Canonicalize(tc TxnContext) ([]byte, error)
}

// ContextHash computes spt_txn_context_hash = SHA-256(l.Canonicalize(tc)),
// returning the raw digest and its hex encoding. It validates first.
func ContextHash(l Ledger, tc TxnContext) ([]byte, string, error) {
	if err := l.Validate(tc); err != nil {
		return nil, "", fmt.Errorf("%s: validate: %w", l.Name(), err)
	}
	pre, err := l.Canonicalize(tc)
	if err != nil {
		return nil, "", fmt.Errorf("%s: canonicalize: %w", l.Name(), err)
	}
	sum := sha256.Sum256(pre)
	return sum[:], hex.EncodeToString(sum[:]), nil
}

// ── adapter registry ─────────────────────────────────────────────────────────

var registry = map[string]Ledger{}

// Register makes an adapter available by name. Adapters call this from init().
func Register(l Ledger) { registry[l.Name()] = l }

// Get returns the registered adapter for name, or an error if none is
// registered. Callers select the adapter by TxnContext.Chain.
func Get(name string) (Ledger, error) {
	l, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("ledger: no adapter registered for %q", name)
	}
	return l, nil
}

// validAmount is the adapters' gate on TxnContext.Amount. It delegates to
// ParseAmount so that the adapters, the tbac scope projection and anything else
// that judges an amount share ONE grammar — a second implementation here is
// exactly the drift the threat model warns about.
func validAmount(s string) error {
	_, err := ParseAmount(s)
	return err
}

// ── canonical encoding shared by adapters ────────────────────────────────────

// canonicalEncode produces a deterministic, injective byte encoding of an
// ordered set of fields plus a sorted map of extras. Format:
//
//	<key>\x1f<value>\x1e<key>\x1f<value>\x1e...
//
// using ASCII unit (0x1f) and record (0x1e) separators. Values MUST NOT contain
// those bytes; callers validate that. This avoids JSON's map-ordering and
// whitespace nondeterminism.
func canonicalEncode(ordered [][2]string, extra map[string]string) ([]byte, error) {
	var b strings.Builder
	write := func(k, v string) error {
		if strings.ContainsAny(k, "\x1f\x1e") || strings.ContainsAny(v, "\x1f\x1e") {
			return fmt.Errorf("field %q contains a reserved separator byte", k)
		}
		b.WriteString(k)
		b.WriteByte(0x1f)
		b.WriteString(v)
		b.WriteByte(0x1e)
		return nil
	}
	for _, kv := range ordered {
		if err := write(kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := write("x:"+k, extra[k]); err != nil {
			return nil, err
		}
	}
	return []byte(b.String()), nil
}
