// Package trustsnapshot reconstructs and (later) verifies the detached
// signature over a trust-registry snapshot manifest.
//
// SigningInput MUST reproduce, byte-for-byte, the bytes the reference signer
// covers under domain "spt-cp/trust-snapshot-v2". The rules below are the
// entire trap surface; they are locked by the cross-language KAT in
// testdata/trust-snapshot-signing-v1.kat.json. If you change anything here,
// the KAT test fails — that is the point.
//
// The vectors are the contract, not any particular signer. An implementation
// that reproduces them is conformant regardless of what language it is written
// in or where it runs; one that does not is wrong even if it agrees with some
// other implementation. Canonicalization mismatch between a signer and a
// verifier is a full authorization bypass, so the agreement has to be pinned to
// published bytes rather than to a codebase.
package trustsnapshot

import (
	"bytes"
	"encoding/json"
)

// SnapshotSigDomain is the domain tag bound inside the signed object. It gives
// cross-artifact domain separation: a snapshot signature can never be replayed
// as an OT bundle (which uses a different tag) or anything else.
const SnapshotSigDomain = "spt-cp/trust-snapshot-v2"

// Registered `alg` values. A verifier MUST reject anything outside this set,
// MUST reject anything outside its own configured accept-set (which may be
// narrower), and MUST verify under exactly the named suite — never trial-verify
// against each accepted suite in turn, which reintroduces the ambiguity `alg`
// exists to remove.
//
// These mirror internal/suite's identifiers deliberately: one vocabulary, not
// two. The HYBRID entries are dual-signature envelopes, not the composite
// signatures of draft-ietf-jose-pq-composite-sigs.
const (
	AlgEdDSA    = "EdDSA"
	AlgHybrid65 = "HYBRID-Ed25519-ML-DSA-65"
	AlgHybrid87 = "HYBRID-Ed25519-ML-DSA-87"
	AlgMLDSA87  = "ML-DSA-87"
)

// RegisteredAlgs is the allowlist. Membership is necessary, not sufficient: a
// deployment's accept-set may be narrower, and an `alg` inconsistent with the
// pinned publication key is malformed regardless of registration.
var RegisteredAlgs = map[string]bool{
	AlgEdDSA:    true,
	AlgHybrid65: true,
	AlgHybrid87: true,
	AlgMLDSA87:  true,
}

// SigningInput returns the exact bytes the snapshot signature is computed over.
//
// prevSnapshotID is a pointer because the field is ALWAYS present in the signed
// bytes: nil is emitted as JSON null (a first-ever snapshot), a value as the
// string. This differs from the manifest's on-the-wire form, which omits the
// field when absent — do NOT mirror the wire form here.
//
// Canonicalization (all load-bearing):
//   - object keys SORTED lexicographically (built from a map, which
//     encoding/json sorts — never a struct, which would use field order);
//   - compact, no whitespace;
//   - HTML escaping OFF (SetEscapeHTML(false)) so '<' '>' '&' are literal;
//   - issued_ms is an integer (uint64), never a float;
//   - issuer_ids is an array in caller order (arrays are not sorted).
//
// alg names the signature suite and is COVERED BY THE SIGNATURE. That is what
// closes downgrade-by-relabelling: substituting a weaker declaration changes
// these bytes, so the signature no longer verifies. An attacker cannot take a
// hybrid-signed snapshot, call it EdDSA, drop the ML-DSA component and present
// it to a verifier that accepts both.
//
// It does NOT stop a publisher genuinely signing with a weaker suite. That is
// the verifier's accept-set, which is policy. The format removes the ambiguity;
// the deployment removes the permission.
//
// alg is in the SIGNING INPUT only, never the body digest: digest_hex commits to
// content, alg describes how the head was signed, and folding one into the other
// would make re-signing identical content under a different suite change the
// value consumers were told to pin.
func SigningInput(alg string, id string, issuedMs uint64, issuerIDs []string, digestHex string, prevSnapshotID *string) []byte {
	var prev any // nil -> JSON null
	if prevSnapshotID != nil {
		prev = *prevSnapshotID
	}
	// issuer_ids: emit [] (not null) for an empty set, and copy so we never
	// alias the caller's slice.
	ids := make([]string, len(issuerIDs))
	copy(ids, issuerIDs)

	obj := map[string]any{
		"domain":           SnapshotSigDomain,
		"alg":              alg,
		"id":               id,
		"issued_ms":        issuedMs,
		"issuer_ids":       ids,
		"digest_hex":       digestHex,
		"prev_snapshot_id": prev,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		// A map[string]any of strings/uint64/[]string is always encodable.
		panic("trustsnapshot: signing input encode: " + err.Error())
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}
