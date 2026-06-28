// Package zkhash is the single source of truth for the SPT-Txn ZK-friendly hash
// over BN254. It is used both NATIVELY (the zkDID humanAnchor commitment in
// internal/zkdid, the amount commitment and Merkle tree in internal/zkproof) and
// is matched IN-CIRCUIT by gnark's std hash gadget. Keeping it in one place
// means the token's humanAnchor and the ZK-proven commitment are the same value,
// and swapping the hash (MiMC -> Poseidon, Section 5) is a one-file change here
// plus the circuit gadget.
//
// Importing this package pulls only gnark-crypto field arithmetic + the hash —
// NOT the gnark prover — so key-holding services (catsvc) stay lean.
//
// Current hash: Poseidon2 over BN254 (gnark-crypto native MerkleDamgardHasher <->
// gnark/std/hash/poseidon2 in-circuit, matched by construction). Migrated from
// MiMC in v2 (gnark v0.15 / gnark-crypto v0.20) for a large proving speedup. The
// hash is defined in exactly two matched places — the HashCommit/HashNode helpers
// here and the gadget in internal/zkproof/circuits.go — so the token humanAnchor
// == the proven commitment. Changing the hash changes the serialized circuit/key
// format, so re-run cmd/zk-setup after any change here.
//
// Domain separation (CR-1): the same 2-input Poseidon2 sponge backs three
// logically distinct commitments — the identity humanAnchor H(ID, randomness),
// the amount commitment H(amount, blinding), and each inner Merkle node
// H(left, right). To stop a value computed for one purpose from being replayed
// as another, every hash absorbs a distinct domain tag as its FIRST input:
// H(tag, a, b). The tags are small field-element constants (DomainAnchor,
// DomainAmount, DomainMerkleNode) and the in-circuit gadget writes the IDENTICAL
// constant first (see circuits.go), so native and circuit digests stay equal.
package zkhash

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Domain-separation tags absorbed as the first input of every commitment hash.
// These MUST be mirrored byte-for-byte by the in-circuit gadget in
// internal/zkproof/circuits.go (a frontend.Variable holding the same small
// integer marshals to the same canonical field element). Never reuse or reorder
// these values without regenerating the trusted setup.
const (
	DomainAnchor     uint64 = 1 // identity humanAnchor: H(tag, ID, randomness)
	DomainAmount     uint64 = 2 // amount commitment:    H(tag, amount, blinding)
	DomainMerkleNode uint64 = 3 // VASP/issuer Merkle inner node: H(tag, left, right)
	DomainIssuer     uint64 = 4 // CT-issuer registry leaf: H(tag, pubkeyX, pubkeyY)
)

// FeFromBytes reduces arbitrary bytes to a field element (big-endian mod r).
//
// WARNING: this is NOT injective. SetBytes interprets b as a big-endian integer
// and reduces it modulo r, so any two inputs congruent mod r (including a 32-byte
// value >= r and its reduced form) collide. Callers that need a faithful mapping
// of secret material into the field MUST use FeFromWide (for wide hash outputs)
// or FeFromCanonical (to reject/forbid non-canonical fixed-width inputs). This
// helper is retained for internal use where the input is already known canonical.
func FeFromBytes(b []byte) fr.Element {
	var e fr.Element
	e.SetBytes(b)
	return e
}

// FeFromWide maps an arbitrary-width byte string into the field via a uniform
// wide reduction. It is the safe path for hash digests wider than the field
// (e.g. a 64-byte SHA-512 identity stand-in): interpreting the full digest as a
// big-endian integer mod r spreads the reduction bias far below any detectable
// level. Use this for ID material and randomness/blinding derived from hashes.
func FeFromWide(b []byte) fr.Element {
	// SetBytes already performs a big-endian reduction over the full slice,
	// which is exactly the wide reduction we want for >32-byte digests.
	var e fr.Element
	e.SetBytes(b)
	return e
}

// FeFromCanonical maps a fixed-width (<= 32-byte) byte string into the field,
// rejecting any input that is not already a canonical field element (i.e. an
// integer >= r). This lets callers that rely on injectivity of a 32-byte
// randomness/blinding value enforce it instead of silently aliasing under the
// modular reduction performed by FeFromBytes. Inputs longer than 32 bytes are
// rejected; route those through FeFromWide.
func FeFromCanonical(b []byte) (fr.Element, error) {
	var e fr.Element
	if len(b) > fr.Bytes {
		return e, fmt.Errorf("zkhash: %d-byte input exceeds field width %d; use FeFromWide", len(b), fr.Bytes)
	}
	v := new(big.Int).SetBytes(b)
	if v.Cmp(fr.Modulus()) >= 0 {
		return e, fmt.Errorf("zkhash: input is not a canonical field element (>= r)")
	}
	e.SetBigInt(v)
	return e, nil
}

// FeFromUint64 lifts a uint64 into a field element.
func FeFromUint64(u uint64) fr.Element {
	var e fr.Element
	e.SetUint64(u)
	return e
}

// BigOf converts a field element to a *big.Int (for gnark witness values).
func BigOf(e fr.Element) *big.Int {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

// hashWithDomain computes H(domainTag, a, b) over field elements using the
// Poseidon2 Merkle-Damgard sponge. The tag is absorbed FIRST. This MUST match
// the in-circuit gadget, which writes the identical constant first and then a, b
// (gnark hashes field elements as canonical 32-byte Marshal blocks; the native
// hasher's block size is also one field element, so the absorption sequence is
// identical).
func hashWithDomain(domainTag uint64, a, b fr.Element) fr.Element {
	tag := FeFromUint64(domainTag)
	h := poseidon2.NewMerkleDamgardHasher()
	h.Write(tag.Marshal())
	h.Write(a.Marshal())
	h.Write(b.Marshal())
	var out fr.Element
	out.SetBytes(h.Sum(nil))
	return out
}

// HashCommit computes a domain-separated 2-input commitment H(domainTag, a, b).
// It is the single source of truth for the native side; the matching in-circuit
// gadget lives in internal/zkproof/circuits.go.
func HashCommit(domainTag uint64, a, b fr.Element) fr.Element {
	return hashWithDomain(domainTag, a, b)
}

// HashAnchor computes the identity humanAnchor commitment H(DomainAnchor, id, r).
func HashAnchor(id, r fr.Element) fr.Element {
	return hashWithDomain(DomainAnchor, id, r)
}

// HashAmount computes the amount commitment H(DomainAmount, amount, blinding).
func HashAmount(amount, blinding fr.Element) fr.Element {
	return hashWithDomain(DomainAmount, amount, blinding)
}

// HashNode computes a VASP Merkle inner node H(DomainMerkleNode, left, right).
func HashNode(left, right fr.Element) fr.Element {
	return hashWithDomain(DomainMerkleNode, left, right)
}

// Commit is the canonical identity humanAnchor commitment over secret material:
// H(DomainAnchor, FeFromWide(secret), FeFromWide(blinding)). Secret and blinding
// are mapped through the safe wide reduction (CR-3) rather than FeFromBytes.
func Commit(secret, blinding []byte) fr.Element {
	return HashAnchor(FeFromWide(secret), FeFromWide(blinding))
}
