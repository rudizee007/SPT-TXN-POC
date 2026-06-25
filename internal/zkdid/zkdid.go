// Package zkdid implements the zkDID commitment function for SPT-Txn.
//
// Per Section 5.4 of draft-coetzee-oauth-spt-txn-tokens, the humanAnchor is:
//
//	zkdid_commitment = H(biometric_template, template_randomness)   over BN254
//
// The hash H lives in internal/zkhash and is the SAME function the ZK commitment
// circuit (internal/zkproof) proves in-circuit — so the token's humanAnchor IS
// the value a holder proves knowledge of, not a separate digest. H is Poseidon2
// (migrated from MiMC), domain-separated per use; native and in-circuit hashing
// are kept identical (swapping H is a coordinated change in zkhash + the circuit
// gadget + a trusted-setup regen). Importing this pulls gnark-crypto field
// arithmetic + the hash only, not the prover.
//
// The zkDNS resolution layer (Toby Bolton's .zkdid/.zkdns infrastructure) is the
// intended production provider of zkDID anchors. For the POC, identity material
// is supplied directly as a deterministic byte slice representing a test human.
package zkdid

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkhash"
)

// Commitment is a 32-byte zkDID commitment (the humanAnchor) — the canonical
// big-endian encoding of a BN254 field element.
type Commitment [32]byte

// String returns the hex encoding of the commitment.
func (c Commitment) String() string {
	return hex.EncodeToString(c[:])
}

// Bytes returns the commitment as a byte slice.
func (c Commitment) Bytes() []byte {
	b := make([]byte, 32)
	copy(b, c[:])
	return b
}

// BigInt returns the commitment as a field-element integer — the form used as
// the ZK circuit's public input, so a commitment proof can be verified directly
// against a token's humanAnchor.
func (c Commitment) BigInt() *big.Int {
	return new(big.Int).SetBytes(c[:])
}

// Compute derives a zkDID commitment from identity material and randomness using
// the shared ZK-friendly hash, so the result equals zkproof's commitment over
// the same inputs.
func Compute(identityMaterial, randomness []byte) Commitment {
	e := zkhash.Commit(identityMaterial, randomness)
	var out Commitment
	copy(out[:], e.Marshal()) // canonical 32-byte big-endian field element
	return out
}

// NewRandomness generates 32 bytes of cryptographic randomness for use as the
// template_randomness. Each CAT issuance uses fresh randomness so commitments
// are unlinkable across tokens.
func NewRandomness() ([32]byte, error) {
	var r [32]byte
	_, err := rand.Read(r[:])
	return r, err
}

// TestPrincipal returns deterministic identity material for the named test
// principal. POC only — production derives this from a verified biometric.
func TestPrincipal(name string) []byte {
	h := sha512.Sum512([]byte("spt-txn-poc:principal:" + name))
	return h[:]
}
