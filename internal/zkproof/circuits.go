// Package zkproof provides the real Groth16 zero-knowledge circuits for the
// SPT-Txn privacy-preserving Travel Rule layer, validated on the OpenBSD host.
//
// Three predicates, each proving a compliance fact while revealing nothing
// about the underlying private data:
//
//   - Commitment: the holder knows the identity material behind a humanAnchor.
//   - Threshold:  a committed transfer amount is at/above the FATF reporting
//     threshold, without revealing the amount.
//   - VASP:       a counterparty is in the registered-VASP set, without
//     revealing which member.
//
// Poseidon2 is the ZK-friendly hash (gnark's native MerkleDamgard hasher and the
// in-circuit gadget are matched by construction); it replaced MiMC in v2 for a
// large proving speedup. This package depends on gnark but the M0-M2 services do
// not import it, so only the prover/verifier binaries pull in the proving backend.
//
// Domain separation (CR-1): each predicate hashes under a distinct domain tag,
// absorbed as the FIRST input — H(tag, a, b) — exactly mirroring the native
// helpers in internal/zkhash (HashAnchor/HashAmount/HashNode). The tag constants
// are imported from zkhash so the native and in-circuit absorption sequences can
// never drift apart. The Poseidon2 Merkle-Damgard hasher absorbs one field
// element per Write argument with initial state 0, so h.Write(tag, a, b) computes
// Compress(Compress(Compress(0, tag), a), b) — identical to the native side,
// which writes the same three 32-byte canonical blocks in the same order.
package zkproof

import (
	"github.com/consensys/gnark/frontend"
	circuitposeidon2 "github.com/consensys/gnark/std/hash/poseidon2"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkhash"
)

// VASPTreeDepth fixes the registered-VASP Merkle tree depth (2^depth members).
const VASPTreeDepth = 8

// CommitmentCircuit constrains Anchor == Poseidon2(DomainAnchor, ID, Randomness).
type CommitmentCircuit struct {
	ID         frontend.Variable `gnark:",secret"`
	Randomness frontend.Variable `gnark:",secret"`
	Anchor     frontend.Variable `gnark:",public"`
}

func (c *CommitmentCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAnchor.
	h.Write(zkhash.DomainAnchor, c.ID, c.Randomness)
	api.AssertIsEqual(c.Anchor, h.Sum())
	return nil
}

// ThresholdCircuit constrains a committed amount to be >= a public threshold,
// with the amount range-checked to 64 bits to prevent field wraparound.
type ThresholdCircuit struct {
	Amount     frontend.Variable `gnark:",secret"`
	Blinding   frontend.Variable `gnark:",secret"`
	Commitment frontend.Variable `gnark:",public"`
	Threshold  frontend.Variable `gnark:",public"`
}

func (c *ThresholdCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	// Domain tag absorbed first; mirrors zkhash.HashAmount.
	h.Write(zkhash.DomainAmount, c.Amount, c.Blinding)
	api.AssertIsEqual(c.Commitment, h.Sum())

	// Range-check BOTH operands of the comparison to a shared 64-bit domain
	// (CR-4). Without constraining Threshold, the public input could be a field
	// element outside [0, 2^64) and AssertIsLessOrEqual would compare in the full
	// field, allowing a spurious "amount >= threshold" via modular wraparound.
	api.ToBinary(c.Amount, 64)
	api.ToBinary(c.Threshold, 64)
	api.AssertIsLessOrEqual(c.Threshold, c.Amount)
	return nil
}

// VASPCircuit verifies a Merkle authentication path from a secret leaf to the
// public registered-VASP root.
type VASPCircuit struct {
	Leaf     frontend.Variable                `gnark:",secret"`
	Siblings [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	PathBits [VASPTreeDepth]frontend.Variable `gnark:",secret"`
	Root     frontend.Variable                `gnark:",public"`
}

func (c *VASPCircuit) Define(api frontend.API) error {
	h, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	cur := c.Leaf
	for i := 0; i < VASPTreeDepth; i++ {
		api.AssertIsBoolean(c.PathBits[i])
		left := api.Select(c.PathBits[i], c.Siblings[i], cur)
		right := api.Select(c.PathBits[i], cur, c.Siblings[i])
		h.Reset()
		// Inner-node domain tag absorbed first; mirrors zkhash.HashNode and is
		// distinct from the commitment domains so a commitment value can never be
		// passed off as a Merkle node (or vice versa).
		h.Write(zkhash.DomainMerkleNode, left, right)
		cur = h.Sum()
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}

// MaxHops bounds the delegation-chain length the agentic proof supports (root
// CAT + up to MaxHops-1 delegations). A fixed size keeps the circuit constant;
// shorter chains pad the inactive tail so its constraints hold trivially.
const MaxHops = 4

// ChainCircuit proves a delegation chain (CAT -> CT -> ... -> leaf) is valid
// WITHOUT revealing the intermediate scopes: each hop's ceiling only narrows,
// the currency is unchanged, the delegation depth decrements by one and never
// goes negative, and the whole chain is tied to one accountable human — while
// only commitments to the leaf scope and to the human-anchor are public.
//
//	Public:  H0    = Poseidon2(DomainAnchor, Anchor, Salt)            (human-anchor commitment)
//	         CLeaf = Poseidon2(DomainAmount, leafMaxAmt, leafCurrency) (leaf scope commitment)
//	         D     = root (maximum) delegation depth
//	Private: anchor preimage + salt, and per-hop (Active, MaxAmt, Currency, Depth).
//
// Signature/issuer-trust checks stay in the native eight-step engine; this
// circuit proves only the scope-attenuation + depth + human-anchor invariants,
// which keeps it small. DomainAmount is reused for the leaf-scope commitment (a
// 2-input Poseidon2 over (maxAmount, currency)) — it is a distinct public input
// in a distinct circuit, so no cross-predicate confusion arises.
type ChainCircuit struct {
	H0      frontend.Variable `gnark:",public"`
	CLeaf   frontend.Variable `gnark:",public"`
	D       frontend.Variable `gnark:",public"`
	RegRoot frontend.Variable `gnark:",public"` // registered-CT-issuer Merkle root (F1)

	Anchor   frontend.Variable          `gnark:",secret"`
	Salt     frontend.Variable          `gnark:",secret"`
	Active   [MaxHops]frontend.Variable `gnark:",secret"`
	MaxAmt   [MaxHops]frontend.Variable `gnark:",secret"`
	Currency [MaxHops]frontend.Variable `gnark:",secret"`
	Depth    [MaxHops]frontend.Variable `gnark:",secret"`

	// Per-hop issuer registry-membership (F1, phase 1): for each ACTIVE hop, the
	// hop issuer's registry leaf (Issuer[i]) plus its authentication path
	// (IssuerSib/IssuerDir) must reconstruct the public RegRoot. Inactive tail
	// hops are unconstrained (the prover pads them with zeros).
	Issuer    [MaxHops]frontend.Variable                `gnark:",secret"`
	IssuerSib [MaxHops][VASPTreeDepth]frontend.Variable `gnark:",secret"`
	IssuerDir [MaxHops][VASPTreeDepth]frontend.Variable `gnark:",secret"`
}

func (c *ChainCircuit) Define(api frontend.API) error {
	// 1) Human-anchor: prove knowledge of the preimage behind the public commitment.
	ha, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	ha.Write(zkhash.DomainAnchor, c.Anchor, c.Salt)
	api.AssertIsEqual(c.H0, ha.Sum())

	// 2) Root hop: active, at the full declared depth D, amount range-checked.
	api.AssertIsEqual(c.Active[0], 1)
	api.AssertIsEqual(c.Depth[0], c.D)
	api.ToBinary(c.MaxAmt[0], 64)
	api.ToBinary(c.Depth[0], 32)

	// 3) Each later hop attenuates. Inactive tail hops fall back to their parent
	//    so their constraints hold trivially (the active hops form a prefix).
	for i := 1; i < MaxHops; i++ {
		api.AssertIsBoolean(c.Active[i])
		// contiguous active prefix: no 0 -> 1 reactivation.
		api.AssertIsLessOrEqual(c.Active[i], c.Active[i-1])

		amtEff := api.Select(c.Active[i], c.MaxAmt[i], c.MaxAmt[i-1])
		curEff := api.Select(c.Active[i], c.Currency[i], c.Currency[i-1])
		depEff := api.Select(c.Active[i], c.Depth[i], api.Sub(c.Depth[i-1], 1))

		// attenuation: parent - child >= 0 (child also range-checked).
		api.ToBinary(c.MaxAmt[i], 64)
		api.ToBinary(api.Sub(c.MaxAmt[i-1], amtEff), 64)

		// currency unchanged along the chain.
		api.AssertIsEqual(curEff, c.Currency[i-1])

		// depth decrements by one; the active depth stays non-negative.
		api.AssertIsEqual(depEff, api.Sub(c.Depth[i-1], 1))
		api.ToBinary(api.Select(c.Active[i], c.Depth[i], 0), 32)
	}

	// 4) Leaf = last active hop: isLeaf[i] = Active[i] AND NOT Active[i+1].
	var leafAmt frontend.Variable = 0
	var leafCur frontend.Variable = 0
	for i := 0; i < MaxHops; i++ {
		var nextActive frontend.Variable = 0
		if i+1 < MaxHops {
			nextActive = c.Active[i+1]
		}
		isLeaf := api.Mul(c.Active[i], api.Sub(1, nextActive))
		leafAmt = api.Add(leafAmt, api.Mul(isLeaf, c.MaxAmt[i]))
		leafCur = api.Add(leafCur, api.Mul(isLeaf, c.Currency[i]))
	}

	// 5) The leaf scope commitment must match the public CLeaf.
	hs, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	hs.Write(zkhash.DomainAmount, leafAmt, leafCur)
	api.AssertIsEqual(c.CLeaf, hs.Sum())

	// 6) Per-hop issuer trust (F1, phase 1): every ACTIVE hop's issuer key must be
	//    a member of the registered-CT-issuer tree committed by the public RegRoot
	//    — proving each hidden hop was issued by a registry-listed issuer key. The
	//    Merkle node domain/orientation mirror VASPCircuit exactly. This does NOT
	//    prove the issuer SIGNED the hop (that is the opt-in in-circuit-signature
	//    phase; the cleartext engine verifies signatures and stays the stronger
	//    default). Inactive tail hops compare RegRoot to itself, so the prover may
	//    pad them with zeros.
	hm, err := circuitposeidon2.New(api)
	if err != nil {
		return err
	}
	for i := 0; i < MaxHops; i++ {
		cur := c.Issuer[i]
		for j := 0; j < VASPTreeDepth; j++ {
			api.AssertIsBoolean(c.IssuerDir[i][j])
			left := api.Select(c.IssuerDir[i][j], c.IssuerSib[i][j], cur)
			right := api.Select(c.IssuerDir[i][j], cur, c.IssuerSib[i][j])
			hm.Reset()
			hm.Write(zkhash.DomainMerkleNode, left, right)
			cur = hm.Sum()
		}
		api.AssertIsEqual(api.Select(c.Active[i], cur, c.RegRoot), c.RegRoot)
	}

	return nil
}
