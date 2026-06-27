package zkproof

// zkproof.go — circuit lifecycle (compile + trusted setup), proving, and
// verification, with a domain API that keeps gnark types out of callers.
//
// IMPORTANT (trusted setup): groth16.Setup is randomized — each call produces a
// different proving/verifying key pair. A real deployment runs Setup ONCE per
// circuit and shares the verifying key with all verifiers; proofs only verify
// against the vk from the same setup. Key persistence (Save/Load) is the next
// step; this file keeps setup in-process so the package and its tests are
// self-contained.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CircuitID names a circuit.
type CircuitID string

const (
	CircuitCommitment CircuitID = "commitment"
	CircuitThreshold  CircuitID = "threshold"
	CircuitVASP       CircuitID = "vasp"
)

// ProofBytes is a serialized Groth16 proof, ready for transport (e.g., embedded
// in a Travel Rule attestation). Public inputs are NOT carried inside it — the
// verifier supplies them from its own trusted context (token claims, the known
// registry root, the policy threshold), which is the secure pattern.
type ProofBytes []byte

// Artifacts holds a compiled circuit and its setup keys.
type Artifacts struct {
	ID  CircuitID
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

func newCircuit(id CircuitID) (frontend.Circuit, error) {
	switch id {
	case CircuitCommitment:
		return &CommitmentCircuit{}, nil
	case CircuitThreshold:
		return &ThresholdCircuit{}, nil
	case CircuitVASP:
		return &VASPCircuit{}, nil
	default:
		return nil, fmt.Errorf("zkproof: unknown circuit %q", id)
	}
}

// Setup compiles the circuit and runs the one-time Groth16 trusted setup.
func Setup(id CircuitID) (*Artifacts, error) {
	circuit, err := newCircuit(id)
	if err != nil {
		return nil, err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", id, err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup %s: %w", id, err)
	}
	return &Artifacts{ID: id, ccs: ccs, pk: pk, vk: vk}, nil
}

// NbConstraints reports the circuit size (useful for diagnostics/benchmarks).
func (a *Artifacts) NbConstraints() int { return a.ccs.GetNbConstraints() }

// ExportSolidity writes a Solidity Groth16 verifier for this circuit's verifying
// key. The generated contract lets an Ethereum / EVM L2 verify an SPT-Txn proof
// on-chain. Export from a PINNED verifying key (Load/LoadVerifier), never a fresh
// Setup, so the on-chain verifier matches the key the prover actually uses.
func (a *Artifacts) ExportSolidity(w io.Writer) error { return a.vk.ExportSolidity(w) }

// MarshalProofSolidity re-encodes a BN254 Groth16 proof into the EIP-197 byte
// layout the gnark-generated Solidity verifier expects (the `bytes` argument of
// its verifyProof), hex-encoded with a 0x prefix. Pass the ProofBytes returned
// by a Prove* call.
func MarshalProofSolidity(p ProofBytes) (string, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(p)); err != nil {
		return "", fmt.Errorf("read proof: %w", err)
	}
	bn, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return "", fmt.Errorf("unexpected proof type %T (want BN254)", proof)
	}
	return "0x" + hex.EncodeToString(bn.MarshalSolidity()), nil
}

// ── persistence ──────────────────────────────────────────────────────────────
//
// groth16.Setup is randomized, so prover and verifier MUST share the keys from a
// single setup. Save them once (zk-setup tool); the prover loads ccs+pk and the
// verifier loads just the vk.

// Save writes the compiled circuit and keys to dir as <id>.ccs/.pk/.vk.
func (a *Artifacts) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	parts := map[string]io.WriterTo{"ccs": a.ccs, "pk": a.pk, "vk": a.vk}
	for name, wt := range parts {
		if err := writeArtifact(filepath.Join(dir, string(a.ID)+"."+name), wt); err != nil {
			return fmt.Errorf("save %s.%s: %w", a.ID, name, err)
		}
	}
	return nil
}

// Load reads a full Artifacts (ccs+pk+vk) for proving.
func Load(id CircuitID, dir string) (*Artifacts, error) {
	ccs := groth16.NewCS(ecc.BN254)
	if err := readArtifact(filepath.Join(dir, string(id)+".ccs"), ccs); err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readArtifact(filepath.Join(dir, string(id)+".pk"), pk); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readArtifact(filepath.Join(dir, string(id)+".vk"), vk); err != nil {
		return nil, err
	}
	return &Artifacts{ID: id, ccs: ccs, pk: pk, vk: vk}, nil
}

// LoadVerifier reads only the verifying key. The result can Verify but not Prove
// — suitable for a verifier-only service, and it avoids loading the large pk.
func LoadVerifier(id CircuitID, dir string) (*Artifacts, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readArtifact(filepath.Join(dir, string(id)+".vk"), vk); err != nil {
		return nil, err
	}
	return &Artifacts{ID: id, vk: vk}, nil
}

func writeArtifact(path string, wt io.WriterTo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := wt.WriteTo(f); err != nil {
		return err
	}
	return f.Sync()
}

func readArtifact(path string, rf io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = rf.ReadFrom(f)
	return err
}

func (a *Artifacts) prove(full frontend.Circuit) (ProofBytes, error) {
	w, err := frontend.NewWitness(full, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(a.ccs, a.pk, w)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *Artifacts) verify(p ProofBytes, public frontend.Circuit) error {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(p)); err != nil {
		return fmt.Errorf("deserialize proof: %w", err)
	}
	pw, err := frontend.NewWitness(public, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof, a.vk, pw)
}

// ── Commitment predicate ─────────────────────────────────────────────────────

// ProveCommitment proves knowledge of (idMaterial, randomness) behind the
// returned humanAnchor.
func (a *Artifacts) ProveCommitment(idMaterial, randomness []byte) (proof ProofBytes, anchor *big.Int, err error) {
	id := feFromWide(idMaterial)
	r := feFromWide(randomness)
	anc := hashAnchor(id, r)
	proof, err = a.prove(&CommitmentCircuit{ID: bigOf(id), Randomness: bigOf(r), Anchor: bigOf(anc)})
	return proof, bigOf(anc), err
}

// VerifyCommitment checks a commitment proof against an expected anchor (e.g.,
// the human_anchor claim carried in the token).
func (a *Artifacts) VerifyCommitment(p ProofBytes, anchor *big.Int) error {
	return a.verify(p, &CommitmentCircuit{Anchor: anchor})
}

// ── Threshold predicate ──────────────────────────────────────────────────────

// ProveThreshold proves the committed amount is >= threshold, returning the
// amount commitment. The amount itself is never revealed.
func (a *Artifacts) ProveThreshold(amount uint64, blinding []byte, threshold uint64) (proof ProofBytes, commitment *big.Int, err error) {
	amt := feFromUint64(amount)
	bl := feFromWide(blinding)
	commit := hashAmount(amt, bl)
	proof, err = a.prove(&ThresholdCircuit{
		Amount: bigOf(amt), Blinding: bigOf(bl),
		Commitment: bigOf(commit), Threshold: new(big.Int).SetUint64(threshold),
	})
	return proof, bigOf(commit), err
}

// VerifyThreshold checks a threshold proof against the amount commitment and the
// policy threshold the verifier independently knows.
func (a *Artifacts) VerifyThreshold(p ProofBytes, commitment *big.Int, threshold uint64) error {
	return a.verify(p, &ThresholdCircuit{Commitment: commitment, Threshold: new(big.Int).SetUint64(threshold)})
}

// ── VASP-membership predicate ────────────────────────────────────────────────

// ProveVASPMembership proves the leaf is in the tree with the given root,
// without revealing which member it is.
func (a *Artifacts) ProveVASPMembership(leaf *big.Int, sibs []*big.Int, bits []int, root *big.Int) (ProofBytes, error) {
	if len(sibs) != VASPTreeDepth || len(bits) != VASPTreeDepth {
		return nil, fmt.Errorf("authentication path must have depth %d", VASPTreeDepth)
	}
	var full VASPCircuit
	full.Leaf = leaf
	full.Root = root
	for i := 0; i < VASPTreeDepth; i++ {
		full.Siblings[i] = sibs[i]
		full.PathBits[i] = bits[i]
	}
	return a.prove(&full)
}

// VerifyVASPMembership checks a membership proof against the registry root the
// verifier independently trusts.
func (a *Artifacts) VerifyVASPMembership(p ProofBytes, root *big.Int) error {
	return a.verify(p, &VASPCircuit{Root: root})
}
