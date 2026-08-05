// Package travelrule assembles the privacy-preserving FATF Travel Rule
// attestation for SPT-Txn. It complements XRPL's on-ledger Credentials/DID
// layer: instead of shipping raw originator/beneficiary PII between VASPs, it
// produces an attestation that
//
//   - carries the IVMS101 fields as a selectively-disclosable SD-JWT (reveal
//     only what a counterparty/regulator is entitled to), and
//   - proves the predicates that must stay private with zero-knowledge:
//     identity-commitment knowledge, amount ≥ reporting threshold (amount
//     hidden), and beneficiary-VASP registration (which VASP hidden),
//
// all bound to the specific SPT-Txn payment via its context hash. The verifier
// learns "this transfer is reportable, between a known-registered counterparty,
// with an authenticated identity" without learning the amount or the
// counterparty identity it was not entitled to see.
//
// Binding note (POC): the attestation's HumanAnchor is the MiMC identity
// commitment proven here; unifying it with the token's human_anchor claim is the
// internal/zkdid rewire (still SHA-256 there). The payment binding via
// TxnContextHash is already shared with the SPT-Txn token end to end.
package travelrule

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/ivms101"
	"github.com/rudizee007/spt-txn-poc/internal/sdjwt"
	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

// DefaultReportingThreshold is the FATF ~1000-unit reporting threshold. Real
// deployments set it per jurisdiction/currency.
const DefaultReportingThreshold = uint64(1000)

// Transfer is the value transfer being attested. Originator/beneficiary identity
// is carried as an IVMS101 payload — the data model TRISA and TRP use — so the
// attestation interoperates with existing Travel Rule networks.
type Transfer struct {
	Identity ivms101.IdentityPayload
	Amount   uint64
	Currency string
}

// Secrets are the private inputs the originator VASP holds for the proofs.
type Secrets struct {
	OriginatorID      []byte // identity material behind the humanAnchor
	OriginatorRand    []byte // anchor randomness
	AmountBlinding    []byte // blinding for the amount commitment
	BeneficiaryVASPID []byte // the beneficiary VASP's registry leaf identifier
}

// Attestation is the transport object. Proofs are opaque bytes; public inputs
// are decimal strings so the verifier can match them against trusted context.
type Attestation struct {
	SDJWT            string             // IVMS101 fields, selectively disclosable
	HumanAnchor      string             // public input to the commitment proof
	CommitmentProof  zkproof.ProofBytes // knows identity behind HumanAnchor
	AmountCommitment string             // public input to the threshold proof
	Threshold        uint64
	ThresholdProof   zkproof.ProofBytes // committed amount >= Threshold
	VASPRoot         string             // registry root (public input)
	VASPProof        zkproof.ProofBytes // beneficiary VASP is registered
	TxnContextHash   string             // binding to the SPT-Txn payment
}

// Issuer is the originator VASP. It holds the signing key, the per-circuit
// setup artifacts, and the registered-VASP registry.
type Issuer struct {
	Name           string
	Signer         ed25519.PrivateKey
	Commit         *zkproof.Artifacts
	Threshold      *zkproof.Artifacts
	VASP           *zkproof.Artifacts
	Registry       *zkproof.MerkleTree
	ThresholdValue uint64
}

// Build produces a Travel Rule attestation for a transfer, bound to
// txnContextHash (the SPT-Txn payment the token authorizes).
func (iss *Issuer) Build(t Transfer, s Secrets, txnContextHash string, ttl time.Duration) (*Attestation, error) {
	threshold := iss.ThresholdValue
	if threshold == 0 {
		threshold = DefaultReportingThreshold
	}

	// 1. ZK: identity commitment.
	cProof, anchor, err := iss.Commit.ProveCommitment(s.OriginatorID, s.OriginatorRand)
	if err != nil {
		return nil, fmt.Errorf("commitment proof: %w", err)
	}

	// 2. ZK: amount is at/above the reporting threshold (amount stays hidden).
	tProof, amtCommit, err := iss.Threshold.ProveThreshold(t.Amount, s.AmountBlinding, threshold)
	if err != nil {
		return nil, fmt.Errorf("threshold proof: %w", err)
	}

	// 3. ZK: beneficiary VASP is registered (which one stays hidden).
	leaf, sibs, bits, root, ok := iss.Registry.ProofForMember(s.BeneficiaryVASPID)
	if !ok {
		return nil, fmt.Errorf("beneficiary VASP is not in the registry")
	}
	vProof, err := iss.VASP.ProveVASPMembership(leaf, sibs, bits, root)
	if err != nil {
		return nil, fmt.Errorf("VASP membership proof: %w", err)
	}

	// 4. IVMS101 as a selectively-disclosable SD-JWT, bound to the payment and
	//    the identity anchor. The payload is validated against the FATF minimum
	//    data set, then flattened to dotted-path claims so each field can be
	//    revealed or hidden individually (e.g. disclose a surname but not a DOB).
	if err := t.Identity.Validate(); err != nil {
		return nil, fmt.Errorf("IVMS101: %w", err)
	}
	disclosable := t.Identity.Flatten()
	disclosable["currency"] = t.Currency
	bound := map[string]any{
		"txn_context_hash": txnContextHash,
		"human_anchor":     anchor.Text(10),
		// Bind the committed amount into the signed attestation so the
		// threshold proof is provably about THIS transfer's commitment and an
		// attacker cannot swap in a different AmountCommitment (TR-1).
		"amount_commitment": amtCommit.Text(10),
	}
	sd, err := sdjwt.IssueBound(iss.Name, disclosable, bound, iss.Signer, ttl)
	if err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}

	return &Attestation{
		SDJWT:            sd,
		HumanAnchor:      anchor.Text(10),
		CommitmentProof:  cProof,
		AmountCommitment: amtCommit.Text(10),
		Threshold:        threshold,
		ThresholdProof:   tProof,
		VASPRoot:         root.Text(10),
		VASPProof:        vProof,
		TxnContextHash:   txnContextHash,
	}, nil
}

// Verifier is the beneficiary VASP / regulator. It trusts the issuer key, the
// per-circuit verifying artifacts, the registered-VASP root, and the policy
// threshold — all out of band, not from the attestation.
type Verifier struct {
	IssuerPub      ed25519.PublicKey
	Commit         *zkproof.Artifacts
	Threshold      *zkproof.Artifacts
	VASP           *zkproof.Artifacts
	KnownRoot      *big.Int
	ThresholdValue uint64
}

// Verify validates an attestation against the SPT-Txn payment it must be bound
// to, returns the IVMS101 claims the verifier is entitled to (the bound claims
// plus the requested disclosures). It checks, in order: payment binding, that
// the registry root and threshold are the trusted ones, the SD-JWT signature
// and its bound claims, and the three zero-knowledge proofs.
func (v *Verifier) Verify(att *Attestation, expectedTxnContextHash string, disclose []string) (map[string]any, error) {
	threshold := v.ThresholdValue
	if threshold == 0 {
		threshold = DefaultReportingThreshold
	}

	// 1. Payment binding.
	if att.TxnContextHash != expectedTxnContextHash {
		return nil, fmt.Errorf("attestation not bound to this payment")
	}
	// 2. Public inputs must be the trusted ones, not attacker-chosen.
	if att.VASPRoot != v.KnownRoot.Text(10) {
		return nil, fmt.Errorf("attestation references an unknown registry root")
	}
	if att.Threshold != threshold {
		return nil, fmt.Errorf("attestation threshold %d != policy %d", att.Threshold, threshold)
	}

	// 3. SD-JWT: verify signature, then confirm bound claims match.
	pres, err := sdjwt.Present(att.SDJWT, disclose)
	if err != nil {
		return nil, err
	}
	claims, err := sdjwt.Verify(pres, v.IssuerPub)
	if err != nil {
		return nil, fmt.Errorf("SD-JWT: %w", err)
	}
	if claims["txn_context_hash"] != att.TxnContextHash {
		return nil, fmt.Errorf("SD-JWT context-hash binding mismatch")
	}
	if claims["human_anchor"] != att.HumanAnchor {
		return nil, fmt.Errorf("SD-JWT anchor binding mismatch")
	}
	if claims["amount_commitment"] != att.AmountCommitment {
		return nil, fmt.Errorf("SD-JWT amount-commitment binding mismatch")
	}

	// 4. Zero-knowledge proofs against the trusted public inputs.
	anchor, ok := new(big.Int).SetString(att.HumanAnchor, 10)
	if !ok {
		return nil, fmt.Errorf("bad humanAnchor encoding")
	}
	if err := v.Commit.VerifyCommitment(att.CommitmentProof, anchor); err != nil {
		return nil, fmt.Errorf("identity commitment proof: %w", err)
	}
	amtCommit, ok := new(big.Int).SetString(att.AmountCommitment, 10)
	if !ok {
		return nil, fmt.Errorf("bad amount-commitment encoding")
	}
	if err := v.Threshold.VerifyThreshold(att.ThresholdProof, amtCommit, threshold); err != nil {
		return nil, fmt.Errorf("threshold proof: %w", err)
	}
	if err := v.VASP.VerifyVASPMembership(att.VASPProof, v.KnownRoot); err != nil {
		return nil, fmt.Errorf("VASP membership proof: %w", err)
	}

	return claims, nil
}
