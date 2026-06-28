// Package trisa bridges an SPT-Txn Travel Rule attestation to/from a TRISA
// SecureEnvelope payload, so a SPT-Txn node can exchange with a TRISA
// counterparty (TRP support already lives in internal/trp).
//
// Scope (deliberate): this is the PAYLOAD MAPPING — the semantic translation
// between travelrule.Attestation (SD-JWT IVMS101 + the three Groth16 proofs +
// the payment binding) and TRISA's cleartext Payload shape (identity /
// transaction / timestamps). It is pure Go, round-trip tested, and pulls in no
// network or protobuf dependency.
//
// The TRANSPORT — per-message AES-GCM sealing of the payload, sealing the key to
// the recipient's public key, the TRISA Global Directory (GDS) lookup, the
// X.509/mTLS trust, and the gRPC Transfer/KeyExchange RPCs — is intentionally NOT
// here. It belongs in a separate module built against the official TRISA Go SDK,
// kept out of the authorization core exactly like the Hedera client
// (clients/hcs-anchor). This package is what that transport carries.
//
// Why this composes: SPT-Txn's proofs already give payload-level privacy and
// non-repudiation, so running them inside a TRISA sealed envelope is defence in
// depth — ZK for what the counterparty may compute, sealing for confidentiality
// at rest and crypto-erasure.
package trisa

import (
	"fmt"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/travelrule"
)

// ExtensionID identifies the SPT-Txn proof extension carried in a TRISA payload.
const ExtensionID = "spt-txn/1"

// Envelope mirrors the cleartext Payload of a TRISA SecureEnvelope. In TRISA the
// envelope id is a UUID and the payload is protobuf sealed on the wire; here the
// id is the SPT-Txn payment binding so the envelope is self-describing.
type Envelope struct {
	ID      string  `json:"id"`
	Payload Payload `json:"payload"`
}

// Payload is TRISA's payload: an IVMS101 identity, a transaction, and timestamps.
type Payload struct {
	Identity    Identity    `json:"identity"`
	Transaction Transaction `json:"transaction"`
	SentAt      string      `json:"sent_at"`
	ReceivedAt  string      `json:"received_at,omitempty"`
}

// Identity is TRISA's IVMS101 identity slot. SPT-Txn carries the
// selectively-disclosable SD-JWT here instead of cleartext IVMS101 blocks — so
// the counterparty receives only what the disclosure policy permits.
type Identity struct {
	Format string `json:"format"` // "sd-jwt+ivms101"
	SDJWT  string `json:"sd_jwt"`
}

// Transaction is TRISA's generic transaction plus the SPT-Txn proof extension.
type Transaction struct {
	Asset     string  `json:"asset"`
	Amount    string  `json:"amount"`
	Extension ProofExt `json:"spt_txn"`
}

// ProofExt carries the SPT-Txn zero-knowledge attestation as a registered TRISA
// envelope extension. Proof bytes serialize as base64 in JSON.
type ProofExt struct {
	Version          string `json:"version"`
	HumanAnchor      string `json:"human_anchor"`
	CommitmentProof  []byte `json:"commitment_proof"`
	AmountCommitment string `json:"amount_commitment"`
	Threshold        uint64 `json:"threshold"`
	ThresholdProof   []byte `json:"threshold_proof"`
	VASPRoot         string `json:"vasp_root"`
	VASPProof        []byte `json:"vasp_proof"`
	TxnContextHash   string `json:"txn_context_hash"`
}

// ToTRISA maps an SPT-Txn attestation + transfer (asset, amount) into a
// TRISA-shaped envelope. The envelope id is bound to the payment context hash.
func ToTRISA(att travelrule.Attestation, asset, amount string) Envelope {
	return Envelope{
		ID: att.TxnContextHash,
		Payload: Payload{
			Identity: Identity{Format: "sd-jwt+ivms101", SDJWT: att.SDJWT},
			Transaction: Transaction{
				Asset:  asset,
				Amount: amount,
				Extension: ProofExt{
					Version:          ExtensionID,
					HumanAnchor:      att.HumanAnchor,
					CommitmentProof:  att.CommitmentProof,
					AmountCommitment: att.AmountCommitment,
					Threshold:        att.Threshold,
					ThresholdProof:   att.ThresholdProof,
					VASPRoot:         att.VASPRoot,
					VASPProof:        att.VASPProof,
					TxnContextHash:   att.TxnContextHash,
				},
			},
			SentAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// FromTRISA reconstructs the SPT-Txn attestation + transfer from a TRISA
// envelope. It rejects an envelope without the SPT-Txn extension (this node
// requires payload-level ZK, mirroring the TRP cleartext-only refusal) and one
// whose id does not match the attestation's payment binding.
func FromTRISA(env Envelope) (att travelrule.Attestation, asset, amount string, err error) {
	e := env.Payload.Transaction.Extension
	if e.Version != ExtensionID {
		return att, "", "", fmt.Errorf("trisa: missing or unsupported spt-txn extension %q (cleartext-only refused)", e.Version)
	}
	if env.ID != e.TxnContextHash {
		return att, "", "", fmt.Errorf("trisa: envelope id %q does not match attestation txn_context_hash %q", env.ID, e.TxnContextHash)
	}
	att = travelrule.Attestation{
		SDJWT:            env.Payload.Identity.SDJWT,
		HumanAnchor:      e.HumanAnchor,
		CommitmentProof:  e.CommitmentProof,
		AmountCommitment: e.AmountCommitment,
		Threshold:        e.Threshold,
		ThresholdProof:   e.ThresholdProof,
		VASPRoot:         e.VASPRoot,
		VASPProof:        e.VASPProof,
		TxnContextHash:   e.TxnContextHash,
	}
	return att, env.Payload.Transaction.Asset, env.Payload.Transaction.Amount, nil
}
