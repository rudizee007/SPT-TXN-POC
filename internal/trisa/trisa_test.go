package trisa_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/travelrule"
	"github.com/violetskysecurity/spt-txn-poc/internal/trisa"
)

func sampleAttestation() travelrule.Attestation {
	return travelrule.Attestation{
		SDJWT:            "eyJ...sd-jwt...~disclosure1~disclosure2",
		HumanAnchor:      "1bbbaffe38a62d8da4e8db161036f85020bb0be83a958f9461b24f1a92944abb",
		CommitmentProof:  []byte("commitment-proof-bytes"),
		AmountCommitment: "3dc647fce95607d40723c910c64062e76a1702fc00ca754c3dccab719fe888ff",
		Threshold:        1000,
		ThresholdProof:   []byte("threshold-proof-bytes"),
		VASPRoot:         "abc123root",
		VASPProof:        []byte("vasp-proof-bytes"),
		TxnContextHash:   "624ee03644109dad9f688f537608b07f2df817fd4f501502c735be85da3697da",
	}
}

func TestTRISA_RoundTrip(t *testing.T) {
	att := sampleAttestation()
	env := trisa.ToTRISA(att, "XRP", "5000.00")

	// envelope must JSON-serialize (this is what the sealed transport carries)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var env2 trisa.Envelope
	if err := json.Unmarshal(raw, &env2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, asset, amount, err := trisa.FromTRISA(env2)
	if err != nil {
		t.Fatalf("FromTRISA: %v", err)
	}
	if asset != "XRP" || amount != "5000.00" {
		t.Errorf("transfer fields: got %s/%s", asset, amount)
	}
	if got.SDJWT != att.SDJWT || got.HumanAnchor != att.HumanAnchor ||
		got.AmountCommitment != att.AmountCommitment || got.Threshold != att.Threshold ||
		got.VASPRoot != att.VASPRoot || got.TxnContextHash != att.TxnContextHash {
		t.Errorf("attestation scalar fields did not round-trip: %+v", got)
	}
	if !bytes.Equal(got.CommitmentProof, att.CommitmentProof) ||
		!bytes.Equal(got.ThresholdProof, att.ThresholdProof) ||
		!bytes.Equal(got.VASPProof, att.VASPProof) {
		t.Error("proof bytes did not round-trip")
	}
	// the payment binding is the envelope id
	if env.ID != att.TxnContextHash {
		t.Errorf("envelope id %q != txn_context_hash %q", env.ID, att.TxnContextHash)
	}
}

func TestTRISA_RejectsMissingExtension(t *testing.T) {
	var env trisa.Envelope // no spt-txn extension
	env.ID = "anything"
	if _, _, _, err := trisa.FromTRISA(env); err == nil {
		t.Error("expected rejection of a cleartext envelope with no spt-txn extension")
	}
}

func TestTRISA_RejectsBindingMismatch(t *testing.T) {
	att := sampleAttestation()
	env := trisa.ToTRISA(att, "XRP", "1")
	env.ID = "tampered-envelope-id" // no longer equals the attestation binding
	if _, _, _, err := trisa.FromTRISA(env); err == nil {
		t.Error("expected rejection when envelope id != attestation txn_context_hash")
	}
}
