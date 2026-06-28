// Package tfrpolicy is a configurable decision engine for the EU Transfer of
// Funds Regulation (Reg (EU) 2023/1113) "missing-information" procedures: a CASP
// must have a risk-based policy for what to do when an incoming transfer lacks
// required originator/beneficiary information, comes from an unregistered
// counterparty, or involves a self-hosted wallet above the verification
// threshold. This package turns those obligations into an explicit, testable
// ACCEPT / HOLD / REJECT / REQUEST_MORE decision.
//
// It decides; it does not perform KYC, sanctions screening, or the self-hosted
// wallet ownership check itself — those remain the CASP's. See
// docs/EU-TFR-MICA-MAPPING.md.
package tfrpolicy

import "fmt"

// Action is the policy outcome for a transfer.
type Action string

const (
	// Accept — process the transfer.
	Accept Action = "ACCEPT"
	// Hold — quarantine pending review (e.g. unregistered counterparty, or a
	// self-hosted wallet whose control has not been verified).
	Hold Action = "HOLD"
	// Reject — refuse and return (e.g. no attestation and cleartext disallowed).
	Reject Action = "REJECT"
	// RequestMore — ask the counterparty for the missing required fields.
	RequestMore Action = "REQUEST_MORE"
)

// Transfer is the compliance-relevant state of an inbound transfer (no PII).
type Transfer struct {
	HasAttestation         bool   // an SPT-Txn / Travel Rule payload is present
	RequiredFieldsPresent  bool   // the TFR-required originator/beneficiary fields are captured
	CounterpartyRegistered bool   // the counterparty CASP is a registered/known VASP
	SelfHosted             bool   // the other side is a self-hosted (unhosted) wallet
	SelfHostedVerified     bool   // proof-of-control of the self-hosted wallet passed
	AmountEUR              uint64 // transfer value in EUR (for the self-hosted threshold)
}

// Policy is the node's configured risk posture.
type Policy struct {
	// AllowCleartext permits transfers with no privacy-preserving attestation.
	// Default false — security-by-design: this node requires an attestation.
	AllowCleartext bool
	// SelfHostedThresholdEUR is the value at/above which a self-hosted wallet
	// must have verified control (TFR uses €1000). Zero means use the default.
	SelfHostedThresholdEUR uint64
	// OnMissingFields is applied when required fields are absent (default RequestMore).
	OnMissingFields Action
	// OnUnregisteredCounterparty is applied when the counterparty is not
	// registered/known (default Hold).
	OnUnregisteredCounterparty Action
}

// DefaultSelfHostedThresholdEUR is the EU TFR self-hosted verification threshold.
const DefaultSelfHostedThresholdEUR = 1000

// Decision is the engine output.
type Decision struct {
	Action Action
	Reason string
}

func (p Policy) selfHostedThreshold() uint64 {
	if p.SelfHostedThresholdEUR == 0 {
		return DefaultSelfHostedThresholdEUR
	}
	return p.SelfHostedThresholdEUR
}

func (p Policy) onMissing() Action {
	if p.OnMissingFields == "" {
		return RequestMore
	}
	return p.OnMissingFields
}

func (p Policy) onUnregistered() Action {
	if p.OnUnregisteredCounterparty == "" {
		return Hold
	}
	return p.OnUnregisteredCounterparty
}

// Decide evaluates a transfer against the policy. Checks run hardest-fail first;
// the first failing condition determines the action (fail-closed ordering).
func (p Policy) Decide(t Transfer) Decision {
	if !t.HasAttestation && !p.AllowCleartext {
		return Decision{Reject, "no Travel Rule attestation and cleartext is not permitted by this node"}
	}
	if !t.RequiredFieldsPresent {
		return Decision{p.onMissing(), "required originator/beneficiary information is missing or incomplete"}
	}
	if t.SelfHosted && t.AmountEUR >= p.selfHostedThreshold() && !t.SelfHostedVerified {
		return Decision{Hold, fmt.Sprintf("self-hosted wallet at/above €%d requires verified proof-of-control", p.selfHostedThreshold())}
	}
	if !t.CounterpartyRegistered {
		return Decision{p.onUnregistered(), "counterparty CASP is not registered/known"}
	}
	return Decision{Accept, "all TFR preconditions satisfied"}
}
