package tfrpolicy

import "testing"

// a fully-compliant transfer used as the baseline; tests flip one field at a time.
func good() Transfer {
	return Transfer{
		HasAttestation:         true,
		RequiredFieldsPresent:  true,
		CounterpartyRegistered: true,
		SelfHosted:             false,
		AmountEUR:              500,
	}
}

func TestDecide_Accept(t *testing.T) {
	if d := (Policy{}).Decide(good()); d.Action != Accept {
		t.Fatalf("got %s (%s), want ACCEPT", d.Action, d.Reason)
	}
}

func TestDecide_RejectNoAttestation(t *testing.T) {
	tr := good()
	tr.HasAttestation = false
	if d := (Policy{}).Decide(tr); d.Action != Reject {
		t.Fatalf("got %s, want REJECT (cleartext disallowed by default)", d.Action)
	}
	// but allowed if the node opts in to cleartext
	if d := (Policy{AllowCleartext: true}).Decide(tr); d.Action != Accept {
		t.Fatalf("got %s, want ACCEPT when AllowCleartext", d.Action)
	}
}

func TestDecide_MissingFieldsRequestsMore(t *testing.T) {
	tr := good()
	tr.RequiredFieldsPresent = false
	if d := (Policy{}).Decide(tr); d.Action != RequestMore {
		t.Fatalf("got %s, want REQUEST_MORE", d.Action)
	}
	// configurable to reject
	if d := (Policy{OnMissingFields: Reject}).Decide(tr); d.Action != Reject {
		t.Fatalf("got %s, want REJECT override", d.Action)
	}
}

func TestDecide_SelfHostedThreshold(t *testing.T) {
	tr := good()
	tr.SelfHosted = true
	tr.SelfHostedVerified = false

	tr.AmountEUR = 999 // below default €1000 threshold → fine
	if d := (Policy{}).Decide(tr); d.Action != Accept {
		t.Fatalf("got %s, want ACCEPT below threshold", d.Action)
	}

	tr.AmountEUR = 1000 // at threshold, unverified → HOLD
	if d := (Policy{}).Decide(tr); d.Action != Hold {
		t.Fatalf("got %s, want HOLD at threshold unverified", d.Action)
	}

	tr.SelfHostedVerified = true // verified → fine
	if d := (Policy{}).Decide(tr); d.Action != Accept {
		t.Fatalf("got %s, want ACCEPT when control verified", d.Action)
	}
}

func TestDecide_UnregisteredCounterpartyHolds(t *testing.T) {
	tr := good()
	tr.CounterpartyRegistered = false
	if d := (Policy{}).Decide(tr); d.Action != Hold {
		t.Fatalf("got %s, want HOLD", d.Action)
	}
	if d := (Policy{OnUnregisteredCounterparty: Reject}).Decide(tr); d.Action != Reject {
		t.Fatalf("got %s, want REJECT override", d.Action)
	}
}
