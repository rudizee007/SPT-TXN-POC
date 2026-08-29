package tbac

import (
	"errors"
	"testing"
)

// The enforcement this closes: a token carrying a cumulative budget but no
// max_amount must still bound its transactions at spend time. Before
// max_cumulative was projected, TxnScope asserted NOTHING for such a token, so
// Contains(parent, projected) had nothing to compare and a transaction of any
// size cleared — a $3-cumulative slice could mint a $1000 transfer.
//
// This is the spend-time half of the stateless sub-band control. The SUM across
// slices is bounded at issuance (ValidateSubbandDivision) plus single-use; here
// we prove one slice's single transaction cannot exceed the slice's own budget.
func TestTxnScope_CumulativeOnlySlice_BoundsItsTransaction(t *testing.T) {
	parent := Scope{cumulativeDim: 3, "currency": "USD"} // a $3 slice, no max_amount

	// Over the slice budget: must be refused (projected, then Contains fails).
	over, err := TxnScope(parent, txn("1000", "USD"))
	if err != nil {
		t.Fatalf("projecting a valid amount must not error: %v", err)
	}
	if got := over[cumulativeDim]; got != anyNumber("1000") {
		t.Fatalf("max_cumulative was not projected: got %v", over)
	}
	if err := Contains(parent, over); err == nil {
		t.Fatal("a transaction over the slice's cumulative budget cleared — it must be refused")
	}

	// Within the slice budget: must clear.
	within, err := TxnScope(parent, txn("3", "USD"))
	if err != nil {
		t.Fatalf("projecting a valid amount must not error: %v", err)
	}
	if err := Contains(parent, within); err != nil {
		t.Fatalf("a transaction within the slice budget must clear: %v", err)
	}
}

// A cumulative budget with no currency is as meaningless as an unqualified
// max_amount: it would bound "$3 cumulative in every currency at once". Refused
// on the same terms, and diagnosed as the cumulative dimension, not max_amount.
func TestTxnScope_UnqualifiedCumulativeCeiling_Refused(t *testing.T) {
	for name, parent := range map[string]Scope{
		"bare cumulative":       {cumulativeDim: 5000},
		"cumulative and action": {"action": "payment", cumulativeDim: 5000},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := TxnScope(parent, txn("100", "USD"))
			if err == nil {
				t.Fatal("an unqualified cumulative ceiling was projected")
			}
			if !errors.Is(err, ErrCeilingUnqualified) {
				t.Errorf("wrong diagnosis: want ErrCeilingUnqualified, got: %v", err)
			}
		})
	}
}

// Both money ceilings are enforced together (conjunction). A slice may carry a
// per-transaction max_amount AND a cumulative budget; a transaction must clear
// both. This guards against a regression that projected only one of the two.
func TestTxnScope_AmountAndCumulative_BothEnforced(t *testing.T) {
	parent := Scope{"max_amount": 500, cumulativeDim: 5000, "currency": "USD"}

	// Over the per-transaction ceiling but under the cumulative budget: refused.
	overAmount, err := TxnScope(parent, txn("1000", "USD"))
	if err != nil {
		t.Fatalf("projection error: %v", err)
	}
	if overAmount["max_amount"] != anyNumber("1000") || overAmount[cumulativeDim] != anyNumber("1000") {
		t.Fatalf("both ceilings must be projected: %v", overAmount)
	}
	if err := Contains(parent, overAmount); err == nil {
		t.Fatal("a transaction over max_amount cleared despite being under the cumulative budget")
	}

	// Under both: clears.
	within, err := TxnScope(parent, txn("100", "USD"))
	if err != nil {
		t.Fatalf("projection error: %v", err)
	}
	if err := Contains(parent, within); err != nil {
		t.Fatalf("a transaction within both ceilings must clear: %v", err)
	}
}

// A scope with no cumulative budget must still project exactly as before — the
// new branch must not over-assert.
func TestTxnScope_NoCumulative_Unchanged(t *testing.T) {
	got, err := TxnScope(Scope{"max_amount": 5000, "currency": "USD"}, txn("100", "USD"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := got[cumulativeDim]; present {
		t.Fatalf("a cumulative ceiling was asserted against a scope that declares none: %v", got)
	}
}
