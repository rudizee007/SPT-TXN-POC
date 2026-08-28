package tbac_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// monthBudget is a $100 (USD) cumulative budget for a period — the thing a
// division cuts into bands. It is a valid, currency-qualified money ceiling.
func monthBudget() tbac.Scope {
	return tbac.Scope{"max_cumulative": 100, "currency": "USD"}
}

// band is a single sub-band carrying its own slice of the budget, in USD.
func band(v any) tbac.Scope {
	return tbac.Scope{"max_cumulative": v, "currency": "USD"}
}

// A division that allocates LESS than the budget is sound, and the allocated
// total is reported exactly. 30 day-bands of $3 = $90 under a $100 month.
func TestSubband_ValidDivisionUnderBudget(t *testing.T) {
	slices := make([]tbac.Scope, 30)
	for i := range slices {
		slices[i] = band(3)
	}
	total, err := tbac.ValidateSubbandDivision(monthBudget(), slices)
	if err != nil {
		t.Fatalf("30x$3=$90 under a $100 budget must be sound: %v", err)
	}
	if total.RatString() != "90" {
		t.Errorf("allocated total = %s, want 90", total.RatString())
	}
}

// The bound is <=, not <: a division whose slices sum to EXACTLY the budget is
// allowed. 4 x $25 = $100.
func TestSubband_ExactBudgetIsAllowed(t *testing.T) {
	slices := []tbac.Scope{band(25), band(25), band(25), band(25)}
	if _, err := tbac.ValidateSubbandDivision(monthBudget(), slices); err != nil {
		t.Fatalf("an exact division (sum == budget) must be allowed: %v", err)
	}
}

// The core property: slices that each fit under the total but SUM past it are
// over-issuance and must be refused. 34 x $3 = $102 over a $100 budget. This is
// the case per-hop containment cannot see.
func TestSubband_OverAllocationIsRefused(t *testing.T) {
	slices := make([]tbac.Scope, 34)
	for i := range slices {
		slices[i] = band(3)
	}
	_, err := tbac.ValidateSubbandDivision(monthBudget(), slices)
	if !errors.Is(err, tbac.ErrSubbandOverAllocates) {
		t.Fatalf("$102 over a $100 budget must be ErrSubbandOverAllocates, got %v", err)
	}
}

// A single band larger than the whole budget is caught by containment, before
// the sum is ever reached.
func TestSubband_OneSliceOverParentIsRefused(t *testing.T) {
	if _, err := tbac.ValidateSubbandDivision(monthBudget(), []tbac.Scope{band(101)}); err == nil {
		t.Fatal("a slice exceeding the parent budget must be refused")
	}
}

// A per-transaction ceiling is not a cumulative budget; you cannot sub-band a
// scope that declares no total to divide.
func TestSubband_ParentWithoutBudgetIsRefused(t *testing.T) {
	parent := tbac.Scope{"max_amount": 50, "currency": "USD"}
	_, err := tbac.ValidateSubbandDivision(parent, []tbac.Scope{band(10)})
	if !errors.Is(err, tbac.ErrSubbandNoParentBudget) {
		t.Fatalf("a parent with no max_cumulative must be ErrSubbandNoParentBudget, got %v", err)
	}
}

// A band with a budget but no currency bounds every currency at once — refused
// at division time, exactly as issuance refuses an unqualified ceiling.
func TestSubband_UnqualifiedSliceIsRefused(t *testing.T) {
	slice := tbac.Scope{"max_cumulative": 3} // no currency
	_, err := tbac.ValidateSubbandDivision(monthBudget(), []tbac.Scope{slice})
	if !errors.Is(err, tbac.ErrCeilingUnqualified) {
		t.Fatalf("an unqualified band must be ErrCeilingUnqualified, got %v", err)
	}
}

// A band in a different currency cannot divide the budget — caught by
// containment's equality check on currency.
func TestSubband_MixedCurrencyIsRefused(t *testing.T) {
	slice := tbac.Scope{"max_cumulative": 3, "currency": "EUR"}
	if _, err := tbac.ValidateSubbandDivision(monthBudget(), []tbac.Scope{slice}); err == nil {
		t.Fatal("a band in a currency other than the parent's must be refused")
	}
}

// A slice with a currency but no max_cumulative is not a band at all.
func TestSubband_SliceMissingBudgetIsRefused(t *testing.T) {
	slice := tbac.Scope{"currency": "USD"}
	_, err := tbac.ValidateSubbandDivision(monthBudget(), []tbac.Scope{slice})
	if !errors.Is(err, tbac.ErrSubbandNotABand) {
		t.Fatalf("a slice with no max_cumulative must be ErrSubbandNotABand, got %v", err)
	}
}

// An empty division is a caller mistake and is refused loudly.
func TestSubband_EmptyDivisionIsRefused(t *testing.T) {
	if _, err := tbac.ValidateSubbandDivision(monthBudget(), nil); !errors.Is(err, tbac.ErrSubbandEmpty) {
		t.Fatalf("an empty division must be ErrSubbandEmpty, got %v", err)
	}
}

// The sum is exact big.Rat, not float64: at 2^53+1 (past float's integer
// precision) a division that is correct to the unit is accepted, and one unit
// over is refused. float64 would round both to 2^53 and accept the over-budget
// division — this test is what proves it does not.
func TestSubband_ExactPrecisionOnLargeValues(t *testing.T) {
	const budget = "9007199254740993" // 2^53 + 1
	parent := tbac.Scope{"max_cumulative": json.Number(budget), "currency": "USD"}

	// 4503599627370496 + 4503599627370497 = 9007199254740993 exactly.
	ok := []tbac.Scope{
		{"max_cumulative": json.Number("4503599627370496"), "currency": "USD"},
		{"max_cumulative": json.Number("4503599627370497"), "currency": "USD"},
	}
	if _, err := tbac.ValidateSubbandDivision(parent, ok); err != nil {
		t.Fatalf("exact large-value division must be sound (no float rounding): %v", err)
	}

	// One unit more must be caught — total 9007199254740994 > budget.
	over := []tbac.Scope{
		{"max_cumulative": json.Number("4503599627370496"), "currency": "USD"},
		{"max_cumulative": json.Number("4503599627370498"), "currency": "USD"},
	}
	if _, err := tbac.ValidateSubbandDivision(parent, over); !errors.Is(err, tbac.ErrSubbandOverAllocates) {
		t.Fatalf("one unit over, at 2^53 scale, must be caught exactly: %v", err)
	}
}

// A single child's max_cumulative still attenuates by the ordinary ceiling rule
// (this is what registering it in numericDirection buys) — proving the new
// dimension is wired into Contains, not only into the division helper.
func TestSubband_CumulativeAttenuatesAsCeiling(t *testing.T) {
	parent := tbac.Scope{"max_cumulative": 100, "currency": "USD"}
	if err := tbac.Contains(parent, tbac.Scope{"max_cumulative": 40, "currency": "USD"}); err != nil {
		t.Errorf("a lower cumulative budget must be contained: %v", err)
	}
	if err := tbac.Contains(parent, tbac.Scope{"max_cumulative": 140, "currency": "USD"}); err == nil {
		t.Error("a higher cumulative budget must be refused by containment")
	}
}
