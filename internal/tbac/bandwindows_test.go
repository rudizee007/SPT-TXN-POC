package tbac_test

import (
	"errors"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// bandUSD is a slice carrying its budget portion (USD) and a time window.
func bandUSD(v any, nbf, exp int64) tbac.Band {
	return tbac.Band{Scope: tbac.Scope{"max_cumulative": v, "currency": "USD"}, NotBefore: nbf, Expiry: exp}
}

// A sound windowed division: three $3 day-bands tiling [0,30) back-to-back under
// a $100 month whose window is [0,30). Both axes pass; the total is exact.
func TestBandDivision_ValidWindowedDivision(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 0, 10), bandUSD(3, 10, 20), bandUSD(3, 20, 30)}
	total, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands)
	if err != nil {
		t.Fatalf("a sound windowed division must pass: %v", err)
	}
	if total.RatString() != "9" {
		t.Errorf("allocated total = %s, want 9", total.RatString())
	}
}

// Adjacent windows meeting at a point (Expiry == next NotBefore) do not overlap.
func TestBandDivision_BackToBackAllowed(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 0, 10), bandUSD(3, 10, 20)}
	if _, err := tbac.ValidateBandDivision(monthBudget(), 0, 20, bands); err != nil {
		t.Fatalf("back-to-back windows must be allowed: %v", err)
	}
}

// Two bands live at once would let the per-window cap stack. Refused. This is the
// property that makes "$3 today, not $6" hold.
func TestBandDivision_OverlapRefused(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 0, 15), bandUSD(3, 10, 20)}
	_, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands)
	if !errors.Is(err, tbac.ErrBandWindowsOverlap) {
		t.Fatalf("overlapping windows must be ErrBandWindowsOverlap, got %v", err)
	}
}

// Overlap is detected regardless of the caller's slice order.
func TestBandDivision_OverlapDetectedUnsorted(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 20, 30), bandUSD(3, 0, 15), bandUSD(3, 10, 20)}
	_, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands)
	if !errors.Is(err, tbac.ErrBandWindowsOverlap) {
		t.Fatalf("overlap out of input order must still be caught, got %v", err)
	}
}

// A valid division presented out of order still passes (internal sort).
func TestBandDivision_UnsortedValidPasses(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 20, 30), bandUSD(3, 0, 10), bandUSD(3, 10, 20)}
	if _, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands); err != nil {
		t.Fatalf("a valid division in any order must pass: %v", err)
	}
}

// A band reaching outside the parent's window is refused.
func TestBandDivision_OutsideParentRefused(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 0, 40)}
	_, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands)
	if !errors.Is(err, tbac.ErrBandWindowOutsideParent) {
		t.Fatalf("a band outside the parent window must be ErrBandWindowOutsideParent, got %v", err)
	}
}

// An empty band window is refused.
func TestBandDivision_EmptyBandWindowRefused(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 10, 10)}
	_, err := tbac.ValidateBandDivision(monthBudget(), 0, 30, bands)
	if !errors.Is(err, tbac.ErrBandWindowEmpty) {
		t.Fatalf("an empty band window must be ErrBandWindowEmpty, got %v", err)
	}
}

// An empty parent window is refused (nothing to divide).
func TestBandDivision_EmptyParentWindowRefused(t *testing.T) {
	bands := []tbac.Band{bandUSD(3, 30, 40)}
	_, err := tbac.ValidateBandDivision(monthBudget(), 30, 30, bands)
	if !errors.Is(err, tbac.ErrBandWindowEmpty) {
		t.Fatalf("an empty parent window must be ErrBandWindowEmpty, got %v", err)
	}
}

// The amount axis is still enforced: bands whose windows are fine but which
// over-allocate the budget are refused by the delegated ValidateSubbandDivision.
func TestBandDivision_AmountStillEnforced(t *testing.T) {
	small := tbac.Scope{"max_cumulative": 5, "currency": "USD"}
	bands := []tbac.Band{bandUSD(3, 0, 10), bandUSD(3, 10, 20), bandUSD(3, 20, 30)} // 9 > 5
	_, err := tbac.ValidateBandDivision(small, 0, 30, bands)
	if !errors.Is(err, tbac.ErrSubbandOverAllocates) {
		t.Fatalf("over-allocation must still be caught across both axes, got %v", err)
	}
}
