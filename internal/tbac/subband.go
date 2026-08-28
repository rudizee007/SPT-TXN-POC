package tbac

import (
	"errors"
	"fmt"
	"math/big"
)

// cumulativeDim is the scope dimension carrying a CUMULATIVE spending budget: the
// total a holder may spend across MANY transactions, as distinct from max_amount,
// which bounds a SINGLE transaction. It is registered as a ceiling in
// numericDirection (scope.go) and as a money ceiling in moneyCeilings
// (issuance.go), so it inherits the same fail-closed treatment as max_amount:
// currency-qualified, non-negative, attenuated by interval subset.
const cumulativeDim = "max_cumulative"

var (
	// ErrSubbandNoParentBudget: the parent declares no cumulative budget, so there
	// is nothing to divide. A per-transaction ceiling (max_amount) is NOT a
	// cumulative budget; sub-banding a scope that only bounds single transactions
	// is meaningless and is refused rather than treated as an unbounded total.
	ErrSubbandNoParentBudget = errors.New("parent declares no max_cumulative budget to divide")

	// ErrSubbandNotABand: a slice carries no max_cumulative, so it is not a
	// sub-band of the budget. Every slice in a division MUST name the portion of
	// the budget it claims; a slice without one is an unbounded child on the
	// cumulative axis and would defeat the division.
	ErrSubbandNotABand = errors.New("sub-band slice declares no max_cumulative")

	// ErrSubbandEmpty: a division into zero slices. Almost always a caller bug, so
	// it is refused loudly rather than silently succeeding as a grant of nothing —
	// the house rule is that malformed input is loud.
	ErrSubbandEmpty = errors.New("sub-band division has no slices")

	// ErrSubbandOverAllocates: the slices' budgets sum to MORE than the parent's
	// cumulative budget. This is the over-issuance the division exists to prevent.
	// The per-slice containment check alone does NOT catch it: each slice can be
	// individually within the total while the SUM exceeds it (fifty $100 slices
	// are each "<= $100" yet total $5,000). Only the sum bound closes that.
	ErrSubbandOverAllocates = errors.New("sub-band slices over-allocate the parent budget")
)

// ValidateSubbandDivision checks that slices is a sound pre-division of parent's
// cumulative budget. It is the stateless heart of the sub-band velocity control:
// it needs no shared counter and no state, because it proves the division at
// issuance time rather than summing spend at enforcement time.
//
// It enforces, in order:
//
//   - parent is a well-formed scope (ValidateIssuance) AND declares a
//     max_cumulative budget (else ErrSubbandNoParentBudget). ValidateIssuance
//     also guarantees the budget is currency-qualified and non-negative — a
//     parent budget that bounds "100 in every currency at once" is refused here.
//   - the division is non-empty (else ErrSubbandEmpty);
//   - every slice is a well-formed scope (ValidateIssuance): its max_cumulative
//     is numeric, non-negative and currency-qualified — an unqualified band is
//     refused here, not at spend time;
//   - every slice actually declares max_cumulative (else ErrSubbandNotABand);
//   - every slice is contained in parent (Contains): same currency, and no
//     dimension it declares — including its own max_cumulative — exceeds the
//     parent. A single band larger than the whole budget, or in another currency,
//     is caught here, before the sum;
//   - the slices' max_cumulative values SUM to <= parent's max_cumulative (else
//     ErrSubbandOverAllocates). The bound is <=, not <: a division may hold budget
//     in reserve (sum < budget); it may never allocate more than it was granted.
//
// The sum bound is the property that makes the division sound. Once the total
// authority handed out is provably <= what the parent held, N single-use slices
// bound cumulative spend BY CONSTRUCTION — there is no (N+1)th slice to spend, so
// structuring across the slices buys the attacker nothing, and no verifier ever
// needs to hold a running total. This function proves the division; enforcing
// that each slice is redeemed at most once is the separate single-use concern
// (max_uses / replay), and binding a slice to a time window (a $3 day-band inside
// a $100 month) is layered on top. See VELOCITY-AND-CUMULATIVE-SPEND-DESIGN
// §3a and §7.
//
// It deliberately does NOT deduplicate slices: two identical slices are two
// distinct claims on the budget and are counted twice, which is exactly right for
// the sum bound (their uniqueness for single-use is enforced elsewhere, by nonce,
// not here). All arithmetic is exact big.Rat, so a division that is correct to the
// smallest unit is not silently accepted-or-rejected by float rounding at large
// values (e.g. XRP drops above 2^53).
//
// The exact total actually allocated is returned for the caller's records; it is
// meaningful only when err is nil.
func ValidateSubbandDivision(parent Scope, slices []Scope) (*big.Rat, error) {
	// The parent must be a well-formed scope AND actually hold a cumulative
	// budget. ValidateIssuance refuses a budget that is unqualified, negative or
	// non-numeric, so the checks below can assume a clean parent ceiling.
	if err := ValidateIssuance(parent); err != nil {
		return nil, fmt.Errorf("parent scope: %w", err)
	}
	pv, ok := parent[cumulativeDim]
	if !ok {
		return nil, ErrSubbandNoParentBudget
	}
	budget, ok := toRat(pv)
	if !ok {
		// Unreachable after ValidateIssuance (which requires a numeric ceiling for
		// a money dimension) and kept so a future loosening of issuance fails
		// closed here rather than summing against a non-number.
		return nil, fmt.Errorf("%s: %w", cumulativeDim, ErrCeilingNotNumeric)
	}
	if len(slices) == 0 {
		return nil, ErrSubbandEmpty
	}

	sum := new(big.Rat)
	for i, slice := range slices {
		if err := ValidateIssuance(slice); err != nil {
			return nil, fmt.Errorf("sub-band %d: %w", i, err)
		}
		sv, ok := slice[cumulativeDim]
		if !ok {
			return nil, fmt.Errorf("sub-band %d: %w", i, ErrSubbandNotABand)
		}
		// Per-hop containment: same currency, and this slice's own budget does not
		// exceed the parent total. This catches a single over-large or
		// wrong-currency band before it reaches the sum.
		if err := Contains(parent, slice); err != nil {
			return nil, fmt.Errorf("sub-band %d not contained in parent: %w", i, err)
		}
		sr, ok := toRat(sv)
		if !ok {
			return nil, fmt.Errorf("sub-band %d: %s: %w", i, cumulativeDim, ErrCeilingNotNumeric)
		}
		sum.Add(sum, sr)
	}

	if sum.Cmp(budget) > 0 {
		return nil, fmt.Errorf("%w: slices total %s, parent budget %s",
			ErrSubbandOverAllocates, sum.RatString(), budget.RatString())
	}
	return sum, nil
}
