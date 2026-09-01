package tbac

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
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
// The sum bound is what makes the division sound: the total authority handed
// out is provably <= what the parent held, so there is no (N+1)th slice and
// structuring across the slices gains nothing. This function proves
// the division and nothing else. Two further things are needed before the sum
// bound is a spending bound, and both live in the verifier, not here: every
// child of a budgeted parent must be a member slice (step 6 refuses an ordinary
// child, which would otherwise inherit the whole budget uncounted), and each
// slice is consumed on its first ALLOW per enforcement point (keyed on the
// committed root and leg, so a re-minted copy is the same slice). No verifier
// holds a running total; each holds a set of consumed slices. Binding a slice
// to a time window (a $3 day-band inside a $100 month) is layered on top. See
// VELOCITY-AND-CUMULATIVE-SPEND-DESIGN §3a and §7.
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

// Band is one slice of a pre-divided budget across both axes: the scope carrying
// its max_cumulative portion (and currency), and the time window it is live in,
// [NotBefore, Expiry) as Unix seconds -- the nbf and exp the slice's CT will
// carry.
type Band struct {
	Scope     Scope
	NotBefore int64
	Expiry    int64
}

var (
	// ErrBandWindowEmpty: a band (or the parent) opens at or after it closes.
	ErrBandWindowEmpty = errors.New("band window is empty (NotBefore is not before Expiry)")
	// ErrBandWindowOutsideParent: a band's window is not contained in the parent's.
	ErrBandWindowOutsideParent = errors.New("band window falls outside the parent window")
	// ErrBandWindowsOverlap: two bands are live at once, so their caps would stack.
	ErrBandWindowsOverlap = errors.New("band windows overlap (two bands live at once)")
)

// ValidateBandDivision checks that bands is a sound pre-division of a parent
// budget across BOTH axes at once -- amount and time -- the stateless issuance
// guard for a windowed sub-band schedule (a $3 day inside a $100 month).
//
// Amount: it runs ValidateSubbandDivision on the bands' scopes, so the slices'
// max_cumulative values sum to <= the parent budget (see there for the full set
// of amount checks: currency-qualified, contained, non-empty, exact big.Rat).
//
// Time: the parent's own window [parentNbf, parentExp) must be non-empty; then
// every band's window must be non-empty, sit INSIDE the parent's, and the bands'
// windows must be pairwise NON-OVERLAPPING. Non-overlap is the property that
// makes "$3 today, not $6" hold: at most one band is ever live, so the per-window
// cap cannot be doubled by two bands active at the same instant. Adjacent windows
// that meet at a point (one's Expiry == the next's NotBefore) do not overlap -- a
// back-to-back schedule is sound.
//
// The exact total amount allocated is returned, as ValidateSubbandDivision does;
// it is meaningful only when err is nil.
func ValidateBandDivision(parent Scope, parentNbf, parentExp int64, bands []Band) (*big.Rat, error) {
	// Amount axis first, reusing the single source of truth for the sum bound.
	scopes := make([]Scope, len(bands))
	for i, b := range bands {
		scopes[i] = b.Scope
	}
	total, err := ValidateSubbandDivision(parent, scopes)
	if err != nil {
		return nil, err
	}

	// Time axis. The parent must hold a real window to divide.
	if parentNbf >= parentExp {
		return nil, fmt.Errorf("parent [%d,%d): %w", parentNbf, parentExp, ErrBandWindowEmpty)
	}
	for i, b := range bands {
		if b.NotBefore >= b.Expiry {
			return nil, fmt.Errorf("band %d [%d,%d): %w", i, b.NotBefore, b.Expiry, ErrBandWindowEmpty)
		}
		if b.NotBefore < parentNbf || b.Expiry > parentExp {
			return nil, fmt.Errorf("band %d [%d,%d) not inside parent [%d,%d): %w",
				i, b.NotBefore, b.Expiry, parentNbf, parentExp, ErrBandWindowOutsideParent)
		}
	}

	// Pairwise non-overlap, checked in sorted order (O(n log n), not O(n^2)) so the
	// error can name the adjacent offenders. Sort a COPY of the indices; the
	// caller's slice order is theirs to keep.
	order := make([]int, len(bands))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		return bands[order[a]].NotBefore < bands[order[b]].NotBefore
	})
	for k := 1; k < len(order); k++ {
		prev := bands[order[k-1]]
		cur := bands[order[k]]
		if cur.NotBefore < prev.Expiry {
			return nil, fmt.Errorf("bands %d [%d,%d) and %d [%d,%d): %w",
				order[k-1], prev.NotBefore, prev.Expiry, order[k], cur.NotBefore, cur.Expiry, ErrBandWindowsOverlap)
		}
	}
	return total, nil
}
