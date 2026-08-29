// Package tbac implements the Token-Bound Access Control scope logic for the
// SPT-Txn POC. M3 uses the scope-containment check defined here to attenuate a
// parent Compliance Attestation Token's scope into a narrower Capability Token
// scope, per Section 3.4 (Scope Invariants) of
// draft-coetzee-oauth-spt-txn-tokens.
//
// # POC scope model
//
// A Scope is a set of named dimensions (map[string]any), matching the
// capability_scope claim produced by internal/cattoken. Containment is
// evaluated per dimension with deterministic, documented semantics:
//
//   - number  child MUST be <= parent, but ONLY for dimensions declared as
//     ceilings in numericDirection. An undeclared numeric dimension is an
//     error, not a ceiling. See "Numeric direction" below.
//   - string  child MUST equal parent   (e.g. currency=USD, action=transfer)
//   - bool    child MUST equal parent
//   - list    child set MUST be a subset of parent set
//   - object  child MUST be contained recursively
//
// A dimension present in the child but absent in the parent is a violation:
// the child cannot grant authority the parent never held.
//
// A dimension present in the parent but absent in the child passes THIS
// per-hop containment check — but it is NOT thereby "more restrictive." Each
// dimension is a CONSTRAINT, and dropping a constraint widens authority on
// that axis at transaction time (TxnScope only asserts the dimensions the
// scope actually declares). Dropping is therefore neutralised at the
// enforcement point: the verifier (verifier.step6Chain) computes the
// INTERSECTION of every scope from the root CAT to the leaf and checks the
// transaction against that, so a dropped ceiling is inherited from the
// nearest ancestor that still declares it. See docs/THREAT-MODEL.md §4.2 and
// docs/spec/DELEGATION-INTENT-MCP.md §1.2. Do not rely on per-hop Contains
// alone to bound a transaction.
//
// # Numeric direction
//
// "Narrower" is not a property of a number. It is a property of the CONSTRAINT
// the number expresses. For a ceiling (max_amount) a smaller child is narrower.
// For a floor — a minimum acceptable output, the shape a swap needs — a smaller
// child is WIDER, and treating it as narrower authorizes an agent to accept an
// arbitrarily bad rate. That is the sandwich case, and it is a live
// authorization bypass, not a modelling nicety.
//
// This package therefore refuses to infer direction. Every numeric dimension
// must be declared in numericDirection; an undeclared one is an error at both
// the containment check and at issuance. The cost is that adding a numeric
// dimension takes one line in a registry. The alternative — a default — is what
// makes the bypass silent, because the wrong answer is produced by the code
// path nobody edited.
//
// Direction is deliberately NOT inferred from the name. A "min_"-prefix rule
// looks equivalent and is not: it is a guess that fails open for every name
// that does not match the pattern, and it puts the security property in a
// naming convention rather than in a declaration.
//
// Two-sided intervals (a declared floor, or a single interval-valued dimension)
// are a separate piece of work. This file only guarantees that their absence is
// loud: adding a floor today produces an error, where before it silently
// inverted the containment order.
//
// Cedar policy interop (the richer production model) is a v2 task; the
// interface below is what the v2 swap must preserve.
package tbac

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

// Scope is a set of capability dimensions. Values are produced either from Go
// literals (ints, strings, []any) or from JSON decoding (float64 for all
// numbers), so the containment logic normalises numeric types.
type Scope map[string]any

// direction records which way "narrower" runs for a numeric dimension.
type direction int

const (
	// dirCeiling: the value is an upper bound. A child MUST be <= its parent.
	dirCeiling direction = iota + 1
)

// numericDirection declares every numeric scope dimension this package will
// evaluate. There is NO default entry and there must never be one: an
// unrecognised numeric dimension has an unknown direction, and guessing is the
// bypass this registry exists to prevent.
//
// Nested dimensions are looked up by their own leaf name, because Contains and
// Intersect recurse per dimension — `region.tier` is registered as "tier".
//
// Adding an entry is a security decision, not bookkeeping. Ask: if a child
// declares a SMALLER value here, does the holder end up able to do less, or
// more? Only "less" is dirCeiling. If the answer is "more", the dimension is a
// floor and this package cannot yet express it — do not register it as a
// ceiling to make a test pass.
var numericDirection = map[string]direction{
	// The transaction amount ceiling. A child asking for less can spend less.
	"max_amount": dirCeiling,
	// Generic nested bound used by the `limits` object.
	"max": dirCeiling,
	// Privilege tier, where a lower tier grants strictly less.
	"tier": dirCeiling,
	// A cumulative spending budget: the total a holder may spend across MANY
	// transactions, as distinct from max_amount (one transaction). A child
	// asking for less can spend less, so it is a ceiling. Sub-band division
	// (subband.go) bounds a SET of children by the parent budget; this entry
	// makes a SINGLE child's max_cumulative attenuate by interval subset.
	"max_cumulative": dirCeiling,
}

// directionOf reports the declared direction for a numeric dimension.
func directionOf(dim string) (direction, bool) {
	d, ok := numericDirection[dim]
	return d, ok
}

// errUndeclaredNumeric is the shared fail-closed error for a numeric dimension
// with no declared direction. Phrased for whoever hits it at 3am: it says what
// to do and warns against the fix that reintroduces the bug.
func errUndeclaredNumeric(dim string) error {
	return fmt.Errorf(
		"numeric dimension %q has no declared direction — refusing to assume it is a ceiling. "+
			"Declare it in tbac.numericDirection only if a SMALLER value grants strictly LESS "+
			"authority. If a smaller value grants more (a floor, e.g. a minimum acceptable "+
			"output), this package cannot express it yet and registering it as a ceiling "+
			"would authorize accepting an arbitrarily bad one", dim)
}

// Contains reports whether child is fully contained within parent. It returns
// nil when child is a valid attenuation of parent, or a descriptive error
// naming the dimension that failed. The error text is suitable for the
// verifier's "which step/dimension decided" reporting (M5, Step 7).
func Contains(parent, child Scope) error {
	for dim, cv := range child {
		pv, ok := parent[dim]
		if !ok {
			return fmt.Errorf("scope dimension %q not present in parent (cannot grant unheld authority)", dim)
		}
		if err := valueContained(dim, pv, cv); err != nil {
			return fmt.Errorf("scope dimension %q: %w", dim, err)
		}
	}
	return nil
}

// Attenuate validates that request is contained in parent and, if so, returns
// request as the attenuated scope to embed in the child token. It is a thin
// wrapper over Contains that makes issuer call sites read clearly.
func Attenuate(parent, request Scope) (Scope, error) {
	if err := Contains(parent, request); err != nil {
		return nil, fmt.Errorf("attenuation rejected: %w", err)
	}
	// Return a copy so callers cannot mutate shared maps.
	out := make(Scope, len(request))
	for k, v := range request {
		out[k] = v
	}
	return out, nil
}

// Intersect computes the greatest-lower-bound scope for ROOT issuance: the
// authority granted by an issuer is bounded by BOTH the policy-permitted ceiling
// and the caller's requested scope. Unlike per-hop delegation, a root token has
// no ancestor to inherit a dropped ceiling from, so the result asserts EVERY
// dimension the permitted ceiling declares — a request cannot silently drop the
// `max_amount` ceiling and leave the root unbounded. For each dimension:
//
//   - present only in permitted: carried as-is (the request did not restrict it);
//   - present in both: narrowed to the greatest lower bound — numeric to the
//     lower of the two, string/bool to the common value (a mismatch is an
//     error), list to the set intersection, object recursively;
//   - present only in the request: rejected — a request cannot introduce
//     authority the policy ceiling does not grant.
//
// The result is guaranteed contained in permitted: Contains(permitted, result)
// is nil. A request that exceeds a numeric ceiling is clamped down (the ceiling
// is a bound, not an instruction); a request that conflicts on an equality
// dimension (e.g. currency USD vs EUR) is an error and issuance MUST fail.
func Intersect(permitted, requested Scope) (Scope, error) {
	out := make(Scope, len(permitted))
	for dim, pv := range permitted {
		rv, ok := requested[dim]
		if !ok {
			out[dim] = pv // request did not restrict this axis; carry the ceiling
			continue
		}
		gv, err := glb(dim, pv, rv)
		if err != nil {
			return nil, fmt.Errorf("scope dimension %q: %w", dim, err)
		}
		out[dim] = gv
	}
	for dim := range requested {
		if _, ok := permitted[dim]; !ok {
			return nil, fmt.Errorf("scope dimension %q not permitted by policy (cannot grant unheld authority)", dim)
		}
	}
	return out, nil
}

// glb returns the greatest lower bound of a permitted value and a requested
// value under the same containment order used by Contains.
func glb(dim string, permitted, requested any) (any, error) {
	// Numbers: for a ceiling the greatest lower bound is the LOWER of the two,
	// so a request above the ceiling is clamped down rather than honoured. That
	// is only correct for a declared ceiling — for a floor the glb is the higher
	// value, and applying the ceiling rule would issue a token weaker than the
	// policy permits in the one direction that matters. Fail closed instead.
	if pr, pok := toRat(permitted); pok {
		rr, rok := toRat(requested)
		if !rok {
			return nil, fmt.Errorf("type mismatch: permitted is numeric, requested is %T", requested)
		}
		d, ok := directionOf(dim)
		if !ok {
			return nil, errUndeclaredNumeric(dim)
		}
		switch d {
		case dirCeiling:
			if rr.Cmp(pr) <= 0 {
				return requested, nil
			}
			return permitted, nil
		default:
			return nil, errUndeclaredNumeric(dim)
		}
	}
	switch p := permitted.(type) {
	case string:
		r, ok := requested.(string)
		if !ok {
			return nil, fmt.Errorf("type mismatch: permitted is string, requested is %T", requested)
		}
		if r != p {
			return nil, fmt.Errorf("requested %q is not the permitted value %q", r, p)
		}
		return p, nil
	case bool:
		r, ok := requested.(bool)
		if !ok {
			return nil, fmt.Errorf("type mismatch: permitted is bool, requested is %T", requested)
		}
		if r != p {
			return nil, fmt.Errorf("requested %v is not the permitted value %v", r, p)
		}
		return p, nil
	case []any:
		r, ok := requested.([]any)
		if !ok {
			return nil, fmt.Errorf("type mismatch: permitted is list, requested is %T", requested)
		}
		return listIntersect(p, r), nil // elements in both; may be empty (maximally narrow)
	case map[string]any:
		r, ok := requested.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("type mismatch: permitted is object, requested is %T", requested)
		}
		sub, err := Intersect(Scope(p), Scope(r))
		if err != nil {
			return nil, err
		}
		return map[string]any(sub), nil
	default:
		if !reflect.DeepEqual(permitted, requested) {
			return nil, fmt.Errorf("requested %v is not the permitted value %v", requested, permitted)
		}
		return permitted, nil
	}
}

// listIntersect returns the elements present in BOTH lists (requested ∩
// permitted), preserving the request's order. An empty result is a valid,
// maximally-narrow grant (nothing on that axis is authorized).
func listIntersect(permitted, requested []any) []any {
	out := []any{}
	for _, r := range requested {
		for _, p := range permitted {
			if equalValue(p, r) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// TxnScope projects a concrete ledger transaction onto the scope dimensions a
// capability actually constrains, so containment is checked only where the
// capability speaks. POC mapping: Amount -> max_amount (numeric ceiling),
// Currency -> currency (equality). Dimensions the capability does not declare
// are not asserted by the transaction (more restrictive, allowed). Shared by
// the M4 issuer (txntoken) and the M5 verifier engine so both apply identical
// rules.
func TxnScope(parent Scope, tc ledger.TxnContext) (Scope, error) {
	out := Scope{}
	if _, ok := parent["max_amount"]; ok {
		// A ceiling with no unit beside it is not a ceiling: this function would
		// project the amount and NOT the currency, so the capability would bound
		// a transfer of that size in every currency at once. Issuance refuses to
		// seal such a scope (see ValidateIssuance), but a token minted before
		// that check existed, or by a non-conforming issuer, still reaches here —
		// and enforcement must not be the layer that trusts issuance got it
		// right. Refuse to project it.
		if _, qualified := parent["currency"]; !qualified {
			return nil, fmt.Errorf("capability declares %q but no %q: %w",
				"max_amount", "currency", ErrCeilingUnqualified)
		}
		// The amount is compared as a NUMBER here and hashed as a LITERAL STRING
		// into spt_txn_context_hash, so it must be canonical and positive before
		// either happens. ledger.ParseAmount is the single grammar; do not
		// re-derive one here (see its doc comment for why big.Rat alone is too
		// permissive — "0x2710" is 10000 to it, and "-5000 <= 5000" is true).
		if _, err := ledger.ParseAmount(tc.Amount); err != nil {
			return nil, fmt.Errorf("transaction amount: %w", err)
		}
		// Carry the amount as json.Number (the exact decimal string) so the
		// containment check compares it with big.Rat precision, not lossy
		// float64 — important for large values like XRP drops (> 2^53).
		out["max_amount"] = json.Number(tc.Amount)
	}
	// max_cumulative is a money ceiling too, and it must project or a token that
	// carries a cumulative budget but no max_amount would assert NOTHING here and
	// leave its transactions unbounded at spend time — a $3-cumulative slice
	// minting a $1000 transfer. Project it on the same terms as max_amount
	// (currency-qualified, positive, canonical, exact json.Number) so a single-use
	// slice is bounded by its own budget. The cumulative SUM across slices is
	// bounded by construction at ISSUANCE (ValidateSubbandDivision) plus
	// single-use, never by a running total here — this layer stays stateless. See
	// VELOCITY-AND-CUMULATIVE-SPEND-DESIGN §3a and subband.go.
	if _, ok := parent[cumulativeDim]; ok {
		if _, qualified := parent["currency"]; !qualified {
			return nil, fmt.Errorf("capability declares %q but no %q: %w",
				cumulativeDim, "currency", ErrCeilingUnqualified)
		}
		if _, err := ledger.ParseAmount(tc.Amount); err != nil {
			return nil, fmt.Errorf("transaction amount: %w", err)
		}
		out[cumulativeDim] = json.Number(tc.Amount)
	}
	if _, ok := parent["currency"]; ok {
		out["currency"] = tc.Currency
	}
	return out, nil
}

func valueContained(dim string, parent, child any) error {
	// Numbers: the comparison depends on the DECLARED direction of the
	// dimension, never on the number. An undeclared dimension fails closed
	// rather than defaulting to a ceiling.
	if pr, pok := toRat(parent); pok {
		cr, cok := toRat(child)
		if !cok {
			return fmt.Errorf("type mismatch: parent is numeric, child is %T", child)
		}
		d, ok := directionOf(dim)
		if !ok {
			return errUndeclaredNumeric(dim)
		}
		switch d {
		case dirCeiling:
			if cr.Cmp(pr) > 0 {
				return fmt.Errorf("value %s exceeds parent ceiling %s", cr.RatString(), pr.RatString())
			}
			return nil
		default:
			// Unreachable while dirCeiling is the only member, and deliberately
			// present: adding a direction without handling it here must fail
			// closed rather than fall through to "contained".
			return errUndeclaredNumeric(dim)
		}
	}

	switch p := parent.(type) {
	case string:
		c, ok := child.(string)
		if !ok || c != p {
			return fmt.Errorf("string %v does not equal parent %q", child, p)
		}
		return nil
	case bool:
		c, ok := child.(bool)
		if !ok || c != p {
			return fmt.Errorf("bool %v does not equal parent %v", child, p)
		}
		return nil
	case []any:
		c, ok := child.([]any)
		if !ok {
			return fmt.Errorf("type mismatch: parent is list, child is %T", child)
		}
		if !subset(c, p) {
			return fmt.Errorf("list %v is not a subset of parent %v", c, p)
		}
		return nil
	case map[string]any:
		c, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("type mismatch: parent is object, child is %T", child)
		}
		return Contains(Scope(p), Scope(c))
	default:
		// Fallback: require deep equality for unknown types.
		if !reflect.DeepEqual(parent, child) {
			return fmt.Errorf("value %v does not equal parent %v", child, parent)
		}
		return nil
	}
}

// subset reports whether every element of child appears in parent (by value
// equality, numbers normalised).
func subset(child, parent []any) bool {
	for _, c := range child {
		found := false
		for _, p := range parent {
			if equalValue(p, c) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func equalValue(a, b any) bool {
	if ar, aok := toRat(a); aok {
		if br, bok := toRat(b); bok {
			return ar.Cmp(br) == 0
		}
		return false
	}
	return reflect.DeepEqual(a, b)
}

// toRat normalises any Go numeric type (including JSON's float64 and
// json.Number) to an exact *big.Rat. It deliberately does NOT parse plain
// strings — those are compared by equality, not magnitude (e.g. currency
// codes). json.Number IS parsed, since that is how exact decimal amounts are
// carried through the scope.
func toRat(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case float64:
		r := new(big.Rat)
		if r.SetFloat64(n) == nil {
			return nil, false // NaN or Inf
		}
		return r, true
	case float32:
		r := new(big.Rat)
		if r.SetFloat64(float64(n)) == nil {
			return nil, false
		}
		return r, true
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int8:
		return new(big.Rat).SetInt64(int64(n)), true
	case int16:
		return new(big.Rat).SetInt64(int64(n)), true
	case int32:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	case uint:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint8:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint16:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint32:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint64:
		return new(big.Rat).SetUint64(n), true
	case json.Number:
		r, ok := new(big.Rat).SetString(n.String())
		return r, ok
	default:
		return nil, false
	}
}
