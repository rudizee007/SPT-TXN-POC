// Package tbac implements the Token-Bound Access Control scope logic for the
// SPT-Txn POC. M3 uses the scope-containment check defined here to attenuate a
// parent Compliance Attestation Token's scope into a narrower Capability Token
// scope, per Section 3.4 (Scope Invariants) of
// draft-coetzee-oauth-spt-txn-tokens.
//
// POC scope model
//
// A Scope is a set of named dimensions (map[string]any), matching the
// capability_scope claim produced by internal/cattoken. Containment is
// evaluated per dimension with deterministic, documented semantics:
//
//   - number  child MUST be <= parent   (numeric dimensions are ceilings,
//                                         e.g. max_amount, delegation limits)
//   - string  child MUST equal parent   (e.g. currency=USD, action=transfer)
//   - bool    child MUST equal parent
//   - list    child set MUST be a subset of parent set
//   - object  child MUST be contained recursively
//
// A dimension present in the parent but absent in the child is permitted: the
// child simply does not request that dimension and is therefore more
// restrictive. A dimension present in the child but absent in the parent is a
// violation: the child cannot grant authority the parent never held.
//
// Cedar policy interop (the richer production model) is a v2 task; the
// interface below is what the v2 swap must preserve.
package tbac

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

// Scope is a set of capability dimensions. Values are produced either from Go
// literals (ints, strings, []any) or from JSON decoding (float64 for all
// numbers), so the containment logic normalises numeric types.
type Scope map[string]any

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
		if err := valueContained(pv, cv); err != nil {
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
		// Carry the amount as json.Number (the exact decimal string) so the
		// containment check compares it with big.Rat precision, not lossy
		// float64 — important for large values like XRP drops (> 2^53).
		if _, valid := new(big.Rat).SetString(tc.Amount); !valid {
			return nil, fmt.Errorf("transaction amount %q is not numeric", tc.Amount)
		}
		out["max_amount"] = json.Number(tc.Amount)
	}
	if _, ok := parent["currency"]; ok {
		out["currency"] = tc.Currency
	}
	return out, nil
}

func valueContained(parent, child any) error {
	// Numbers: child must not exceed parent (exact big.Rat comparison).
	if pr, pok := toRat(parent); pok {
		cr, cok := toRat(child)
		if !cok {
			return fmt.Errorf("type mismatch: parent is numeric, child is %T", child)
		}
		if cr.Cmp(pr) > 0 {
			return fmt.Errorf("value %s exceeds parent ceiling %s", cr.RatString(), pr.RatString())
		}
		return nil
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
