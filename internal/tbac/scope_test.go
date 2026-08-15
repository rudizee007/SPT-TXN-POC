package tbac_test

import (
	"encoding/json"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

func TestContains_EqualScope(t *testing.T) {
	parent := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	child := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("equal scope should be contained: %v", err)
	}
}

func TestContains_Subset(t *testing.T) {
	parent := tbac.Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	// Child omits currency (more restrictive) and lowers the ceiling.
	child := tbac.Scope{"action": "payment", "max_amount": 5000}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("subset scope should be contained: %v", err)
	}
}

func TestContains_NumericOverCeiling(t *testing.T) {
	parent := tbac.Scope{"max_amount": 10000}
	child := tbac.Scope{"max_amount": 10001}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("child exceeding numeric ceiling must be rejected")
	}
}

func TestContains_DimensionNotInParent(t *testing.T) {
	parent := tbac.Scope{"action": "payment"}
	child := tbac.Scope{"action": "payment", "refund": true}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("child requesting a dimension absent from parent must be rejected")
	}
}

func TestContains_StringMismatch(t *testing.T) {
	parent := tbac.Scope{"currency": "USD"}
	child := tbac.Scope{"currency": "EUR"}
	if err := tbac.Contains(parent, child); err == nil {
		t.Error("disjoint string value must be rejected")
	}
}

func TestContains_ListSubset(t *testing.T) {
	parent := tbac.Scope{"methods": []any{"ach", "wire", "card"}}
	ok := tbac.Scope{"methods": []any{"ach", "wire"}}
	if err := tbac.Contains(parent, ok); err != nil {
		t.Errorf("list subset should be contained: %v", err)
	}
	bad := tbac.Scope{"methods": []any{"ach", "crypto"}}
	if err := tbac.Contains(parent, bad); err == nil {
		t.Error("list with an element absent from parent must be rejected")
	}
}

// TestContains_JSONRoundtrip ensures containment holds after a token round-trips
// through JSON (all numbers become float64), which is how parent scope arrives
// at the downstream issuer.
func TestContains_JSONRoundtrip(t *testing.T) {
	original := tbac.Scope{"max_amount": 10000, "currency": "USD"}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var parent tbac.Scope
	if err := json.Unmarshal(b, &parent); err != nil {
		t.Fatal(err)
	}
	child := tbac.Scope{"max_amount": 7500, "currency": "USD"}
	if err := tbac.Contains(parent, child); err != nil {
		t.Errorf("containment must survive JSON roundtrip: %v", err)
	}
}

// TestContains_LargeAmountPrecision: 2^53 and 2^53+1 are indistinguishable as
// float64; the exact big.Rat comparison must still reject the over-by-one value.
func TestContains_LargeAmountPrecision(t *testing.T) {
	parent := tbac.Scope{"max_amount": json.Number("9007199254740992")}    // 2^53
	overByOne := tbac.Scope{"max_amount": json.Number("9007199254740993")} // 2^53 + 1
	if err := tbac.Contains(parent, overByOne); err == nil {
		t.Error("amount exceeding the ceiling by 1 (beyond float64 precision) must be rejected")
	}
	exact := tbac.Scope{"max_amount": json.Number("9007199254740992")}
	if err := tbac.Contains(parent, exact); err != nil {
		t.Errorf("an equal large amount must be contained: %v", err)
	}
}

func TestAttenuate_ReturnsIndependentCopy(t *testing.T) {
	parent := tbac.Scope{"max_amount": 10000}
	req := tbac.Scope{"max_amount": 5000}
	out, err := tbac.Attenuate(parent, req)
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	out["max_amount"] = 999999 // mutate the returned copy
	if v, _ := req["max_amount"].(int); v != 5000 {
		t.Error("Attenuate must return an independent copy, not alias the request")
	}
}

// ---- Numeric direction: the sandwich bypass -------------------------------
//
// These tests exist because "child <= parent" was applied to every numeric
// dimension by name-agnostic default. That is right for a ceiling and exactly
// backwards for a floor, and nothing in the package said which a dimension was.

func TestUndeclaredNumericDimensionIsRefused(t *testing.T) {
	// `min_out` is the shape a swap needs: the least the agent will accept.
	// Under the old rule a SMALLER child passed containment, which is a grant
	// of MORE authority — permission to accept a worse rate. The dimension is
	// undeclared, so both entry points must refuse it outright.
	parent := tbac.Scope{"action": "swap", "min_out": 1000}
	child := tbac.Scope{"action": "swap", "min_out": 1}

	if err := tbac.Contains(parent, child); err == nil {
		t.Fatal("SECURITY: an undeclared numeric dimension was accepted as contained; " +
			"a lower floor is wider authority, not narrower")
	}
	if _, err := tbac.Intersect(parent, child); err == nil {
		t.Fatal("SECURITY: Intersect issued a token over an undeclared numeric dimension")
	}

	// And it is refused in the direction that would have LOOKED like a
	// violation too — the point is that the direction is unknown, so neither
	// answer is available, not that one of them is wrong.
	if err := tbac.Contains(parent, tbac.Scope{"action": "swap", "min_out": 5000}); err == nil {
		t.Fatal("SECURITY: undeclared numeric accepted when the child was larger")
	}
}

func TestUndeclaredNumericIsRefusedWhenNested(t *testing.T) {
	// Containment recurses per dimension, so the guard has to hold at depth.
	// A nested floor is the easiest place for one to be introduced unnoticed.
	parent := tbac.Scope{"route": map[string]any{"min_out": 1000}}
	child := tbac.Scope{"route": map[string]any{"min_out": 1}}
	if err := tbac.Contains(parent, child); err == nil {
		t.Fatal("SECURITY: nested undeclared numeric dimension was accepted")
	}
}

func TestDeclaredCeilingStillNarrowsDownward(t *testing.T) {
	// The guard must not break the case it is protecting: max_amount is
	// declared, so less is still narrower and more is still a violation.
	parent := tbac.Scope{"max_amount": 10000}
	if err := tbac.Contains(parent, tbac.Scope{"max_amount": 5000}); err != nil {
		t.Fatalf("a declared ceiling must still narrow downward: %v", err)
	}
	if err := tbac.Contains(parent, tbac.Scope{"max_amount": 10001}); err == nil {
		t.Fatal("a declared ceiling must still reject an increase")
	}
	// Clamping at issuance is unchanged.
	out, err := tbac.Intersect(parent, tbac.Scope{"max_amount": 999999})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if v, _ := out["max_amount"].(int); v != 10000 {
		t.Fatalf("request above the ceiling must clamp to 10000, got %v", out["max_amount"])
	}
}
