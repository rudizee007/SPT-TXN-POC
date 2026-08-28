package tbac

import (
	"encoding/json"
	"errors"
	"testing"
)

// A monetary ceiling with no currency alongside it is not a bound. These are the
// scopes an issuer must refuse to seal.
func TestValidateIssuance_MoneyCeilingRequiresCurrency(t *testing.T) {
	cases := map[string]Scope{
		"bare ceiling":              {"max_amount": 5000},
		"ceiling with action only":  {"action": "payment", "max_amount": 5000},
		"json-decoded ceiling":      mustJSON(t, `{"action":"payment","max_amount":5000}`),
		"currency in a sibling obj": {"max_amount": 5000, "limits": Scope{"currency": "USD"}},
		"nested ceiling, currency one level up": {
			"currency": "USD",
			"limits":   Scope{"max_amount": 5000},
		},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateIssuance(s)
			if err == nil {
				t.Fatal("a monetary ceiling with no currency beside it was accepted for issuance")
			}
			// The diagnosis must be "the unit is missing", not some other branch
			// that happens to also reject this input. Otherwise the branch under
			// test could be deleted with this test still green.
			if !errors.Is(err, ErrCeilingUnqualified) {
				t.Errorf("wrong diagnosis: want ErrCeilingUnqualified, got: %v", err)
			}
		})
	}
}

func TestValidateIssuance_AcceptsCurrencyBoundCeilings(t *testing.T) {
	cases := map[string]Scope{
		"flat":            {"action": "payment", "max_amount": 5000, "currency": "USD"},
		"json-decoded":    mustJSON(t, `{"action":"payment","max_amount":5000,"currency":"USD"}`),
		"json.Number":     {"max_amount": json.Number("18446744073709551616"), "currency": "XRP"},
		"nested, matched": {"limits": Scope{"max_amount": 5000, "currency": "USD"}},
		"nested map[string]any": {
			"limits": map[string]any{"max_amount": 5000, "currency": "EUR"},
		},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIssuance(s); err != nil {
				t.Fatalf("a currency-bound ceiling must be issuable: %v", err)
			}
		})
	}
}

// Dimensions that are not amounts of money do not acquire a currency
// requirement. Registering one of these as monetary would be over-reach that
// blocks legitimate issuance.
func TestValidateIssuance_NonMonetaryDimensionsNeedNoCurrency(t *testing.T) {
	cases := map[string]Scope{
		"privilege tier": {"tier": 2},
		"generic bound":  {"limits": Scope{"max": 3}},
		"no numerics":    {"action": "payment", "region": "EU"},
		"empty":          {},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIssuance(s); err != nil {
				t.Fatalf("non-monetary scope must be issuable: %v", err)
			}
		})
	}
}

// The currency that qualifies a ceiling must actually pin a unit.
func TestValidateIssuance_CurrencyMustBeANonEmptyString(t *testing.T) {
	cases := map[string]Scope{
		"empty string": {"max_amount": 5000, "currency": ""},
		"numeric":      {"max_amount": 5000, "currency": 840},
		"null":         mustJSON(t, `{"max_amount":5000,"currency":null}`),
		"list":         {"max_amount": 5000, "currency": []any{"USD", "EUR"}},
		"bool":         {"max_amount": 5000, "currency": true},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateIssuance(s)
			if err == nil {
				t.Fatal("a ceiling qualified by a non-string currency was accepted")
			}
			if !errors.Is(err, ErrCurrencyNotAString) {
				t.Errorf("wrong diagnosis: want ErrCurrencyNotAString, got: %v", err)
			}
		})
	}
}

// A monetary dimension whose value is not a number is malformed, not a ceiling.
func TestValidateIssuance_MonetaryCeilingMustBeNumeric(t *testing.T) {
	for name, v := range map[string]any{
		"string": "5000",
		"bool":   true,
		"list":   []any{5000},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateIssuance(Scope{"max_amount": v, "currency": "USD"})
			if err == nil {
				t.Fatalf("a non-numeric %q max_amount was accepted", name)
			}
			if !errors.Is(err, ErrCeilingNotNumeric) {
				t.Errorf("wrong diagnosis: want ErrCeilingNotNumeric, got: %v", err)
			}
		})
	}
}

// The check must survive the round trip a scope actually takes: Go literal ->
// JSON -> map[string]any, where every number becomes a float64.
func TestValidateIssuance_SurvivesJSONRoundTrip(t *testing.T) {
	original := Scope{"action": "payment", "max_amount": 5000, "currency": "USD"}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Scope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := ValidateIssuance(back); err != nil {
		t.Fatalf("round-tripped scope must still validate: %v", err)
	}
	delete(back, "currency")
	if err := ValidateIssuance(back); err == nil {
		t.Fatal("dropping currency from a round-tripped scope must be refused")
	}
}

// Intersect can carry a ceiling down from the permitted scope; whatever it
// produces must still be issuable, or the issuer has a check it cannot satisfy.
func TestValidateIssuance_AcceptsWhatIntersectProduces(t *testing.T) {
	permitted := Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	for name, requested := range map[string]Scope{
		"empty request":    {},
		"narrowed ceiling": {"max_amount": 500},
		"same currency":    {"max_amount": 500, "currency": "USD"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Intersect(permitted, requested)
			if err != nil {
				t.Fatalf("Intersect: %v", err)
			}
			if err := ValidateIssuance(got); err != nil {
				t.Fatalf("Intersect produced a scope the issuer refuses: %v", err)
			}
		})
	}
}

func mustJSON(t *testing.T, s string) Scope {
	t.Helper()
	var out Scope
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("test fixture is not JSON: %v", err)
	}
	return out
}

// InheritMoneyUnit carries the parent's unit down to a child that narrowed only
// the amount. That is the normal delegation shape and must keep working.
func TestInheritMoneyUnit_CarriesTheParentsUnitDown(t *testing.T) {
	parent := Scope{"action": "payment", "max_amount": 10000, "currency": "USD"}
	got, err := InheritMoneyUnit(parent, Scope{"max_amount": 5000})
	if err != nil {
		t.Fatalf("narrowing only the amount must remain legitimate: %v", err)
	}
	if got["currency"] != "USD" {
		t.Fatalf("unit not inherited: %v", got)
	}
	if got["max_amount"] != 5000 {
		t.Fatalf("requested ceiling lost: %v", got)
	}
	if err := ValidateIssuance(got); err != nil {
		t.Fatalf("the result must be issuable: %v", err)
	}
	// Inheriting is a NARROWING: the value came from the parent, so the result
	// must still be contained in it.
	if err := Contains(parent, got); err != nil {
		t.Fatalf("inheriting widened the scope: %v", err)
	}
}

// A unit the child asked for is never overwritten by the parent's.
func TestInheritMoneyUnit_DoesNotOverrideTheChildsOwnUnit(t *testing.T) {
	parent := Scope{"max_amount": 10000, "currency": "USD"}
	got, err := InheritMoneyUnit(parent, Scope{"max_amount": 500, "currency": "EUR"})
	if err != nil {
		t.Fatalf("InheritMoneyUnit: %v", err)
	}
	if got["currency"] != "EUR" {
		t.Fatalf("the child's own currency was overwritten: %v", got)
	}
}

// When neither side pins a unit there is nothing to inherit. Failing here is the
// point: the alternative is sealing a ceiling that bounds every currency.
func TestInheritMoneyUnit_FailsWhenThereIsNoUnitAnywhere(t *testing.T) {
	_, err := InheritMoneyUnit(Scope{"action": "payment", "max_amount": 10000}, Scope{"max_amount": 500})
	if err == nil {
		t.Fatal("an unqualified ceiling was accepted with no unit to inherit")
	}
	if !errors.Is(err, ErrNoUnitToInherit) {
		t.Errorf("wrong diagnosis: want ErrNoUnitToInherit, got: %v", err)
	}
}

// A child with no monetary ceiling acquires nothing — inheriting a currency it
// has no use for would add a constraint the delegator never asked about.
func TestInheritMoneyUnit_AddsNothingWithoutACeiling(t *testing.T) {
	parent := Scope{"max_amount": 10000, "currency": "USD", "action": "payment"}
	got, err := InheritMoneyUnit(parent, Scope{"action": "payment"})
	if err != nil {
		t.Fatalf("InheritMoneyUnit: %v", err)
	}
	if _, present := got["currency"]; present {
		t.Fatalf("a unit was added to a scope with no ceiling: %v", got)
	}
}

// Nested objects must come back in the shape the containment algebra expects.
// Contains and Intersect type-assert nested values to map[string]any, so
// returning a tbac.Scope there reads as a type mismatch and rejects a legitimate
// attenuation.
func TestInheritMoneyUnit_PreservesNestedObjectType(t *testing.T) {
	parent := Scope{"region": map[string]any{"tier": 3}, "max_amount": 10000, "currency": "USD"}
	got, err := InheritMoneyUnit(parent, Scope{"region": map[string]any{"tier": 3}, "max_amount": 500})
	if err != nil {
		t.Fatalf("InheritMoneyUnit: %v", err)
	}
	if _, ok := got["region"].(map[string]any); !ok {
		t.Fatalf("nested object came back as %T, which Contains will reject", got["region"])
	}
	if err := Contains(parent, got); err != nil {
		t.Fatalf("result is not contained in the parent: %v", err)
	}
}

// Reviewer finding: a ceiling of zero authorizes nothing, and a NEGATIVE ceiling
// reads as a narrowing to Contains ("-1 <= 5000" is true) and converts to the
// MAXIMUM uint64 on the ZK public-input path on amd64. Neither may be sealed.
func TestValidateIssuance_RefusesNegativeCeilings(t *testing.T) {
	for name, v := range map[string]any{
		"negative":       -1,
		"negative float": -0.0001,
		"negative big":   json.Number("-18446744073709551616"),
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateIssuance(Scope{"max_amount": v, "currency": "USD"})
			if err == nil {
				t.Fatalf("a %s ceiling was accepted for issuance", name)
			}
			if !errors.Is(err, ErrCeilingNegative) {
				t.Errorf("wrong diagnosis: want ErrCeilingNegative, got: %v", err)
			}
		})
	}
}

// Reviewer finding: the recursion into nested objects ran BEFORE the monetary
// check, so a max_amount whose value is an object was descended into rather than
// diagnosed. It minted a token no transaction could ever satisfy.
func TestValidateIssuance_ObjectValuedCeilingIsDiagnosedNotRecursedPast(t *testing.T) {
	for name, v := range map[string]any{
		"object": map[string]any{"x": 1},
		"scope":  Scope{"x": 1},
		"list":   []any{1},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateIssuance(Scope{"max_amount": v, "currency": "USD"})
			if err == nil {
				t.Fatalf("an object-valued max_amount was accepted")
			}
			if !errors.Is(err, ErrCeilingNotNumeric) {
				t.Errorf("wrong diagnosis: want ErrCeilingNotNumeric, got: %v", err)
			}
		})
	}
}

// Reviewer finding: Intersect carries a permitted-only dimension through without
// consulting numericDirection, so a permitted ceiling naming an UNDECLARED
// numeric dimension passed startup validation and then failed Contains on the
// first delegation that named it. The startup check is supposed to fail the
// deploy; now it does.
func TestValidateIssuance_RefusesUndeclaredNumericDimensions(t *testing.T) {
	err := ValidateIssuance(Scope{"max_amount": 5000, "currency": "USD", "velocity": 10})
	if err == nil {
		t.Fatal("a scope with an undeclared numeric dimension was accepted")
	}
	if !errors.Is(err, ErrUndeclaredNumeric) {
		t.Errorf("wrong diagnosis: want ErrUndeclaredNumeric, got: %v", err)
	}

	// And the guarantee Intersect documents now actually holds for what an
	// issuer will accept: whatever Intersect returns from a validated ceiling is
	// contained in it.
	permitted := Scope{"max_amount": 5000, "currency": "USD", "tier": 3}
	if err := ValidateIssuance(permitted); err != nil {
		t.Fatalf("a ceiling using only declared numerics must validate: %v", err)
	}
	got, err := Intersect(permitted, Scope{"max_amount": 100})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if err := Contains(permitted, got); err != nil {
		t.Fatalf("Intersect broke its own containment guarantee: %v", err)
	}
}

// Reviewer finding: inheritMoneyUnit decided "nothing changed" by comparing key
// COUNTS, so a currency inherited two levels down was discarded — the
// intermediate object's key count was unchanged — and the delegation was then
// refused for a ceiling the inheritance had already qualified.
func TestInheritMoneyUnit_CarriesTheUnitDownThroughTwoLevels(t *testing.T) {
	parent := Scope{"a": map[string]any{"b": map[string]any{"max_amount": 10, "currency": "USD"}}}
	child := Scope{"a": map[string]any{"b": map[string]any{"max_amount": 5}}}

	got, err := InheritMoneyUnit(parent, child)
	if err != nil {
		t.Fatalf("a two-level narrowing must remain legitimate: %v", err)
	}
	a, ok := got["a"].(map[string]any)
	if !ok {
		t.Fatalf("level a came back as %T", got["a"])
	}
	b, ok := a["b"].(map[string]any)
	if !ok {
		t.Fatalf("level b came back as %T", a["b"])
	}
	if b["currency"] != "USD" {
		t.Fatalf("the unit was not carried two levels down: %v", b)
	}
	if err := ValidateIssuance(got); err != nil {
		t.Fatalf("the result must be issuable: %v", err)
	}
	if err := Contains(parent, got); err != nil {
		t.Fatalf("inheriting widened the scope: %v", err)
	}
}

// Zero is the maximally-narrow grant, not an error: it authorizes nothing, every
// positive amount is refused against it, and the attenuation property test
// generates it as a legitimate narrowing. Refusing it would remove an expressive,
// safe delegation without closing any hole.
func TestValidateIssuance_AcceptsAZeroCeilingAsTheNarrowestGrant(t *testing.T) {
	for name, v := range map[string]any{
		"zero int":    0,
		"zero float":  0.0,
		"zero number": json.Number("0"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIssuance(Scope{"max_amount": v, "currency": "USD"}); err != nil {
				t.Fatalf("a zero ceiling must be issuable: %v", err)
			}
		})
	}
}
