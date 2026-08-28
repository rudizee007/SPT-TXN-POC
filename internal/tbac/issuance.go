package tbac

import (
	"errors"
	"fmt"
)

// The three ways a scope can fail issuance. They are separate sentinels because
// they are separate diagnoses: one says the unit is missing, one says the unit
// is not a unit, one says the ceiling is not a number. A caller — or a test —
// that cannot tell them apart cannot tell whether the branch it thinks it is
// exercising is the branch that fired.
var (
	// ErrCeilingUnqualified: a monetary ceiling with no currency beside it.
	ErrCeilingUnqualified = errors.New("monetary ceiling has no currency alongside it")
	// ErrCurrencyNotAString: a currency that does not pin a unit.
	ErrCurrencyNotAString = errors.New("currency qualifying a monetary ceiling must be a non-empty string")
	// ErrCeilingNotNumeric: a monetary dimension whose value is not a number.
	ErrCeilingNotNumeric = errors.New("monetary ceiling is not a number")
	// ErrCeilingNegative: a monetary ceiling below zero. It is not a bound —
	// "-1 <= 5000" is true, so the containment algebra reads it as a NARROWING —
	// and it converts to the maximum uint64 on the ZK public-input path on amd64.
	//
	// Zero is deliberately NOT an error. A ceiling of zero authorizes nothing,
	// which makes it the maximally-narrow grant and a legitimate way to delegate
	// "no spend authority": every positive amount is refused against it, and the
	// grammar admits no non-positive amount to compare. Refusing zero would
	// remove an expressive, safe delegation without closing any hole — the
	// project's own attenuation property test generates it as a legitimate
	// narrowing, and it was right to.
	ErrCeilingNegative = errors.New("monetary ceiling must not be negative")
	// ErrUndeclaredNumeric: a numeric dimension with no declared direction.
	ErrUndeclaredNumeric = errors.New("numeric scope dimension has no declared direction")
	// ErrNoUnitToInherit: neither the child nor its parent pins a currency.
	ErrNoUnitToInherit = errors.New("no currency to inherit for a monetary ceiling")
)

// moneyCeilings names the numeric dimensions that bound a VALUE — an amount of
// money — rather than a count, a depth, or a privilege level. A value is only a
// bound together with the unit it is denominated in, so a scope that declares
// one of these MUST also declare the `currency` dimension that pins that unit.
//
// `max` (the generic nested bound inside a `limits` object) and `tier` are
// deliberately absent. `max` takes its unit from whatever object carries it, and
// `tier` is a privilege level, not an amount; neither is meaningless without a
// currency. Adding a name here is a security decision, not bookkeeping: ask
// whether the number means nothing until you know what it is denominated in. If
// so, it belongs here.
var moneyCeilings = map[string]bool{
	"max_amount": true,
	// A cumulative budget is denominated exactly as max_amount is: "100 across
	// the month" is 100 of WHICH unit? Unqualified, it would bound cumulative
	// spend in every currency at once. Same fix, same reason.
	"max_cumulative": true,
}

// ValidateIssuance reports whether a scope is safe to seal into a token.
//
// It enforces one invariant that containment cannot: a monetary ceiling is only
// a bound if the currency it is denominated in is pinned alongside it. TxnScope
// asserts `currency` only when the scope declares it, so a scope of
// {action: "payment", max_amount: 5000} bounds a transfer of 5000 in EVERY
// currency — 5000 JPY, 5000 BTC and 5000 ETH are each "within" it. The ceiling
// reads like a limit and is not one.
//
// The currency must be declared in the SAME object as the ceiling it qualifies.
// A currency one level up does not reach down into a nested limits object: the
// two would be free to drift apart, and a reader could not tell by looking at
// the object which unit its numbers are in.
//
// This is deliberately an ISSUANCE check rather than a containment rule.
// Contains and Intersect implement the draft's scope algebra and are shared with
// the verifier's enforcement path; changing their semantics is trust-boundary
// work that needs its own adversarial review. Refusing to mint the malformed
// ceiling closes the gap for every token issued from here on without touching
// enforcement.
//
// Known residual, stated rather than hidden: a token minted before this check
// existed, or by a non-conforming issuer, still verifies. Binding the ceiling to
// a currency at enforcement time is the second half of the fix.
//
// Issuers MUST call this before sealing a scope into a CAT or CT, and a service
// that loads a policy-permitted ceiling from configuration SHOULD call it at
// startup so a malformed ceiling fails the deploy rather than the first request.
func ValidateIssuance(s Scope) error {
	return validateIssuance(s, "")
}

func validateIssuance(s Scope, path string) error {
	// Money ceilings are validated in their OWN pass, before anything else, so the
	// diagnosis never depends on map-iteration order. A malformed currency (e.g. a
	// numeric one) must be reported as ErrCurrencyNotAString by the ceiling it
	// qualifies — not, when the generic numeric sweep below happens to reach the
	// currency dimension first, as an "undeclared numeric dimension". Two runs over
	// the same scope must give the same error.
	for dim, v := range s {
		if !moneyCeilings[dim] {
			continue
		}
		// The monetary check also precedes the nested-object recursion: a
		// max_amount whose value is an object is a malformed ceiling, not a
		// sub-scope to descend into, and must be diagnosed as one.
		if err := validateMoneyCeiling(s, qualify(path, dim), v, path); err != nil {
			return err
		}
	}
	for dim, v := range s {
		if moneyCeilings[dim] {
			continue // validated in the first pass
		}
		name := qualify(path, dim)
		if nested, ok := asObject(v); ok {
			if err := validateIssuance(nested, name); err != nil {
				return err
			}
			continue
		}
		// A numeric dimension with no declared direction cannot be evaluated by
		// Contains or Intersect at all, so a scope carrying one is unusable. The
		// startup check in the issuers exists so a ceiling like that fails the
		// DEPLOY; without this it would pass startup and fail on the first
		// delegation that happened to name the dimension.
		if _, isNum := toRat(v); isNum {
			if _, declaredDir := directionOf(dim); !declaredDir {
				return fmt.Errorf("scope dimension %q: %w — %s", name, ErrUndeclaredNumeric,
					"declare it in tbac.numericDirection only if a SMALLER value grants strictly LESS authority")
			}
		}
	}
	return nil
}
func validateMoneyCeiling(s Scope, name string, v any, path string) error {
	r, ok := toRat(v)
	if !ok {
		return fmt.Errorf("scope dimension %q: %w (value is %T)", name, ErrCeilingNotNumeric, v)
	}
	// A negative ceiling is not a bound at all: "-1 <= 5000" is true, so Contains
	// reads it as a narrowing, and it converts to the MAXIMUM uint64 on the ZK
	// public-input path on amd64. Zero is fine — see ErrCeilingNegative.
	if r.Sign() < 0 {
		return fmt.Errorf("scope dimension %q: %w (value is %v)", name, ErrCeilingNegative, v)
	}
	cur, declared := s["currency"]
	if !declared {
		return fmt.Errorf(
			"scope dimension %q: %w — it would bound the amount in every currency at once "+
				"(5000 USD, 5000 JPY and 5000 BTC would all be within it). Declare %q, the unit "+
				"the ceiling is denominated in",
			name, ErrCeilingUnqualified, qualify(path, "currency"))
	}
	cs, ok := cur.(string)
	if !ok || cs == "" {
		return fmt.Errorf("scope dimension %q qualifies %q: %w, got %#v",
			qualify(path, "currency"), name, ErrCurrencyNotAString, cur)
	}
	return nil
}

// asObject reports whether v is a nested scope object, in either of the two
// shapes this package sees: a Go literal or a JSON-decoded map.
func asObject(v any) (Scope, bool) {
	switch t := v.(type) {
	case Scope:
		return t, true
	case map[string]any:
		return Scope(t), true
	}
	return nil, false
}

// qualify renders a dimension name with its object path, so an error about a
// nested bound names `limits.max_amount` rather than `max_amount`.
func qualify(path, dim string) string {
	if path == "" {
		return dim
	}
	return path + "." + dim
}

// InheritMoneyUnit returns a copy of child in which every monetary ceiling the
// child declares is qualified by a currency: the child's own where it declared
// one, otherwise the parent's.
//
// Containment permits a child to drop a dimension its parent declared, and for
// `currency` that is a normal, legitimate narrowing request — a delegating agent
// asks for a lower amount and says nothing about the unit. Dropping it, though,
// leaves a token whose sealed ceiling reads as a bound in every currency at
// once. The verifier re-inherits the parent's currency through its root-to-leaf
// intersection, so ENFORCEMENT is already safe; what is not safe is the TOKEN,
// which an auditor, a second implementation, or any consumer that reads the leaf
// scope on its own would read as unbounded.
//
// Inheriting is a strict narrowing. It adds an equality constraint the child did
// not previously assert, and the value comes from the parent, so
// Contains(parent, result) still holds afterwards. It can never widen.
//
// It fails when neither the child nor the parent qualifies a monetary ceiling:
// there is nothing to inherit, and the ceiling cannot be made meaningful.
// Issuers should call this before ValidateIssuance on a delegated scope. Root
// issuance has no parent to inherit from — Intersect already carries every
// permitted dimension into the root scope, so a root that reaches
// ValidateIssuance without a currency has a malformed policy ceiling, and
// failing the issuance is the correct outcome.
func InheritMoneyUnit(parent, child Scope) (Scope, error) {
	return inheritMoneyUnit(parent, child, "")
}

func inheritMoneyUnit(parent, child Scope, path string) (Scope, error) {
	out := make(Scope, len(child)+1)
	for k, v := range child {
		out[k] = v
	}
	needsUnit := false
	for dim, v := range child {
		if nested, ok := asObject(v); ok {
			pn, _ := asObject(parent[dim])
			fixed, err := inheritMoneyUnit(pn, nested, qualify(path, dim))
			if err != nil {
				return nil, err
			}
			// Compare by CONTENT, not by key count. A fix applied two levels
			// down leaves the intermediate level's key count unchanged, so a
			// length test would drop it and blame the child for a ceiling the
			// inheritance had already qualified.
			if scopesEqual(fixed, nested) {
				continue // nothing was inherited; leave the value exactly as it came in
			}
			// Write the result back in the SAME concrete type it arrived as.
			// Contains and Intersect type-assert nested objects to
			// map[string]any, so handing them a tbac.Scope would read as a type
			// mismatch and reject a legitimate attenuation.
			if _, wasScope := v.(Scope); wasScope {
				out[dim] = fixed
			} else {
				out[dim] = map[string]any(fixed)
			}
			continue
		}
		if moneyCeilings[dim] {
			needsUnit = true
		}
	}
	if !needsUnit {
		return out, nil
	}
	if _, declared := out["currency"]; declared {
		return out, nil
	}
	inherited, ok := parent["currency"]
	if !ok {
		return nil, fmt.Errorf("scope declares a monetary ceiling at %q: %w — the ceiling would "+
			"bound the amount in every currency", qualify(path, "max_amount"), ErrNoUnitToInherit)
	}
	out["currency"] = inherited
	return out, nil
}

// scopesEqual reports whether two scope objects are the same all the way down.
// Used to tell "the inheritance changed nothing" from "the inheritance changed
// something at a depth where the key count happens to match".
func scopesEqual(a, b Scope) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, present := b[k]
		if !present {
			return false
		}
		an, aIsObj := asObject(av)
		bn, bIsObj := asObject(bv)
		if aIsObj != bIsObj {
			return false
		}
		if aIsObj {
			if !scopesEqual(an, bn) {
				return false
			}
			continue
		}
		if !equalValue(av, bv) {
			return false
		}
	}
	return true
}
