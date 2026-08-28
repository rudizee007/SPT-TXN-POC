package tbac

import (
	"errors"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

func txn(amount, currency string) ledger.TxnContext {
	return ledger.TxnContext{
		Chain: "none", Originator: "alice", Beneficiary: "bob",
		Amount: amount, Currency: currency, Timestamp: 1750000000,
	}
}

// A capability that declares an amount ceiling and no currency cannot be
// projected: TxnScope would assert the amount and NOT the unit, so the ceiling
// would bound a transfer of that size in every currency at once. Issuance
// refuses to seal such a scope, but enforcement must not be the layer that
// trusts issuance got it right — a token from a non-conforming issuer, or one
// minted before that check existed, still arrives here.
func TestTxnScope_RefusesAnUnqualifiedCeiling(t *testing.T) {
	for name, parent := range map[string]Scope{
		"bare ceiling":       {"max_amount": 5000},
		"ceiling and action": {"action": "payment", "max_amount": 5000},
		"json-decoded":       mustJSON(t, `{"action":"payment","max_amount":5000}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := TxnScope(parent, txn("100", "USD"))
			if err == nil {
				t.Fatal("an unqualified ceiling was projected")
			}
			if !errors.Is(err, ErrCeilingUnqualified) {
				t.Errorf("wrong diagnosis: want ErrCeilingUnqualified, got: %v", err)
			}
		})
	}
}

// The guard must not over-deny. A capability that declares no ceiling has
// nothing to qualify, and one that qualifies its ceiling projects normally.
func TestTxnScope_ProjectsQualifiedAndCeilinglessScopes(t *testing.T) {
	t.Run("qualified ceiling", func(t *testing.T) {
		got, err := TxnScope(Scope{"max_amount": 5000, "currency": "USD"}, txn("100", "USD"))
		if err != nil {
			t.Fatalf("a qualified ceiling must project: %v", err)
		}
		if got["max_amount"] != anyNumber("100") || got["currency"] != "USD" {
			t.Fatalf("wrong projection: %v", got)
		}
	})
	t.Run("no ceiling at all", func(t *testing.T) {
		got, err := TxnScope(Scope{"action": "payment"}, txn("100", "USD"))
		if err != nil {
			t.Fatalf("a scope with no ceiling must project: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("nothing should be asserted: %v", got)
		}
	})
	t.Run("currency only", func(t *testing.T) {
		got, err := TxnScope(Scope{"currency": "USD"}, txn("100", "USD"))
		if err != nil {
			t.Fatalf("a currency-only scope must project: %v", err)
		}
		if got["currency"] != "USD" {
			t.Fatalf("currency not asserted: %v", got)
		}
		if _, present := got["max_amount"]; present {
			t.Fatalf("an amount was asserted against a scope with no ceiling: %v", got)
		}
	})
}

// The scope layer is the layer that claims to bound the amount, so it is the
// layer that must refuse a non-positive one. "-5000 <= 5000" is true; before
// this guard the ceiling comparison passed and something else denied.
func TestTxnScope_RefusesNonPositiveAmounts(t *testing.T) {
	parent := Scope{"max_amount": 5000, "currency": "USD"}
	for _, amount := range []string{"0", "0.0", "-0", "-1", "-5000", "-0.0001"} {
		t.Run(amount, func(t *testing.T) {
			if _, err := TxnScope(parent, txn(amount, "USD")); err == nil {
				t.Fatalf("a non-positive amount %q was projected", amount)
			}
		})
	}
}

// The amount is compared as a number and hashed as a literal string, so a
// grammar wider than a decimal string lets the authorizer and the executor
// disagree about the number authorized while agreeing on the hash.
func TestTxnScope_RefusesNonCanonicalAmounts(t *testing.T) {
	parent := Scope{"max_amount": 5000, "currency": "USD"}
	for _, amount := range []string{"0x2710", "1/3", "1e3", "+100", "007", " 100", "100 ", "1_0", "NaN", "１００"} {
		t.Run(amount, func(t *testing.T) {
			_, err := TxnScope(parent, txn(amount, "USD"))
			if err == nil {
				t.Fatalf("a non-canonical amount %q was projected", amount)
			}
			if !errors.Is(err, ledger.ErrAmountGrammar) {
				t.Errorf("wrong diagnosis: want ErrAmountGrammar, got: %v", err)
			}
		})
	}
}

// The property that matters: a transaction can only clear a ceiling if its
// amount is a positive canonical decimal that is genuinely no greater than the
// ceiling. Nothing that clears may be negative, zero, ambiguous, or larger.
func TestProperty_ClearingACeilingRequiresAPositiveCanonicalAmountWithinIt(t *testing.T) {
	parent := Scope{"max_amount": 1000, "currency": "USD"}
	amounts := []string{
		// Should clear.
		"1", "999", "1000", "0.5", "999.999", "1000.00",
		// Should not: over the ceiling.
		"1001", "1000.01", "99999",
		// Should not: non-positive.
		"0", "0.0", "-1", "-1000", "-0",
		// Should not: non-canonical.
		"0x2710", "1/3", "1e2", "+1", "007", "1 ", " 1", "1,0", "١", "",
	}
	cleared, refused := 0, 0
	for _, a := range amounts {
		projected, err := TxnScope(parent, txn(a, "USD"))
		if err != nil {
			refused++
			continue
		}
		if err := Contains(parent, projected); err != nil {
			refused++
			continue
		}
		cleared++
		// Everything that cleared must satisfy all three conditions.
		r, perr := ledger.ParseAmount(a)
		if perr != nil {
			t.Fatalf("%q cleared the ceiling but is not a valid amount: %v", a, perr)
		}
		if r.Sign() <= 0 {
			t.Fatalf("%q cleared the ceiling and is not positive", a)
		}
		ceiling, _ := ledger.ParseAmount("1000")
		if r.Cmp(ceiling) > 0 {
			t.Fatalf("%q cleared a ceiling of 1000", a)
		}
	}
	t.Logf("denominator: %d cleared and %d refused amounts exercised", cleared, refused)
	if cleared == 0 || refused == 0 {
		t.Fatal("the table did not exercise both outcomes; the test proves nothing")
	}
}

// anyNumber renders the value TxnScope carries for an amount, so the assertion
// above does not depend on the concrete numeric type it chose.
func anyNumber(s string) any {
	got, _ := TxnScope(Scope{"max_amount": 1, "currency": "X"}, txn(s, "X"))
	return got["max_amount"]
}
