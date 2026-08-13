package verifier

// White-box tests. Everything else in this package is `package verifier_test`
// and goes through Verify, which is the right default: a test that can only be
// written against internals is usually testing the wrong thing.
//
// This file exists for one case where that default fails. checkTxnLifetime's
// fail-closed branches are UNREACHABLE through Verify — step2Expiry already
// requires the SPT-Txn's exp to be a float, and cttoken.Verify already requires
// the leaf CT's — so an end-to-end test of them passes because something else
// denied first, not because the branch fired.
//
// That is exactly what happened: the first version of this coverage was an
// end-to-end test asserting only that the request was denied. It survived a
// mutation that made the branches fail open, because step 2 denied the request
// anyway. It looked like coverage and was worth nothing.

import "testing"

func TestCheckTxnLifetime(t *testing.T) {
	f := func(v int64) map[string]any { return map[string]any{"exp": float64(v)} }

	t.Run("attenuating and equal lifetimes pass", func(t *testing.T) {
		for _, c := range []struct{ tx, leaf int64 }{{100, 200}, {200, 200}, {0, 1}} {
			if err := checkTxnLifetime(f(c.tx), f(c.leaf)); err != nil {
				t.Errorf("txExp %d, leafExp %d: %v", c.tx, c.leaf, err)
			}
		}
	})

	t.Run("outliving the leaf is rejected", func(t *testing.T) {
		// One second over is the case that matters. An off-by-one here is the
		// difference between an invariant and a suggestion.
		if err := checkTxnLifetime(f(201), f(200)); err == nil {
			t.Fatal("a token outliving its capability by one second was accepted")
		}
	})

	t.Run("an unusable exp fails closed on either side", func(t *testing.T) {
		good := f(100)
		for name, bad := range map[string]map[string]any{
			"absent":  {},
			"string":  {"exp": "200"},
			"bool":    {"exp": true},
			"null":    {"exp": nil},
			"nested":  {"exp": map[string]any{"v": 200.0}},
			"array":   {"exp": []any{200.0}},
			"integer": {"exp": 200}, // not float64: JSON decodes numbers as float64
		} {
			if err := checkTxnLifetime(bad, good); err == nil {
				t.Errorf("txn exp %s: accepted a lifetime that cannot be computed", name)
			}
			if err := checkTxnLifetime(good, bad); err == nil {
				t.Errorf("leaf exp %s: accepted a lifetime that cannot be computed", name)
			}
		}
	})
}
