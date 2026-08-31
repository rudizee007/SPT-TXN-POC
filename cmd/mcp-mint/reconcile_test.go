package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The ceiling and the intent must describe the SAME payment.
//
// A minted token carries two independent statements about money: the
// TxnContext amount, which the CAT -> CT ceiling chain constrains and which
// nothing downstream executes, and the tool arguments, which ARE what executes
// and are bound byte-exact by the intent digest. Both were enforced. Neither
// was checked against the other, so a token whose chain bounded 3000 could
// carry arguments spending 99999999 -- and every control in the path would
// report success.
func TestReconcile(t *testing.T) {
	parse := func(t *testing.T, s string) map[string]any {
		t.Helper()
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatalf("fixture %s: %v", s, err)
		}
		return m
	}

	for _, c := range []struct {
		name, args, amount, currency string
		unpriced                     bool
		wantErr                      string // "" = must be accepted
	}{
		{name: "agreeing string amount", args: `{"amount":"3000","currency":"USD"}`,
			amount: "3000", currency: "USD"},
		{name: "agreeing numeric amount", args: `{"amount":3000,"currency":"USD"}`,
			amount: "3000", currency: "USD"},

		// THE DEFECT. Ceiling bounds 3000; the tool spends 99999999.
		{name: "the bypass: args exceed the bound amount", args: `{"amount":"99999999"}`,
			amount: "3000", currency: "USD", wantErr: "must be the same payment"},
		{name: "args below the bound amount is also a mismatch", args: `{"amount":"1"}`,
			amount: "3000", currency: "USD", wantErr: "must be the same payment"},

		// A ceiling in one currency does not bound a payment in another.
		{name: "currency mismatch", args: `{"amount":"3000","currency":"EUR"}`,
			amount: "3000", currency: "USD", wantErr: "does not bound a payment in another"},

		// No amount at all: the ceiling is decorative. Fail closed.
		{name: "unpriced refused by default", args: `{"to":"alice"}`,
			amount: "3000", currency: "USD", wantErr: "ceiling would bound a value"},
		{name: "unpriced allowed with the explicit flag", args: `{"to":"alice"}`,
			amount: "3000", currency: "USD", unpriced: true},

		// Strictness: a float literal is not the same literal as an integer.
		{name: "3000.0 is not 3000", args: `{"amount":3000.0}`,
			amount: "3000", currency: "USD", wantErr: "must be the same payment"},
		{name: "non-scalar amount refused", args: `{"amount":{"value":3000}}`,
			amount: "3000", currency: "USD", wantErr: "JSON string or number"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := reconcile(parse(t, c.args), c.amount, c.currency, c.unpriced)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("MINTED: ceiling %s %s alongside args %s -- the chain bounds a "+
					"number the tool never spends", c.amount, c.currency, c.args)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("refused, but for the wrong reason.\n got: %v\nwant substring: %q",
					err, c.wantErr)
			}
		})
	}
}
