package verifier_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// CONTROL. A forged chain that changes nothing must still verify. Without this,
// every denial below could be an artefact of the builder rather than the guard
// under test, and the whole file would prove nothing.
func TestForgedChain_UnmodifiedChainStillVerifies(t *testing.T) {
	a := buildAgentic(t)
	f := newForgedChain(t, a)

	tc := paymentTxn("100")
	txn, proof := f.txnFor(tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: f.chain(), CAT: f.cat, Txn: tc, Audience: aud,
	})
	if !d.Allow {
		t.Fatalf("the builder itself breaks a valid chain — denied at step %d (%s): %s. "+
			"Every denial in this file is meaningless until this passes.", d.Step, d.StepName, d.Reason)
	}
}

// The owed test. A conforming issuer cannot mint a chain whose ROOT declares a
// monetary ceiling with no currency — cattoken refuses it. A non-conforming one
// can, and enforcement must not be the layer that trusts issuance got it right.
//
// The effective scope the verifier computes is the root-to-leaf intersection,
// and its key set is exactly the root CAT's, so an unqualified ceiling at the
// root is an unqualified ceiling at enforcement time. It must be refused at step
// 7, for EVERY currency — not merely denied for a mismatched one.
func TestNonConformingIssuer_UnqualifiedCeilingAtTheRootIsRefused(t *testing.T) {
	for _, currency := range []string{"USD", "EUR", "XRP"} {
		t.Run(currency, func(t *testing.T) {
			a := buildAgentic(t)
			f := newForgedChain(t, a)

			// Strip the currency from every level, so the intersection carries a
			// ceiling and no unit — the shape no conforming issuer can produce.
			strip := func(claims map[string]any) {
				if scope, ok := claims["capability_scope"].(map[string]any); ok {
					delete(scope, "currency")
				}
			}
			f.mutate(-1, strip).mutate(0, strip).mutate(1, strip)

			tc := paymentTxn("100")
			tc.Currency = currency
			txn, proof := f.txnFor(tc)

			d := a.eng.Verify(context.Background(), verifier.Input{
				TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
				CTChain: f.chain(), CAT: f.cat, Txn: tc, Audience: aud,
			})
			if d.Allow {
				t.Fatal("BYPASS: a ceiling that names no currency bounded a transaction")
			}
			if d.Step != 7 {
				t.Fatalf("expected the refusal at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
			}
			if !strings.Contains(d.Reason, tbac.ErrCeilingUnqualified.Error()) {
				t.Errorf("wrong diagnosis at step 7: %s", d.Reason)
			}
		})
	}
}

// The same for a non-positive ceiling. "-1 <= 100" is true, so a negative
// ceiling reads as a narrowing to the containment algebra; nothing but an
// explicit sign check refuses it, and a conforming issuer can no longer mint one
// to test that check with.
func TestNonConformingIssuer_NonPositiveCeilingIsRefused(t *testing.T) {
	for name, ceiling := range map[string]any{
		"negative": float64(-1),
		"zero":     float64(0),
	} {
		t.Run(name, func(t *testing.T) {
			a := buildAgentic(t)
			f := newForgedChain(t, a)

			set := func(claims map[string]any) {
				if scope, ok := claims["capability_scope"].(map[string]any); ok {
					scope["max_amount"] = ceiling
				}
			}
			f.mutate(-1, set).mutate(0, set).mutate(1, set)

			tc := paymentTxn("100")
			txn, proof := f.txnFor(tc)

			d := a.eng.Verify(context.Background(), verifier.Input{
				TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
				CTChain: f.chain(), CAT: f.cat, Txn: tc, Audience: aud,
			})
			if d.Allow {
				t.Fatalf("BYPASS: a %s ceiling authorized a transaction of 100", name)
			}
		})
	}
}

// A non-canonical amount cannot be minted by txntoken any more, so the
// enforcement-side check on it had no end-to-end coverage either. Bind a forged
// SPT-Txn to a transaction whose amount is outside the grammar and require step
// 7 to refuse it — not step 8, which would mean the layer that claims to bound
// the amount is not the layer doing it.
func TestNonConformingIssuer_NonCanonicalAmountIsRefusedAtTheScopeStep(t *testing.T) {
	for _, amount := range []string{"0x2710", "1e2", "+100", "007", "-100", "0"} {
		t.Run(amount, func(t *testing.T) {
			a := buildAgentic(t)
			f := newForgedChain(t, a)

			tc := paymentTxn(amount)
			txn, proof := f.txnFor(tc)

			d := a.eng.Verify(context.Background(), verifier.Input{
				TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
				CTChain: f.chain(), CAT: f.cat, Txn: tc, Audience: aud,
			})
			if d.Allow {
				t.Fatalf("BYPASS: amount %q cleared the ceiling", amount)
			}
			if d.Step != 7 {
				t.Fatalf("expected the refusal at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
			}
			_ = errors.Is // keep the import honest if the assertions above change
		})
	}
}
