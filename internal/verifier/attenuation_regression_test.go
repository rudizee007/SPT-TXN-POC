package verifier_test

// Regression test for the attenuation bypass found in adversarial review
// (docs/THREAT-MODEL.md §4.2): a delegated CT that DROPS a ceiling/equality
// dimension leaves that axis unconstrained at transaction time unless the
// verifier enforces the chain INTERSECTION rather than the leaf scope alone.
//
// Each case builds human -> agent A (max_amount 8000) -> sub-agent B, where B
// drops a dimension, then presents an out-of-bounds transaction. The verifier
// MUST deny at step 7 (scope), because the effective ceiling is inherited from
// an ancestor the leaf tried to shed.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

func (a *agenticChain) delegateB(t *testing.T, scope tbac.Scope) *cttoken.CT {
	t.Helper()
	ct, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issCTA, ParentCT: a.ctA.Token, ParentIssuerKey: keyOf(t, a.reg, issCT),
		RequestedScope:  scope,
		HolderPublicKey: a.agentBPub,
	}, a.ctaPriv)
	if err != nil {
		t.Fatalf("delegate CT_B with scope %v: %v", scope, err)
	}
	return ct
}

// TestAttenuation_DroppedCeilingCannotWiden: CT_B drops max_amount entirely.
// The transaction (1,000,000) is far above the inherited 8000 ceiling and MUST
// be denied — dropping the dimension is not attenuation.
func TestAttenuation_DroppedCeilingCannotWiden(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"currency": "USD"}) // max_amount dropped

	tc := paymentTxn("1000000")
	txn, proof := a.txnFor(t, ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if d.Allow {
		t.Fatal("BYPASS: dropped-ceiling leaf allowed an over-limit transaction")
	}
	if d.Step != 7 {
		t.Fatalf("expected deny at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

// TestAttenuation_DroppedCeilingStillHonoursInheritedLimit: same dropped-ceiling
// leaf, but a transaction WITHIN the inherited 8000 ceiling must still be
// allowed — the fix must not over-deny legitimate traffic.
func TestAttenuation_DroppedCeilingStillHonoursInheritedLimit(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"currency": "USD"})

	tc := paymentTxn("6000") // ≤ inherited 8000
	txn, proof := a.txnFor(t, ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if !d.Allow {
		t.Fatalf("in-bounds transaction under inherited ceiling denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

// TestAttenuation_DroppedCurrencyIsRefusedBeforeATokenCanBeMinted: CT_B keeps a
// (higher) amount ceiling but drops currency. An unqualified ceiling bounds the
// amount in EVERY currency, so nothing may be minted against it.
//
// This test used to assert a step-7 DENY on an off-currency transaction: the
// leaf's dropped currency was re-inherited by the verifier's root-to-leaf
// intersection, so a EUR transfer failed the equality check. That defence still
// exists and is covered by TestAttenuation_DroppedCeilingStillHonoursInheritedLimit
// and by the tbac projection tests. What changed is that the refusal now happens
// EARLIER and unconditionally: tbac.TxnScope refuses to project a capability that
// declares max_amount with no currency, so txntoken.Issue cannot mint against
// such a leaf at all — for any currency, not only a mismatched one.
//
// A conforming issuer no longer emits this leaf either (cttoken carries the
// parent's unit down), so it is forged here: mint legitimately, then re-sign with
// the currency stripped. Note the limit of what this can reach — the leaf's exact
// bytes are bound into the SPT-Txn token, so a chain whose ROOT is also
// unqualified cannot be assembled without a full forged-chain builder. That case
// is covered at the tbac layer (TestTxnScope_RefusesAnUnqualifiedCeiling) and a
// verifier-level version of it is owed.
func TestAttenuation_DroppedCurrencyIsRefusedBeforeATokenCanBeMinted(t *testing.T) {
	a := buildAgentic(t)
	ctB := a.delegateB(t, tbac.Scope{"max_amount": 5000, "currency": "USD"})
	claims := decodeClaims(t, ctB.Token)
	scope, ok := claims["capability_scope"].(map[string]any)
	if !ok {
		t.Fatalf("leaf CT has no capability_scope: %v", claims)
	}
	delete(scope, "currency")
	ctBToken := forgeToken(claims, a.ctaPriv)

	for _, currency := range []string{"EUR", "USD"} {
		t.Run(currency, func(t *testing.T) {
			tc := ledger.TxnContext{
				Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
				Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
				Amount:      "1000", Currency: currency, Timestamp: 1750000000,
				Extra: map[string]string{"DestinationTag": "42"},
			}
			_, err := txntoken.Issue(txntoken.IssueRequest{
				Issuer: issTTS, Audience: aud, ParentCT: ctBToken, ParentIssuerKey: a.ctaPub,
				HolderPublicKey: a.agentBPub, Ledger: a.l, Txn: tc,
			}, a.ttsPriv)
			if err == nil {
				t.Fatal("BYPASS: an SPT-Txn was minted against a capability whose ceiling names no currency")
			}
			if !errors.Is(err, tbac.ErrCeilingUnqualified) {
				t.Errorf("wrong diagnosis: want ErrCeilingUnqualified, got: %v", err)
			}
		})
	}
}

// TestAttenuation_DroppedCurrencyDeniedAtStep7 restores the VERIFIER-level
// assertion that TestAttenuation_DroppedCurrencyIsRefusedBeforeATokenCanBeMinted
// gave up when the refusal moved to issuance time: a leaf that drops an equality
// dimension must RE-INHERIT it from its ancestors during the root-to-leaf
// intersection, even when every issuance-time check has been bypassed.
//
// The first version of this test was VACUOUS, and the mutation harness caught it
// (scripts/mutate-review8-fixes.sh, M-6). It forged a leaf carrying
// {max_amount: 5000} with currency deleted. That denies at step 7 -- but under
// the mutation it ALSO denies at step 7, for a completely different reason: a
// max_amount with no currency beside it is an unqualified ceiling, and
// tbac.TxnScope refuses to project one at all (scope.go:311, ErrCeilingUnqualified).
// The assertion could not tell the two apart, so it passed whether the control it
// named was present or not. That is exactly the flaw review 8 found in
// nonconforming_issuer_test.go, reproduced by the person who reported it.
//
// The fix is to leave NO ceiling in the forged leaf, so the unqualified-ceiling
// guard has nothing to fire on and currency inheritance is the only thing that
// can refuse the transaction:
//
//	CAT   {action: payment, max_amount: 10000, currency: USD}
//	CT_A  {max_amount: 8000, currency: USD}
//	CT_B  {}                                   <- forged: sheds everything
//	txn   1000 EUR                             <- within any inherited ceiling
//
// With the overlay intact, CT_B re-inherits currency=USD and the EUR transfer is
// denied at step 7. With the overlay broken, the effective scope is the leaf's
// own {action: payment}, nothing projects from the transaction context, and the
// transfer is ALLOWED -- which is the bypass, and which fails this test.
func TestAttenuation_DroppedCurrencyDeniedAtStep7(t *testing.T) {
	a := buildAgentic(t)

	f := newForgedChain(t, a).mutate(1, func(claims map[string]any) {
		if _, ok := claims["capability_scope"].(map[string]any); !ok {
			t.Fatalf("leaf CT has no capability_scope: %v", claims)
		}
		// Shed EVERYTHING. Two guards stand in front of the property under test
		// and each rules out an obvious alternative:
		//
		//   {max_amount: N}      -> tbac.TxnScope refuses an unqualified ceiling
		//                           (scope.go:311), denying at step 7 for the
		//                           wrong reason -- the first vacuous attempt.
		//   {action: "payment"}  -> step 6 compares the hop against its IMMEDIATE
		//                           parent's DECLARED scope, and CT_A declares
		//                           only {max_amount, currency}; "action" comes
		//                           from the CAT, so the hop is refused at step 6
		//                           as unheld authority -- the second attempt.
		//
		// An empty scope passes step 6 (tbac.Contains iterates the CHILD's
		// dimensions, so an empty child asserts nothing) and leaves no ceiling for
		// the unqualified guard to fire on. Inherited currency is then the only
		// thing that can refuse a 1000 EUR transfer.
		claims["capability_scope"] = map[string]any{}
	})

	tc := paymentTxn("1000") // comfortably inside the inherited 8000
	tc.Currency = "EUR"      // the inherited constraint is USD

	txn, proof := f.txnFor(tc)
	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: f.chain(), CAT: f.cat,
		Txn: tc, Audience: aud,
	})
	if d.Allow {
		t.Fatal("BYPASS: a leaf that shed currency allowed an off-currency transaction")
	}
	if d.Step != 7 {
		t.Fatalf("expected deny at step 7 (scope), got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
	// And it must be the INHERITED CURRENCY that refused it, not the
	// unqualified-ceiling guard standing in front of the property under test.
	if strings.Contains(d.Reason, "ErrCeilingUnqualified") ||
		strings.Contains(d.Reason, "no \"currency\"") ||
		strings.Contains(d.Reason, "monetary ceiling has no currency") {
		t.Fatalf("denied by the unqualified-ceiling guard, not by currency inheritance -- "+
			"this test is not exercising the property it names: %s", d.Reason)
	}
}
