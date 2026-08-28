package verifier_test

import (
	"context"
	"testing"
)

// These pin verifier.VerifyForSettlement (review #6 A1, the design-true fix):
// a settler derives the ceiling and anchor from the SIGNED tokens, not a JSON
// summary. The harness (build) is the same one the eight-step tests use.

// TestVerifyForSettlement_ReturnsSignedFacts: on a valid chain the settle path
// ALLOWs and returns the anchor and ceiling that live inside the tokens — the
// facts a settler must use instead of trusting a document's fields.
func TestVerifyForSettlement_ReturnsSignedFacts(t *testing.T) {
	h := build(t)
	facts, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if !d.Allow {
		t.Fatalf("valid chain denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
	if facts.HumanAnchor == "" {
		t.Fatal("no humanAnchor returned — a settler cannot record accountability")
	}
	if facts.MaxAmount != "8000" {
		t.Fatalf("ceiling from the signed leaf CT = %q, want 8000", facts.MaxAmount)
	}
	if facts.Currency != "USD" {
		t.Fatalf("currency = %q, want USD", facts.Currency)
	}
	// The anchor is the CAT's, carried through the SPT-Txn token.
	if facts.HumanAnchor != h.cat.HumanAnchor.String() {
		t.Fatalf("anchor %q is not the CAT's %q", facts.HumanAnchor, h.cat.HumanAnchor.String())
	}
}

// TestVerifyForSettlement_AgreesWithFullVerifyOnAGoodChain: the settle path is
// the eight-step minus DPoP, so a chain the full verifier ALLOWs the settle
// path must also ALLOW (it checks a strict subset).
func TestVerifyForSettlement_AgreesWithFullVerify(t *testing.T) {
	h := build(t)
	if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
		t.Fatalf("full verify denied a good chain: %v", d)
	}
	if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); !d.Allow {
		t.Fatalf("settle path denied a chain the full verify allowed: %v", d)
	}
}

// TestVerifyForSettlement_NeedsNoDPoP: the settle path must not depend on the
// proof-of-possession the settler cannot produce. Stripping the DPoP proof
// (which fails the FULL verify at step 5) must NOT change the settle verdict.
func TestVerifyForSettlement_NeedsNoDPoP(t *testing.T) {
	h := build(t)
	h.in.DPoPProof = "" // a settler has no holder key and no proof

	if d := h.eng.Verify(context.Background(), h.in); d.Allow || d.Step != 5 {
		t.Fatalf("expected the FULL verify to fail at step 5 without a DPoP proof, got %v", d)
	}
	facts, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if !d.Allow {
		t.Fatalf("the settle path required a DPoP proof it should not need: step %d %s", d.Step, d.Reason)
	}
	if facts.MaxAmount != "8000" {
		t.Fatalf("ceiling = %q, want 8000", facts.MaxAmount)
	}
}

// TestVerifyForSettlement_RefusesAForgedContext: the whole point is that the
// settler's INDEPENDENTLY-derived transaction must match what the signed TXN
// token binds. Change the transaction the settler claims, and step 8 refuses —
// so a forger who edits the payment cannot get signed facts for it.
func TestVerifyForSettlement_RefusesAForgedContext(t *testing.T) {
	h := build(t)
	h.in.Txn.Amount = "999999" // the settler asserts a different payment
	_, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if d.Allow {
		t.Fatal("the settle path accepted a transaction the signed token does not bind")
	}
	if d.Step != 7 && d.Step != 8 {
		t.Fatalf("expected refusal at scope(7) or context(8), got step %d (%s)", d.Step, d.StepName)
	}
}

// TestVerifyForSettlement_RefusesAForgedSignature: a tampered TXN token fails at
// step 1, so the facts a settler would read are never returned from an
// unsigned or re-signed token.
func TestVerifyForSettlement_RefusesAForgedSignature(t *testing.T) {
	h := build(t)
	h.in.TxnToken = h.in.TxnToken[:len(h.in.TxnToken)-4] + "AAAA" // corrupt the signature
	_, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if d.Allow {
		t.Fatal("the settle path accepted a token with a broken signature")
	}
	if d.Step != 1 {
		t.Fatalf("expected refusal at signature(1), got step %d (%s)", d.Step, d.StepName)
	}
}

// TestVerifyForSettlement_RefusesAForgedBeneficiary is fix-review finding 4:
// the merchant is defended only by step 8 covering Beneficiary in the context
// hash, and no settle-path test forged it. A forged merchant is "pay the
// attacker", so this pins that changing the beneficiary the settler claims —
// while the signed token binds the real one — is refused.
func TestVerifyForSettlement_RefusesAForgedBeneficiary(t *testing.T) {
	h := build(t)
	h.in.Txn.Beneficiary = "rObFnAmj4Tw6aQNiWQMxSHkxCXxwQdXECp" // a different, valid XRPL address
	_, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if d.Allow {
		t.Fatal("a payment to a beneficiary the signed token does not name was accepted — forged merchant")
	}
	if d.Step != 8 {
		t.Fatalf("expected refusal at context(8), got step %d (%s)", d.Step, d.StepName)
	}
}

// TestVerifyForSettlement_RefusesAForgedOriginator: same, for the payer.
func TestVerifyForSettlement_RefusesAForgedOriginator(t *testing.T) {
	h := build(t)
	h.in.Txn.Originator = "rObFnAmj4Tw6aQNiWQMxSHkxCXxwQdXECp"
	_, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if d.Allow {
		t.Fatal("a payment from an originator the signed token does not name was accepted")
	}
	if d.Step != 8 {
		t.Fatalf("expected refusal at context(8), got step %d (%s)", d.Step, d.StepName)
	}
}
