package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

// Shape-valid synthetic StrKey accounts (G + 55 base32 chars = 56). The adapter
// checks shape only (no CRC), so these exercise it without needing live keys.
const (
	stlA = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW"
	stlB = "G234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ"
)

func stellarAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("stellar")
	if err != nil {
		t.Fatalf("stellar adapter not registered: %v", err)
	}
	if l.Name() != "stellar" {
		t.Fatalf("Name() = %q, want stellar", l.Name())
	}
	return l
}

func TestStellar_Validate_AcceptsValidPayment(t *testing.T) {
	l := stellarAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "stellar", Originator: stlA, Beneficiary: stlB, Amount: "50.5", Currency: "XLM", Timestamp: 1750000000},
		// Issued asset (USDC) with a MEMO_HASH anchor (64 hex).
		{Chain: "stellar", Originator: stlA, Beneficiary: stlB, Amount: "1000", Currency: "USDC", Timestamp: 1750000000,
			Extra: map[string]string{"memo_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid payment rejected: %v", i, err)
		}
	}
}

func TestStellar_Validate_Rejects(t *testing.T) {
	l := stellarAdapter(t)
	longMemo := make([]byte, 29)
	for i := range longMemo {
		longMemo[i] = 'a'
	}
	bad := map[string]ledger.TxnContext{
		"bad address":         {Beneficiary: "alice", Amount: "1", Currency: "XLM"},
		"wrong length G":      {Beneficiary: "GABC", Amount: "1", Currency: "XLM"},
		"bad originator":      {Originator: "nope", Beneficiary: stlB, Amount: "1", Currency: "XLM"},
		"empty amount":        {Beneficiary: stlB, Amount: "", Currency: "XLM"},
		"negative amount":     {Beneficiary: stlB, Amount: "-5", Currency: "XLM"},
		"empty currency":      {Beneficiary: stlB, Amount: "1", Currency: ""},
		"asset code too long": {Beneficiary: stlB, Amount: "1", Currency: "THISISTOOLONG"},
		"over-long memo":      {Beneficiary: stlB, Amount: "1", Currency: "XLM", Extra: map[string]string{"memo": string(longMemo)}},
		"bad memo_hash":       {Beneficiary: stlB, Amount: "1", Currency: "XLM", Extra: map[string]string{"memo_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestStellar_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := stellarAdapter(t)
	tc := ledger.TxnContext{
		Chain: "stellar", Originator: stlA, Beneficiary: stlB,
		Amount: "5000.00", Currency: "XLM", Timestamp: 1750000000,
		Extra: map[string]string{"memo": "ref-1"},
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, h2, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
	tc2 := tc
	tc2.Amount = "5001.00"
	_, h3, _ := ledger.ContextHash(l, tc2)
	if h1 == h3 {
		t.Error("amount change did not alter the context hash")
	}
	// Chain tag is in the preimage: Stellar must not collide with Solana.
	sol, _ := ledger.Get("solana")
	stc := ledger.TxnContext{Originator: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
		Beneficiary: "7C4jsPZpht42Tw6MjXWF56Q5RQUocjBBmciEjDa8HRtp", Amount: "5000.00", Currency: "XLM", Timestamp: 1750000000}
	_, hs, _ := ledger.ContextHash(sol, stc)
	if h1 == hs {
		t.Error("stellar and solana context hashes collided")
	}
}
