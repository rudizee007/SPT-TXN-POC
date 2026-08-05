package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

func nearAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("near")
	if err != nil {
		t.Fatalf("near adapter not registered: %v", err)
	}
	if l.Name() != "near" {
		t.Fatalf("Name() = %q, want near", l.Name())
	}
	return l
}

func TestNear_Validate_AcceptsValidTransfer(t *testing.T) {
	l := nearAdapter(t)
	const acctA = "agent.alice.testnet"
	const acctB = "merchant.testnet"
	const ftContract = "usdt.tether-token.near"
	// 64-hex implicit account
	const implicit = "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de"
	cases := []ledger.TxnContext{
		{Chain: "near", Originator: acctA, Beneficiary: acctB, Amount: "1000", Currency: "NEAR", Timestamp: 1750000000},
		{Chain: "near", Originator: acctA, Beneficiary: implicit, Amount: "5.5", Currency: ftContract, Timestamp: 1750000000, Extra: map[string]string{"memo": "invoice-7"}},
		{Chain: "near", Originator: implicit, Beneficiary: acctB, Amount: "42", Currency: "near", Timestamp: 1750000000},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestNear_Validate_Rejects(t *testing.T) {
	l := nearAdapter(t)
	const acctB = "merchant.testnet"
	bad := map[string]ledger.TxnContext{
		"too short":       {Beneficiary: "a", Amount: "1", Currency: "NEAR"},
		"uppercase":       {Beneficiary: "Merchant.testnet", Amount: "1", Currency: "NEAR"},
		"leading dot":     {Beneficiary: ".merchant.testnet", Amount: "1", Currency: "NEAR"},
		"double dot":      {Beneficiary: "a..b", Amount: "1", Currency: "NEAR"},
		"bad char":        {Beneficiary: "mer chant.testnet", Amount: "1", Currency: "NEAR"},
		"bad originator":  {Originator: "!!!", Beneficiary: acctB, Amount: "1", Currency: "NEAR"},
		"empty amount":    {Beneficiary: acctB, Amount: "", Currency: "NEAR"},
		"negative amount": {Beneficiary: acctB, Amount: "-5", Currency: "NEAR"},
		"empty currency":  {Beneficiary: acctB, Amount: "1", Currency: ""},
		"bad currency":    {Beneficiary: acctB, Amount: "1", Currency: "US DC!"},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestNear_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := nearAdapter(t)
	tc := ledger.TxnContext{
		Chain: "near", Originator: "agent.alice.testnet", Beneficiary: "merchant.testnet",
		Amount: "5000", Currency: "NEAR", Timestamp: 1750000000,
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
	tc2.Amount = "5001"
	_, h3, _ := ledger.ContextHash(l, tc2)
	if h1 == h3 {
		t.Error("amount change did not alter the context hash")
	}
	// Chain tag is part of the preimage: a NEAR transfer must not collide with a
	// Solana transfer of the same field values.
	sol, _ := ledger.Get("solana")
	stc := ledger.TxnContext{Originator: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", Beneficiary: "7C4jsPZpht42Tw6MjXWF56Q5RQUocjBBmciEjDa8HRtp", Amount: "5000", Currency: "NEAR", Timestamp: 1750000000}
	_, sh, _ := ledger.ContextHash(sol, stc)
	if h1 == sh {
		t.Error("near and solana context hashes collided")
	}
}
