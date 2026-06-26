package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func hederaAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("hedera")
	if err != nil {
		t.Fatalf("hedera adapter not registered: %v", err)
	}
	if l.Name() != "hedera" {
		t.Fatalf("Name() = %q, want hedera", l.Name())
	}
	return l
}

func TestHedera_Validate_AcceptsValidTransfer(t *testing.T) {
	l := hederaAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "hedera", Originator: "0.0.1001", Beneficiary: "0.0.2002", Amount: "50.5", Currency: "HBAR", Timestamp: 1750000000},
		// HTS token transfer, EVM-alias beneficiary, with a memo.
		{Chain: "hedera", Originator: "0.0.1001", Beneficiary: "0x52908400098527886E0F7030069857D2E4169EE7",
			Amount: "1000", Currency: "0.0.456858", Timestamp: 1750000000, Extra: map[string]string{"memo": "invoice-7"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestHedera_Validate_Rejects(t *testing.T) {
	l := hederaAdapter(t)
	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}
	bad := map[string]ledger.TxnContext{
		"bad beneficiary":  {Beneficiary: "ralice", Amount: "1", Currency: "HBAR"},
		"bad originator":   {Originator: "nope", Beneficiary: "0.0.2002", Amount: "1", Currency: "HBAR"},
		"empty amount":     {Beneficiary: "0.0.2002", Amount: "", Currency: "HBAR"},
		"negative amount":  {Beneficiary: "0.0.2002", Amount: "-5", Currency: "HBAR"},
		"empty currency":   {Beneficiary: "0.0.2002", Amount: "1", Currency: ""},
		"over-long memo":   {Beneficiary: "0.0.2002", Amount: "1", Currency: "HBAR", Extra: map[string]string{"memo": string(long)}},
		"two-part account": {Beneficiary: "0.2002", Amount: "1", Currency: "HBAR"},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestHedera_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := hederaAdapter(t)
	tc := ledger.TxnContext{
		Chain: "hedera", Originator: "0.0.1001", Beneficiary: "0.0.2002",
		Amount: "5000.00", Currency: "HBAR", Timestamp: 1750000000,
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
	// A different amount must change the binding.
	tc2 := tc
	tc2.Amount = "5001.00"
	_, h3, _ := ledger.ContextHash(l, tc2)
	if h1 == h3 {
		t.Error("amount change did not alter the context hash")
	}
	// A Hedera transfer must not collide with an XRPL transfer of the same values
	// (the chain tag is part of the preimage).
	x, _ := ledger.Get("xrpl")
	xtc := ledger.TxnContext{Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW", Amount: "5000.00", Currency: "HBAR", Timestamp: 1750000000}
	_, hx, _ := ledger.ContextHash(x, xtc)
	if h1 == hx {
		t.Error("hedera and xrpl context hashes collided")
	}
}
