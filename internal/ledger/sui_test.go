package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	suiA    = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	suiB    = "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	suiCoin = "0x2::sui::SUI"
)

func suiAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("sui")
	if err != nil {
		t.Fatalf("sui adapter not registered: %v", err)
	}
	if l.Name() != "sui" {
		t.Fatalf("Name() = %q, want sui", l.Name())
	}
	return l
}

func TestSui_Validate_AcceptsValidTransfer(t *testing.T) {
	l := suiAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "sui", Originator: suiA, Beneficiary: suiB, Amount: "5.5", Currency: "SUI", Timestamp: 1750000000},
		{Chain: "sui", Originator: "0x2", Beneficiary: suiB, Amount: "1000", Currency: suiCoin, Timestamp: 1750000000},
		{Chain: "sui", Originator: suiA, Beneficiary: suiB, Amount: "42", Currency: "SUI", Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestSui_Validate_Rejects(t *testing.T) {
	l := suiAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no 0x prefix":   {Beneficiary: "deadbeef", Amount: "1", Currency: "SUI"},
		"too long hex":   {Beneficiary: "0x" + "f" + suiB[2:], Amount: "1", Currency: "SUI"},
		"non-hex":        {Beneficiary: "0xZZZ", Amount: "1", Currency: "SUI"},
		"bad originator": {Originator: "nope", Beneficiary: suiB, Amount: "1", Currency: "SUI"},
		"empty amount":   {Beneficiary: suiB, Amount: "", Currency: "SUI"},
		"negative":       {Beneficiary: suiB, Amount: "-5", Currency: "SUI"},
		"empty currency": {Beneficiary: suiB, Amount: "1", Currency: ""},
		"bad currency":   {Beneficiary: suiB, Amount: "1", Currency: "USDC"},
		"bad coin type":  {Beneficiary: suiB, Amount: "1", Currency: "0x2::sui"},
		"bad type ident": {Beneficiary: suiB, Amount: "1", Currency: "0x2::9bad::SUI"},
		"bad anchor":     {Beneficiary: suiB, Amount: "1", Currency: "SUI", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestSui_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := suiAdapter(t)
	tc := ledger.TxnContext{
		Chain: "sui", Originator: suiA, Beneficiary: suiB,
		Amount: "5000.00", Currency: "SUI", Timestamp: 1750000000,
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, h2, _ := ledger.ContextHash(l, tc)
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
	// Chain tag is in the preimage: Sui must not collide with Aptos even though
	// both use 0x + hex addresses and Move coin types.
	apt, _ := ledger.Get("aptos")
	atc := ledger.TxnContext{Chain: "aptos", Originator: suiA, Beneficiary: suiB,
		Amount: "5000.00", Currency: "APT", Timestamp: 1750000000}
	_, hapt, _ := ledger.ContextHash(apt, atc)
	if h1 == hapt {
		t.Error("sui and aptos context hashes collided")
	}
}
