package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	aptA    = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	aptB    = "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	aptCoin = "0x1::aptos_coin::AptosCoin"
	aptFA   = "0x000000000000000000000000000000000000000000000000000000000000000a"
)

func aptosAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("aptos")
	if err != nil {
		t.Fatalf("aptos adapter not registered: %v", err)
	}
	if l.Name() != "aptos" {
		t.Fatalf("Name() = %q, want aptos", l.Name())
	}
	return l
}

func TestAptos_Validate_AcceptsValidTransfer(t *testing.T) {
	l := aptosAdapter(t)
	cases := []ledger.TxnContext{
		// native APT
		{Chain: "aptos", Originator: aptA, Beneficiary: aptB, Amount: "5.5", Currency: "APT", Timestamp: 1750000000},
		// short-form address (leading zeros omitted) + Move coin type tag
		{Chain: "aptos", Originator: "0x1", Beneficiary: aptB, Amount: "1000", Currency: aptCoin, Timestamp: 1750000000},
		// Fungible Asset object address + an on-chain anchor hash
		{Chain: "aptos", Originator: aptA, Beneficiary: aptB, Amount: "42", Currency: aptFA, Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestAptos_Validate_Rejects(t *testing.T) {
	l := aptosAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no 0x prefix":   {Beneficiary: "deadbeef", Amount: "1", Currency: "APT"},
		"too long hex":   {Beneficiary: "0x" + "f" + aptB[2:], Amount: "1", Currency: "APT"}, // 65 hex
		"non-hex":        {Beneficiary: "0xZZZ", Amount: "1", Currency: "APT"},
		"bad originator": {Originator: "nope", Beneficiary: aptB, Amount: "1", Currency: "APT"},
		"empty amount":   {Beneficiary: aptB, Amount: "", Currency: "APT"},
		"negative":       {Beneficiary: aptB, Amount: "-5", Currency: "APT"},
		"empty currency": {Beneficiary: aptB, Amount: "1", Currency: ""},
		"bad currency":   {Beneficiary: aptB, Amount: "1", Currency: "USDC"},                      // not APT, not a type tag, not an addr
		"bad coin type":  {Beneficiary: aptB, Amount: "1", Currency: "0x1::aptos_coin"},           // only 2 segments
		"bad type ident": {Beneficiary: aptB, Amount: "1", Currency: "0x1::9bad::AptosCoin"},      // module starts with digit
		"bad anchor":     {Beneficiary: aptB, Amount: "1", Currency: "APT", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestAptos_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := aptosAdapter(t)
	tc := ledger.TxnContext{
		Chain: "aptos", Originator: aptA, Beneficiary: aptB,
		Amount: "5000.00", Currency: "APT", Timestamp: 1750000000,
		Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"},
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
	// Chain tag is in the preimage: Aptos must not collide with Starknet even
	// though both use 0x + hex addresses.
	stk, _ := ledger.Get("starknet")
	stc := ledger.TxnContext{Chain: "starknet", Originator: aptA, Beneficiary: aptB,
		Amount: "5000.00", Currency: "STRK", Timestamp: 1750000000}
	_, hstk, _ := ledger.ContextHash(stk, stc)
	if h1 == hstk {
		t.Error("aptos and starknet context hashes collided")
	}
}
