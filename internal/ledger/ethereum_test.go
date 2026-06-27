package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	ethA     = "0x0102030405060708090a0b0c0d0e0f1011121314"
	ethB     = "0xfFEEdDcCBbAa99887766554433221100ffEEddCc"
	ethToken = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" // USDC-style 20-byte token addr
)

func ethereumAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("ethereum")
	if err != nil {
		t.Fatalf("ethereum adapter not registered: %v", err)
	}
	if l.Name() != "ethereum" {
		t.Fatalf("Name() = %q, want ethereum", l.Name())
	}
	return l
}

func TestEthereum_Validate_AcceptsValidTransfer(t *testing.T) {
	l := ethereumAdapter(t)
	cases := []ledger.TxnContext{
		// native ETH
		{Chain: "ethereum", Originator: ethA, Beneficiary: ethB, Amount: "5.5", Currency: "ETH", Timestamp: 1750000000},
		// ERC-20 token transfer (currency = token contract address) + anchor hash
		{Chain: "ethereum", Originator: ethA, Beneficiary: ethB, Amount: "1000", Currency: ethToken, Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestEthereum_Validate_Rejects(t *testing.T) {
	l := ethereumAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no 0x prefix":   {Beneficiary: "deadbeef", Amount: "1", Currency: "ETH"},
		"too long hex":   {Beneficiary: ethB + "ff", Amount: "1", Currency: "ETH"},     // 42 hex
		"too short hex":  {Beneficiary: ethB[:len(ethB)-1], Amount: "1", Currency: "ETH"}, // 39 hex
		"non-hex":        {Beneficiary: "0xZZZ", Amount: "1", Currency: "ETH"},
		"bad originator": {Originator: "nope", Beneficiary: ethB, Amount: "1", Currency: "ETH"},
		"empty amount":   {Beneficiary: ethB, Amount: "", Currency: "ETH"},
		"negative":       {Beneficiary: ethB, Amount: "-5", Currency: "ETH"},
		"empty currency": {Beneficiary: ethB, Amount: "1", Currency: ""},
		"bad currency":   {Beneficiary: ethB, Amount: "1", Currency: "USDC"}, // symbol, not ETH or a token addr
		"bad anchor":     {Beneficiary: ethB, Amount: "1", Currency: "ETH", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestEthereum_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := ethereumAdapter(t)
	tc := ledger.TxnContext{
		Chain: "ethereum", Originator: ethA, Beneficiary: ethB,
		Amount: "5000.00", Currency: "ETH", Timestamp: 1750000000,
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
	// Chain tag is in the preimage: Ethereum must not collide with Starknet even
	// though both use 0x + hex addresses.
	stk, _ := ledger.Get("starknet")
	stc := ledger.TxnContext{Chain: "starknet", Originator: ethA, Beneficiary: ethB,
		Amount: "5000.00", Currency: "ETH", Timestamp: 1750000000}
	_, hstk, _ := ledger.ContextHash(stk, stc)
	if h1 == hstk {
		t.Error("ethereum and starknet context hashes collided")
	}
}
