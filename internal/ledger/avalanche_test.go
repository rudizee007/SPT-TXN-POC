package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	avaxA   = "0x0102030405060708090a0b0c0d0e0f1011121314"
	avaxB   = "0xfFEEdDcCBbAa99887766554433221100ffEEddCc"
	avaxTok = "0x00000000000000000000000000000000000000aa"
)

func avalancheAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("avalanche")
	if err != nil {
		t.Fatalf("avalanche adapter not registered: %v", err)
	}
	if l.Name() != "avalanche" {
		t.Fatalf("Name() = %q, want avalanche", l.Name())
	}
	return l
}

func TestAvalanche_Validate_AcceptsValidTransfer(t *testing.T) {
	l := avalancheAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "avalanche", Originator: avaxA, Beneficiary: avaxB, Amount: "5.5", Currency: "AVAX", Timestamp: 1750000000},
		{Chain: "avalanche", Originator: avaxA, Beneficiary: avaxB, Amount: "1000", Currency: avaxTok, Timestamp: 1750000000},
		{Chain: "avalanche", Originator: avaxA, Beneficiary: avaxB, Amount: "42", Currency: "AVAX", Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestAvalanche_Validate_Rejects(t *testing.T) {
	l := avalancheAdapter(t)
	bad := map[string]ledger.TxnContext{
		"no 0x prefix":   {Beneficiary: "deadbeef", Amount: "1", Currency: "AVAX"},
		"wrong length":   {Beneficiary: avaxB + "ff", Amount: "1", Currency: "AVAX"},
		"non-hex":        {Beneficiary: "0xZZZ", Amount: "1", Currency: "AVAX"},
		"bad originator": {Originator: "nope", Beneficiary: avaxB, Amount: "1", Currency: "AVAX"},
		"empty amount":   {Beneficiary: avaxB, Amount: "", Currency: "AVAX"},
		"negative":       {Beneficiary: avaxB, Amount: "-5", Currency: "AVAX"},
		"empty currency": {Beneficiary: avaxB, Amount: "1", Currency: ""},
		"bad currency":   {Beneficiary: avaxB, Amount: "1", Currency: "USDC"},
		"bad anchor":     {Beneficiary: avaxB, Amount: "1", Currency: "AVAX", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestAvalanche_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := avalancheAdapter(t)
	tc := ledger.TxnContext{
		Chain: "avalanche", Originator: avaxA, Beneficiary: avaxB,
		Amount: "5000.00", Currency: "AVAX", Timestamp: 1750000000,
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
	// Chain tag is in the preimage: Avalanche must not collide with Ethereum even
	// though both accept identical 0x-hex EVM addresses.
	eth, _ := ledger.Get("ethereum")
	etc := ledger.TxnContext{Chain: "ethereum", Originator: avaxA, Beneficiary: avaxB,
		Amount: "5000.00", Currency: "ETH", Timestamp: 1750000000}
	_, heth, _ := ledger.ContextHash(eth, etc)
	if h1 == heth {
		t.Error("avalanche and ethereum context hashes collided")
	}
}
