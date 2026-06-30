package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func TestXLayer_RegistersBindsAndIsDistinct(t *testing.T) {
	l, err := ledger.Get("xlayer")
	if err != nil {
		t.Fatalf("xlayer adapter not registered: %v", err)
	}
	if l.Name() != "xlayer" {
		t.Fatalf("Name() = %q, want xlayer", l.Name())
	}

	tc := ledger.TxnContext{
		Chain: "xlayer", Originator: ethA, Beneficiary: ethB,
		Amount: "5.5", Currency: "OKB", Timestamp: 1750000000,
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("valid transfer rejected: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}

	if err := l.Validate(ledger.TxnContext{Beneficiary: "deadbeef", Amount: "1", Currency: "OKB"}); err == nil {
		t.Error("expected validation error for non-EVM address")
	}

	// reject a non-native currency that isn't an ERC-20 address
	if err := l.Validate(ledger.TxnContext{Beneficiary: ethB, Amount: "1", Currency: "BTC"}); err == nil {
		t.Error("expected validation error for bad currency")
	}

	// distinct chain tag → must not collide with ethereum
	eth, _ := ledger.Get("ethereum")
	etc := tc
	etc.Chain = "ethereum"
	etc.Currency = "ETH"
	_, hEth, _ := ledger.ContextHash(eth, etc)
	if h1 == hEth {
		t.Error("xlayer and ethereum context hashes collided")
	}
}
