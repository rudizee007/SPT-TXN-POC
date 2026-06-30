package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func TestMorph_RegistersBindsAndIsDistinct(t *testing.T) {
	l, err := ledger.Get("morph")
	if err != nil {
		t.Fatalf("morph adapter not registered: %v", err)
	}
	if l.Name() != "morph" {
		t.Fatalf("Name() = %q, want morph", l.Name())
	}

	tc := ledger.TxnContext{
		Chain: "morph", Originator: ethA, Beneficiary: ethB,
		Amount: "5.5", Currency: "ETH", Timestamp: 1750000000,
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("valid transfer rejected: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}

	if err := l.Validate(ledger.TxnContext{Beneficiary: "deadbeef", Amount: "1", Currency: "ETH"}); err == nil {
		t.Error("expected validation error for non-EVM address")
	}

	// distinct chain tag → must not collide with ethereum
	eth, _ := ledger.Get("ethereum")
	etc := tc
	etc.Chain = "ethereum"
	_, hEth, _ := ledger.ContextHash(eth, etc)
	if h1 == hEth {
		t.Error("morph and ethereum context hashes collided")
	}
}
