package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

func TestBSC_RegistersBindsAndIsDistinct(t *testing.T) {
	l, err := ledger.Get("bsc")
	if err != nil {
		t.Fatalf("bsc adapter not registered: %v", err)
	}
	if l.Name() != "bsc" {
		t.Fatalf("Name() = %q, want bsc", l.Name())
	}

	tc := ledger.TxnContext{
		Chain: "bsc", Originator: ethA, Beneficiary: ethB,
		Amount: "5.5", Currency: "BNB", Timestamp: 1750000000,
	}
	_, h1, err := ledger.ContextHash(l, tc)
	if err != nil {
		t.Fatalf("valid transfer rejected: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}

	// rejects a non-EVM address
	if err := l.Validate(ledger.TxnContext{Beneficiary: "deadbeef", Amount: "1", Currency: "BNB"}); err == nil {
		t.Error("expected validation error for non-EVM address")
	}

	// same fields under the Ethereum adapter must hash differently (distinct chain tag)
	eth, _ := ledger.Get("ethereum")
	etc := tc
	etc.Chain = "ethereum"
	etc.Currency = "ETH"
	_, hEth, _ := ledger.ContextHash(eth, etc)
	if h1 == hEth {
		t.Error("bsc and ethereum context hashes collided")
	}
}
