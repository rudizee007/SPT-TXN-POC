package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	opA = "0x0102030405060708090a0b0c0d0e0f1011121314"
	opB = "0xfFEEdDcCBbAa99887766554433221100ffEEddCc"
)

// Both OP-Stack L2 adapters register and validate identical EVM transfer shapes.
func TestOpStack_Register_AndValidate(t *testing.T) {
	for _, name := range []string{"optimism", "base"} {
		l, err := ledger.Get(name)
		if err != nil {
			t.Fatalf("%s adapter not registered: %v", name, err)
		}
		if l.Name() != name {
			t.Fatalf("Name() = %q, want %q", l.Name(), name)
		}
		ok := ledger.TxnContext{Chain: name, Originator: opA, Beneficiary: opB, Amount: "5.5", Currency: "ETH", Timestamp: 1750000000}
		if err := l.Validate(ok); err != nil {
			t.Errorf("%s: valid transfer rejected: %v", name, err)
		}
		bad := ledger.TxnContext{Chain: name, Beneficiary: "nope", Amount: "1", Currency: "ETH"}
		if err := l.Validate(bad); err == nil {
			t.Errorf("%s: expected rejection of a bad address", name)
		}
		if err := l.Validate(ledger.TxnContext{Chain: name, Beneficiary: opB, Amount: "-1", Currency: "ETH"}); err == nil {
			t.Errorf("%s: expected rejection of a negative amount", name)
		}
	}
}

// The chain tag keeps every EVM adapter's context hash distinct, so an identical
// transfer never collides across ethereum / arbitrum / optimism / base.
func TestOpStack_NoCrossChainCollision(t *testing.T) {
	chains := []string{"ethereum", "arbitrum", "optimism", "base"}
	seen := map[string]string{}
	for _, name := range chains {
		l, err := ledger.Get(name)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		tc := ledger.TxnContext{Chain: name, Originator: opA, Beneficiary: opB,
			Amount: "5000.00", Currency: "ETH", Timestamp: 1750000000}
		_, h, err := ledger.ContextHash(l, tc)
		if err != nil {
			t.Fatalf("%s hash: %v", name, err)
		}
		if len(h) != 64 {
			t.Errorf("%s: expected 64 hex chars, got %d", name, len(h))
		}
		if prev, dup := seen[h]; dup {
			t.Errorf("collision: %s and %s produced the same context hash", prev, name)
		}
		seen[h] = name
	}
}
