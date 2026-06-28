package ledger_test

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
)

const (
	// a valid-shape SS58 address (47 chars, base58) and a raw 0x AccountId32.
	dotSS58 = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
	dotHex  = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)

func polkadotAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("polkadot")
	if err != nil {
		t.Fatalf("polkadot adapter not registered: %v", err)
	}
	if l.Name() != "polkadot" {
		t.Fatalf("Name() = %q, want polkadot", l.Name())
	}
	return l
}

func TestPolkadot_Validate_AcceptsValidTransfer(t *testing.T) {
	l := polkadotAdapter(t)
	cases := []ledger.TxnContext{
		{Chain: "polkadot", Originator: dotSS58, Beneficiary: dotSS58, Amount: "12.5", Currency: "DOT", Timestamp: 1750000000},
		{Chain: "polkadot", Originator: dotHex, Beneficiary: dotSS58, Amount: "1000", Currency: "DOT", Timestamp: 1750000000},
		{Chain: "polkadot", Originator: dotSS58, Beneficiary: dotHex, Amount: "42", Currency: "USDT", Timestamp: 1750000000,
			Extra: map[string]string{"remark": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestPolkadot_Validate_Rejects(t *testing.T) {
	l := polkadotAdapter(t)
	bad := map[string]ledger.TxnContext{
		"too short":      {Beneficiary: "abc", Amount: "1", Currency: "DOT"},
		"non-base58":     {Beneficiary: "05oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", Amount: "1", Currency: "DOT"}, // leading 0 not in base58
		"short hex":      {Beneficiary: dotHex[:len(dotHex)-1], Amount: "1", Currency: "DOT"},                              // 63 hex
		"bad originator": {Originator: "nope!", Beneficiary: dotSS58, Amount: "1", Currency: "DOT"},
		"empty amount":   {Beneficiary: dotSS58, Amount: "", Currency: "DOT"},
		"negative":       {Beneficiary: dotSS58, Amount: "-5", Currency: "DOT"},
		"empty currency": {Beneficiary: dotSS58, Amount: "1", Currency: ""},
		"bad remark":     {Beneficiary: dotSS58, Amount: "1", Currency: "DOT", Extra: map[string]string{"remark": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestPolkadot_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := polkadotAdapter(t)
	tc := ledger.TxnContext{
		Chain: "polkadot", Originator: dotSS58, Beneficiary: dotSS58,
		Amount: "5000.00", Currency: "DOT", Timestamp: 1750000000,
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
	// Chain tag is in the preimage: a raw 0x AccountId32 must not collide with the
	// same bytes interpreted as another 0x-hex chain (sui).
	sui, _ := ledger.Get("sui")
	stc := ledger.TxnContext{Chain: "sui", Originator: dotHex, Beneficiary: dotHex,
		Amount: "5000.00", Currency: "SUI", Timestamp: 1750000000}
	ptc := ledger.TxnContext{Chain: "polkadot", Originator: dotHex, Beneficiary: dotHex,
		Amount: "5000.00", Currency: "DOT", Timestamp: 1750000000}
	_, hsui, _ := ledger.ContextHash(sui, stc)
	_, hpol, _ := ledger.ContextHash(l, ptc)
	if hsui == hpol {
		t.Error("polkadot and sui context hashes collided")
	}
}
