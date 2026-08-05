package ledger_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

const (
	algoA = "KNTKMJFYXI2B43M7G4LJ3KU5I452GORN3FCDDMFUEHF7Q3OBNND3OQENZE"
	algoB = "IGIOJAQMOL2F42RGONSM6ONMYZ2M22TNDZODKIOT7TK7IRXGCZXQMHEKQY"
	asaID = "31566704" // USDC ASA id on Algorand
)

func algorandAdapter(t *testing.T) ledger.Ledger {
	t.Helper()
	l, err := ledger.Get("algorand")
	if err != nil {
		t.Fatalf("algorand adapter not registered: %v", err)
	}
	if l.Name() != "algorand" {
		t.Fatalf("Name() = %q, want algorand", l.Name())
	}
	return l
}

func TestAlgorand_Validate_AcceptsValidTransfer(t *testing.T) {
	l := algorandAdapter(t)
	cases := []ledger.TxnContext{
		// native ALGO
		{Chain: "algorand", Originator: algoA, Beneficiary: algoB, Amount: "5.5", Currency: "ALGO", Timestamp: 1750000000},
		// ASA transfer + note-field anchor
		{Chain: "algorand", Originator: algoA, Beneficiary: algoB, Amount: "1000", Currency: asaID, Timestamp: 1750000000,
			Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"}},
	}
	for i, tc := range cases {
		if err := l.Validate(tc); err != nil {
			t.Errorf("case %d: valid transfer rejected: %v", i, err)
		}
	}
}

func TestAlgorand_Validate_Rejects(t *testing.T) {
	l := algorandAdapter(t)
	bad := map[string]ledger.TxnContext{
		"too short":        {Beneficiary: algoA[:57], Amount: "1", Currency: "ALGO"},
		"too long":         {Beneficiary: algoA + "A", Amount: "1", Currency: "ALGO"},
		"lowercase char":   {Beneficiary: algoA[:57] + "a", Amount: "1", Currency: "ALGO"}, // 58 len, 'a' not base32
		"digit out of set": {Beneficiary: algoA[:57] + "0", Amount: "1", Currency: "ALGO"}, // '0' not in [2-7]
		"bad originator":   {Originator: "nope", Beneficiary: algoB, Amount: "1", Currency: "ALGO"},
		"empty amount":     {Beneficiary: algoB, Amount: "", Currency: "ALGO"},
		"negative":         {Beneficiary: algoB, Amount: "-5", Currency: "ALGO"},
		"empty currency":   {Beneficiary: algoB, Amount: "1", Currency: ""},
		"bad currency":     {Beneficiary: algoB, Amount: "1", Currency: "USDCx"}, // not ALGO, not numeric
		"asa zero":         {Beneficiary: algoB, Amount: "1", Currency: "0"},
		"bad anchor":       {Beneficiary: algoB, Amount: "1", Currency: "ALGO", Extra: map[string]string{"anchor_hash": "xyz"}},
	}
	for name, tc := range bad {
		if err := l.Validate(tc); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestAlgorand_ContextHash_DeterministicAndBinding(t *testing.T) {
	l := algorandAdapter(t)
	tc := ledger.TxnContext{
		Chain: "algorand", Originator: algoA, Beneficiary: algoB,
		Amount: "5000.00", Currency: "ALGO", Timestamp: 1750000000,
		Extra: map[string]string{"anchor_hash": "4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9"},
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
	// Distinct chain tag from Stellar.
	stl, _ := ledger.Get("stellar")
	stc := ledger.TxnContext{Chain: "stellar", Originator: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW",
		Beneficiary: "G234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ", Amount: "5000.00", Currency: "XLM", Timestamp: 1750000000}
	_, hstl, _ := ledger.ContextHash(stl, stc)
	if h1 == hstl {
		t.Error("algorand and stellar context hashes collided")
	}
}
