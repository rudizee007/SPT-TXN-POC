package ledger_test

import (
	"testing"

	internalledger "github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/pkg/ledger"
)

// The claim this package makes is that it contains no logic — that a caller
// outside the module gets byte-identical results to a caller inside it. These
// tests exist to make that claim falsifiable rather than merely stated.

func contexts() []ledger.TxnContext {
	return []ledger.TxnContext{
		{
			Chain:       "base",
			Originator:  "0x61d6d0929c83a2678a42295fa78a7b38ef0b8f95",
			Beneficiary: "0xd061cf365c8cb0bd38ab5fdf6832b1cf8313d09d",
			Amount:      "0.100000",
			Currency:    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			Timestamp:   1787847418,
		},
		{
			// With Extra populated, because the canonical encoder sorts those
			// keys separately and that is the part most likely to diverge if
			// this ever stopped being a facade.
			Chain:       "base",
			Originator:  "0x61d6d0929c83a2678a42295fa78a7b38ef0b8f95",
			Beneficiary: "0xd061cf365c8cb0bd38ab5fdf6832b1cf8313d09d",
			Amount:      "1.000000",
			Currency:    "ETH",
			Timestamp:   1787847418,
			Extra: map[string]string{
				"zebra": "last",
				"alpha": "first",
			},
		},
	}
}

// TestFacadeIsByteIdenticalToInternal is the whole point of the package.
func TestFacadeIsByteIdenticalToInternal(t *testing.T) {
	pub, err := ledger.Get("base")
	if err != nil {
		t.Fatalf("pkg/ledger.Get(\"base\"): %v", err)
	}
	priv, err := internalledger.Get("base")
	if err != nil {
		t.Fatalf("internal/ledger.Get(\"base\"): %v", err)
	}

	for i, tc := range contexts() {
		gotRaw, gotHex, err := ledger.ContextHash(pub, tc)
		if err != nil {
			t.Fatalf("case %d: pkg ContextHash: %v", i, err)
		}
		// The alias means this same value is accepted by the internal function
		// with no conversion. If TxnContext ever became a distinct struct here,
		// this line would stop compiling — which is the intended alarm.
		wantRaw, wantHex, err := internalledger.ContextHash(priv, tc)
		if err != nil {
			t.Fatalf("case %d: internal ContextHash: %v", i, err)
		}
		if gotHex != wantHex {
			t.Errorf("case %d: hash differs\n  pkg      %s\n  internal %s", i, gotHex, wantHex)
		}
		if len(gotRaw) != 32 {
			t.Errorf("case %d: raw digest is %d bytes, want 32", i, len(gotRaw))
		}
		if string(gotRaw) != string(wantRaw) {
			t.Errorf("case %d: raw digests differ", i)
		}
	}
}

// TestAdaptersAreRegisteredThroughTheFacade. Adapters register from init() in
// internal/ledger. If importing only pkg/ledger did not pull that in, Get would
// fail here and an external caller would be unable to hash anything.
func TestAdaptersAreRegisteredThroughTheFacade(t *testing.T) {
	for _, name := range []string{"base", "ethereum", "xrpl", "none"} {
		if _, err := ledger.Get(name); err != nil {
			t.Errorf("Get(%q) through the facade: %v", name, err)
		}
	}
	if _, err := ledger.Get("definitely-not-a-chain"); err == nil {
		t.Error("Get accepted an unregistered chain name")
	}
}

// TestChainTagSeparatesOtherwiseIdenticalTransfers.
//
// Base, Ethereum and Optimism all accept identical 0x-hex addresses. If their
// canonical preimages did not carry distinct chain tags, the same transfer on
// two chains would share a context hash — and an anchor attestation bound to a
// payment on one chain would be equally valid for a payment on the other.
// That is a cross-chain replay, so it is worth pinning here rather than
// assuming it from a comment in the adapter.
func TestChainTagSeparatesOtherwiseIdenticalTransfers(t *testing.T) {
	base := ledger.TxnContext{
		Chain:       "base",
		Originator:  "0x61d6d0929c83a2678a42295fa78a7b38ef0b8f95",
		Beneficiary: "0xd061cf365c8cb0bd38ab5fdf6832b1cf8313d09d",
		Amount:      "0.100000",
		Currency:    "ETH",
		Timestamp:   1787847418,
	}
	eth := base
	eth.Chain = "ethereum"

	bl, err := ledger.Get("base")
	if err != nil {
		t.Fatal(err)
	}
	el, err := ledger.Get("ethereum")
	if err != nil {
		t.Fatal(err)
	}
	_, bh, err := ledger.ContextHash(bl, base)
	if err != nil {
		t.Fatal(err)
	}
	_, eh, err := ledger.ContextHash(el, eth)
	if err != nil {
		t.Fatal(err)
	}
	if bh == eh {
		t.Fatalf("base and ethereum produced the same context hash %s for the "+
			"same transfer — an attestation bound to one would be valid for the other", bh)
	}
}

// TestMatchesPublishedConformanceVectors pins the facade against the vectors
// cmd/conformance emits, rather than only against internal/ledger.
//
// The other tests here check the facade agrees with the implementation behind
// it. That is necessary and not sufficient: if BOTH changed together the tests
// would still pass and every previously issued context hash would silently
// stop matching. These values are the project's published conformance vectors
// -- the same numbers an external implementer would build against -- so this
// test fails if the canonicalization itself ever moves, whichever side moved it.
//
// If it fails: do not update the constants. Find out what changed the preimage.
func TestMatchesPublishedConformanceVectors(t *testing.T) {
	for _, v := range []struct {
		chain, originator, beneficiary, amount, currency, want string
		timestamp                                              int64
	}{
		{
			chain: "base", timestamp: 1750000000,
			originator:  "0x0102030405060708090a0b0c0d0e0f1011121314",
			beneficiary: "0xfFEEdDcCBbAa99887766554433221100ffEEddCc",
			amount:      "5000.00", currency: "ETH",
			want: "1b26b985cb78490b3cba43c397094aa87c87b023017f5acb16d2aa57b4f782bf",
		},
		{
			// Ethereum, for the cross-chain separation claim: identical fields
			// on a different chain tag must produce a different digest, and
			// both digests are pinned rather than merely asserted unequal.
			chain: "ethereum", timestamp: 1750000000,
			originator:  "0x0102030405060708090a0b0c0d0e0f1011121314",
			beneficiary: "0xfFEEdDcCBbAa99887766554433221100ffEEddCc",
			amount:      "5000.00", currency: "ETH",
			want: "537d44521507cc881c32db2af3e963698baf5b0de7b0e162e4f22f279f1384bc",
		},
		{
			// A non-EVM chain, so the pin is not only exercising one adapter.
			chain: "xrpl", timestamp: 1750000000,
			originator:  "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
			beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
			amount:      "5000.00", currency: "USD",
			want: "b91913f380e18e3a82fef69b92ae191a55dcae7d37fd05d766b12ebbb3991128",
		},
	} {
		l, err := ledger.Get(v.chain)
		if err != nil {
			t.Errorf("%s: %v", v.chain, err)
			continue
		}
		_, got, err := ledger.ContextHash(l, ledger.TxnContext{
			Chain: v.chain, Originator: v.originator, Beneficiary: v.beneficiary,
			Amount: v.amount, Currency: v.currency, Timestamp: v.timestamp,
		})
		if err != nil {
			t.Errorf("%s: %v", v.chain, err)
			continue
		}
		if got != v.want {
			t.Errorf("%s context hash drifted\n  got  %s\n  want %s (published vector)",
				v.chain, got, v.want)
		}
	}
}
