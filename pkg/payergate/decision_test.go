package payergate

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/ledger"
)

// goodDecision builds an ALLOW whose ContextHash genuinely derives from its
// fields, so every test starts from a document the checks should accept.
func goodDecision(t *testing.T) Decision {
	t.Helper()
	ctx := Context{
		Chain:       "base",
		Originator:  "0x61d6d0929c83a2678a42295fa78a7b38ef0b8f95",
		Beneficiary: "0xd061cf365c8cb0bd38ab5fdf6832b1cf8313d09d",
		Amount:      "0.100000",
		Currency:    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		Timestamp:   1787862062,
	}
	l, err := ledger.Get(ctx.Chain)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err := ledger.ContextHash(l, ledger.TxnContext{
		Chain: ctx.Chain, Originator: ctx.Originator, Beneficiary: ctx.Beneficiary,
		Amount: ctx.Amount, Currency: ctx.Currency, Timestamp: ctx.Timestamp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Decision{
		Version:     FormatVersion,
		Outcome:     Allow,
		Anchor:      "055cc320d970db0da5c4fda7ffcd95b753990c7778e33d74731ea35a90254403",
		Ceiling:     "0.100000",
		Context:     ctx,
		ContextHash: h,
		IssuedAt:    time.Now().Unix(),
		Verified:    true,
	}
}

// TestCheckSettleable_AcceptsAGenuineAllow is the baseline; without it every
// refusal test below could pass by refusing everything.
func TestCheckSettleable_AcceptsAGenuineAllow(t *testing.T) {
	d := goodDecision(t)
	if err := d.CheckSettleable(time.Now(), 10*time.Minute); err != nil {
		t.Fatalf("a genuine ALLOW was refused: %v", err)
	}
}

// TestCheckSettleable_RefusesADeny. The consumer-side half of "the DENY branch
// has no path to signing": a DENY document must be unusable for settlement,
// whatever else it says.
func TestCheckSettleable_RefusesADeny(t *testing.T) {
	d := goodDecision(t)
	d.Outcome = Deny
	d.Reason = "policy: over ceiling"
	if err := d.CheckSettleable(time.Now(), 10*time.Minute); !errors.Is(err, ErrNotAllow) {
		t.Fatalf("a DENY decision passed the settle check: %v", err)
	}
}

// TestCheckSettleable_RefusesAlteredFields. The document carries both the
// fields and the hash; changing either after the decision must be caught.
// This is what stops a consumer settling a DIFFERENT payment than the gate
// decided about while still pointing at the gate's ALLOW.
func TestCheckSettleable_RefusesAlteredFields(t *testing.T) {
	for name, mutate := range map[string]func(*Decision){
		"amount raised":       func(d *Decision) { d.Context.Amount = "999.000000" },
		"beneficiary swapped": func(d *Decision) { d.Context.Beneficiary = "0x61d6d0929c83a2678a42295fa78a7b38ef0b8f95" },
		"timestamp moved":     func(d *Decision) { d.Context.Timestamp++ },
		"chain switched":      func(d *Decision) { d.Context.Chain = "ethereum" },
		"hash replaced":       func(d *Decision) { d.ContextHash = "00" + d.ContextHash[2:] },
	} {
		d := goodDecision(t)
		mutate(&d)
		if err := d.CheckSettleable(time.Now(), 10*time.Minute); err == nil {
			t.Errorf("%s: an altered decision passed the settle check", name)
		}
	}
}

// TestCheckSettleable_RefusesStale. A decision is an answer about a moment; a
// consumer settling on yesterday's ALLOW is settling on yesterday's registry,
// yesterday's revocations and yesterday's scope.
func TestCheckSettleable_RefusesStale(t *testing.T) {
	d := goodDecision(t)
	d.IssuedAt = time.Now().Add(-time.Hour).Unix()
	if err := d.CheckSettleable(time.Now(), 10*time.Minute); !errors.Is(err, ErrStale) {
		t.Fatalf("an hour-old decision passed a 10-minute bound: %v", err)
	}
	// maxAge <= 0 disables the check, for audit replay only.
	if err := d.CheckSettleable(time.Now(), 0); err != nil {
		t.Fatalf("audit replay with maxAge=0 refused: %v", err)
	}
}

func TestCheckSettleable_RefusesWrongVersion(t *testing.T) {
	d := goodDecision(t)
	d.Version = 99
	if err := d.CheckSettleable(time.Now(), time.Minute); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("a foreign version passed: %v", err)
	}
}

// TestRoundTrip. Write then Read then CheckSettleable: the on-disk form must
// carry everything the checks need, and DisallowUnknownFields must hold the
// contract closed.
func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decision.json")
	d := goodDecision(t)
	if err := Write(path, d); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckSettleable(time.Now(), 10*time.Minute); err != nil {
		t.Fatalf("round-tripped decision refused: %v", err)
	}
	if got.Anchor != d.Anchor || got.Ceiling != d.Ceiling {
		t.Fatal("round trip lost fields")
	}
}
