package verifier

import (
	"encoding/hex"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// checkSubbandMembership is the §7.2 enforcement point: a hop that carries a
// max_cumulative budget must prove membership in its parent's one committed
// division. This exercises it directly with constructed claims — the same shapes
// the chain walk hands it — so the enforcement is proven without standing up a
// full CAT→CT→TXN chain.
func TestCheckSubbandMembership(t *testing.T) {
	suite := tbac.SuiteSHA3_256
	catScope := tbac.Scope{"max_cumulative": 100, "currency": "USD"}
	bands := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 0, Expiry: 10},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 10, Expiry: 20},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 20, Expiry: 30},
	}
	root, _, paths, err := tbac.CommitBandDivision(suite, catScope, 0, 30, bands)
	if err != nil {
		t.Fatal(err)
	}
	rootHex := hex.EncodeToString(root[:])
	parentClaims := map[string]any{"subband_group_root": rootHex}

	// A member child's claims for band i, exactly as the JWT round-trip produces
	// them (numbers as float64, path as []any of hex strings).
	member := func(i int) map[string]any {
		ph := make([]any, len(paths[i]))
		for k, h := range paths[i] {
			ph[k] = hex.EncodeToString(h[:])
		}
		return map[string]any{
			"subband_group_root":  rootHex,
			"subband_group_size":  float64(3),
			"subband_leg_index":   float64(i),
			"subband_hash_suite":  string(suite),
			"subband_merkle_path": ph,
			"nbf":                 float64(bands[i].NotBefore),
			"exp":                 float64(bands[i].Expiry),
		}
	}

	// Happy path: every genuine member verifies.
	for i := 0; i < 3; i++ {
		if err := checkSubbandMembership(parentClaims, catScope, member(i), bands[i].Scope); err != nil {
			t.Fatalf("member %d rejected: %v", i, err)
		}
	}

	// A child with no cumulative budget is unaffected (the common case).
	if err := checkSubbandMembership(parentClaims, catScope, map[string]any{}, tbac.Scope{"max_amount": 5, "currency": "USD"}); err != nil {
		t.Fatalf("a non-cumulative child must pass: %v", err)
	}

	// Self-granted budget: a cumulative child whose parent committed no division.
	if err := checkSubbandMembership(map[string]any{}, catScope, member(0), bands[0].Scope); err == nil {
		t.Fatal("a cumulative child with no committed division above it must be refused")
	}

	// Mismatched leg index: band 0's tuple/path presented as leg 2.
	badLeg := member(0)
	badLeg["subband_leg_index"] = float64(2)
	if err := checkSubbandMembership(parentClaims, catScope, badLeg, bands[0].Scope); err == nil {
		t.Fatal("a mismatched leg index must be refused")
	}

	// Inflated budget: child claims more cumulative than the committed leaf.
	if err := checkSubbandMembership(parentClaims, catScope, member(0), tbac.Scope{"max_cumulative": 999, "currency": "USD"}); err == nil {
		t.Fatal("an inflated cumulative budget must be refused")
	}

	// Wrong root: child points at an attacker root the parent never committed.
	badRoot := member(0)
	var other [32]byte
	other[0] = 0xFF
	badRoot["subband_group_root"] = hex.EncodeToString(other[:])
	if err := checkSubbandMembership(parentClaims, catScope, badRoot, bands[0].Scope); err == nil {
		t.Fatal("a child root differing from the parent's committed root must be refused")
	}

	// Widened window: same budget/index but a window the committed leaf did not have.
	badWin := member(0)
	badWin["exp"] = float64(25)
	if err := checkSubbandMembership(parentClaims, catScope, badWin, bands[0].Scope); err == nil {
		t.Fatal("a widened window must be refused")
	}
}
