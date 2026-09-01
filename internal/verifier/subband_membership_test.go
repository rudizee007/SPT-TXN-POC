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

	// Happy path: every genuine member verifies, and reports its identity —
	// the committed root and leg index, never the jti — for the single-use record.
	for i := 0; i < 3; i++ {
		id, err := checkSubbandMembership(parentClaims, catScope, member(i), bands[i].Scope)
		if err != nil {
			t.Fatalf("member %d rejected: %v", i, err)
		}
		if id == nil || id.root != rootHex || id.legIndex != int64(i) || id.expiry != bands[i].Expiry {
			t.Fatalf("member %d identity wrong: %+v", i, id)
		}
	}

	// A child of a BUDGETED parent that declares no cumulative budget is
	// refused. Under Contains a child may drop any dimension, and the budget
	// is the one dimension that must not be droppable.
	if _, err := checkSubbandMembership(parentClaims, catScope, map[string]any{}, tbac.Scope{"max_amount": 5, "currency": "USD"}); err == nil {
		t.Fatal("a non-cumulative child of a budgeted parent must be refused")
	}
	// The trigger is the parent's DECLARATION, not only a committed root: a
	// parent that declares max_cumulative and commits nothing authorizes no
	// children at all.
	if _, err := checkSubbandMembership(map[string]any{}, catScope, map[string]any{}, tbac.Scope{"currency": "USD"}); err == nil {
		t.Fatal("a child of a parent that declares a budget but committed no division must be refused")
	}
	if _, err := checkSubbandMembership(map[string]any{}, catScope, member(0), bands[0].Scope); err == nil {
		t.Fatal("a slice under a parent that committed no division must be refused")
	}

	// The common case, correctly stated: an UNBUDGETED parent, a non-cumulative
	// child. Untouched.
	plainParent := tbac.Scope{"max_amount": 100, "currency": "USD"}
	id, err := checkSubbandMembership(map[string]any{}, plainParent, map[string]any{}, tbac.Scope{"max_amount": 5, "currency": "USD"})
	if err != nil || id != nil {
		t.Fatalf("a non-cumulative child of an unbudgeted parent must pass with no slice identity: id=%v err=%v", id, err)
	}

	// Self-granted budget: a cumulative child whose parent is unbudgeted.
	if _, err := checkSubbandMembership(map[string]any{}, plainParent, member(0), bands[0].Scope); err == nil {
		t.Fatal("a cumulative child under an unbudgeted parent must be refused")
	}

	// Mismatched leg index: band 0's tuple/path presented as leg 2.
	badLeg := member(0)
	badLeg["subband_leg_index"] = float64(2)
	if _, err := checkSubbandMembership(parentClaims, catScope, badLeg, bands[0].Scope); err == nil {
		t.Fatal("a mismatched leg index must be refused")
	}

	// Inflated budget: child claims more cumulative than the committed leaf.
	if _, err := checkSubbandMembership(parentClaims, catScope, member(0), tbac.Scope{"max_cumulative": 999, "currency": "USD"}); err == nil {
		t.Fatal("an inflated cumulative budget must be refused")
	}

	// Wrong root: child points at an attacker root the parent never committed.
	badRoot := member(0)
	var other [32]byte
	other[0] = 0xFF
	badRoot["subband_group_root"] = hex.EncodeToString(other[:])
	if _, err := checkSubbandMembership(parentClaims, catScope, badRoot, bands[0].Scope); err == nil {
		t.Fatal("a child root differing from the parent's committed root must be refused")
	}

	// Widened window: same budget/index but a window the committed leaf did not have.
	badWin := member(0)
	badWin["exp"] = float64(25)
	if _, err := checkSubbandMembership(parentClaims, catScope, badWin, bands[0].Scope); err == nil {
		t.Fatal("a widened window must be refused")
	}
}
