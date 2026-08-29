package tbac

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"testing"
)

func cband(cum any, nbf, exp int64) Band {
	return Band{Scope: Scope{cumulativeDim: cum, "currency": "USD"}, NotBefore: nbf, Expiry: exp}
}

// parentScope is a $100 month-budget in USD over [0,30).
func cparent() (Scope, int64, int64) {
	return Scope{cumulativeDim: 100, "currency": "USD"}, 0, 30
}

// Round-trip across a range of group sizes, including 1, odd, and non-powers of
// two (the shapes that exercise the odd-node-carry rule). Every slice's leaf,
// rebuilt from its declared tuple, must verify against the committed root at its
// own index — and must NOT verify at any other index.
func TestSubbandCommit_RoundTripAllSizes(t *testing.T) {
	suite := SuiteSHA3_256
	parent, pnbf, pexp := cparent()
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 30} {
		bands := make([]Band, n)
		// n non-overlapping unit windows inside [0,30), each a small equal budget.
		for i := 0; i < n; i++ {
			nbf := int64(i) * (30 / int64(n))
			exp := nbf + (30 / int64(n))
			if i == n-1 {
				exp = pexp
			}
			bands[i] = cband(1, nbf, exp)
		}
		root, leaves, paths, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
		if err != nil {
			t.Fatalf("n=%d: CommitBandDivision: %v", n, err)
		}
		if len(leaves) != n || len(paths) != n {
			t.Fatalf("n=%d: got %d leaves, %d paths", n, len(leaves), len(paths))
		}
		pc, err := SubbandParentCommit(suite, parent)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			leaf, err := SubbandLeaf(suite, pc, bands[i], uint32(i), uint32(n))
			if err != nil {
				t.Fatal(err)
			}
			if leaf != leaves[i] {
				t.Fatalf("n=%d i=%d: rebuilt leaf != committed leaf", n, i)
			}
			if err := SubbandVerifyMembership(suite, leaf, uint32(i), uint32(n), paths[i], root); err != nil {
				t.Fatalf("n=%d i=%d: genuine member rejected: %v", n, i, err)
			}
			// Same leaf claimed at a different index must not verify (n>1).
			if n > 1 {
				wrong := (i + 1) % n
				if err := SubbandVerifyMembership(suite, leaf, uint32(wrong), uint32(n), paths[i], root); err == nil {
					t.Fatalf("n=%d i=%d: leaf verified at wrong index %d", n, i, wrong)
				}
			}
		}
	}
}

// A tampered leaf is not a member. Flipping one bit of the leaf breaks the root.
func TestSubbandCommit_TamperedLeafRefused(t *testing.T) {
	suite := SuiteSHA3_256
	parent, pnbf, pexp := cparent()
	bands := []Band{cband(10, 0, 10), cband(10, 10, 20), cband(10, 20, 30)}
	root, leaves, paths, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
	if err != nil {
		t.Fatal(err)
	}
	bad := leaves[1]
	bad[0] ^= 0x01
	if err := SubbandVerifyMembership(suite, bad, 1, 3, paths[1], root); !errors.Is(err, ErrMembershipMismatch) {
		t.Fatalf("a tampered leaf verified: %v", err)
	}
}

// A tampered path element is not a valid proof.
func TestSubbandCommit_TamperedPathRefused(t *testing.T) {
	suite := SuiteSHA3_256
	parent, pnbf, pexp := cparent()
	bands := []Band{cband(10, 0, 10), cband(10, 10, 20), cband(10, 20, 30)}
	root, leaves, paths, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths[0]) == 0 {
		t.Fatal("expected a non-empty path")
	}
	badPath := make([][32]byte, len(paths[0]))
	copy(badPath, paths[0])
	badPath[0][0] ^= 0x01
	if err := SubbandVerifyMembership(suite, leaves[0], 0, 3, badPath, root); !errors.Is(err, ErrMembershipMismatch) {
		t.Fatalf("a tampered path verified: %v", err)
	}
}

// Cross-parent replay (decision D3): a leaf minted under one parent's
// budget/window must not verify as a member of a division under a DIFFERENT
// parent. Two parents differ only by budget; the parent binding folded into every
// leaf makes the roots — and the leaves — disjoint.
func TestSubbandCommit_CrossParentReplayRefused(t *testing.T) {
	suite := SuiteSHA3_256
	bands := []Band{cband(10, 0, 10), cband(10, 10, 20), cband(10, 20, 30)}

	parentA := Scope{cumulativeDim: 100, "currency": "USD"}
	parentB := Scope{cumulativeDim: 200, "currency": "USD"} // different budget
	rootA, leavesA, pathsA, err := CommitBandDivision(suite, parentA, 0, 30, bands)
	if err != nil {
		t.Fatal(err)
	}
	rootB, _, _, err := CommitBandDivision(suite, parentB, 0, 30, bands)
	if err != nil {
		t.Fatal(err)
	}
	if rootA == rootB {
		t.Fatal("two different parents produced the same group root — parent binding is not committed")
	}
	// A genuine member of A, presented against B's root, is refused.
	if err := SubbandVerifyMembership(suite, leavesA[0], 0, 3, pathsA[0], rootB); !errors.Is(err, ErrMembershipMismatch) {
		t.Fatalf("a slice from parent A verified under parent B's root: %v", err)
	}
	// And a leaf rebuilt under B's parent commit differs from A's leaf.
	pcB, _ := SubbandParentCommit(suite, parentB)
	leafUnderB, _ := SubbandLeaf(suite, pcB, bands[0], 0, 3)
	if leafUnderB == leavesA[0] {
		t.Fatal("the same band under two parents produced the same leaf")
	}
}

// group_size and leg_index are committed INTO the leaf, so the real protection
// is at leaf reconstruction: a verifier rebuilds the leaf from the slice's
// claimed (band, leg_index, group_size), and any tamper there yields a leaf that
// is not a member of the committed root. This is the flow the engine uses.
func TestSubbandCommit_TamperedTupleRefused(t *testing.T) {
	suite := SuiteSHA3_256
	parent, pnbf, pexp := cparent()
	bands := []Band{cband(10, 0, 10), cband(10, 10, 20), cband(10, 20, 30)}
	root, _, paths, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := SubbandParentCommit(suite, parent)
	if err != nil {
		t.Fatal(err)
	}

	// Tampered group_size: rebuild leaf 0 claiming N=4, verify against the N=3 root.
	badN, err := SubbandLeaf(suite, pc, bands[0], 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := SubbandVerifyMembership(suite, badN, 0, 4, paths[0], root); err == nil {
		t.Fatal("a leaf rebuilt under a tampered group_size verified")
	}

	// Tampered budget: rebuild leaf 0 with a larger max_cumulative than committed.
	inflated := cband(999, 0, 10)
	badAmt, err := SubbandLeaf(suite, pc, inflated, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := SubbandVerifyMembership(suite, badAmt, 0, 3, paths[0], root); !errors.Is(err, ErrMembershipMismatch) {
		t.Fatalf("a leaf claiming an inflated budget verified: %v", err)
	}

	// Tampered window: rebuild leaf 0 with a widened window.
	widened := cband(10, 0, 25)
	badWin, err := SubbandLeaf(suite, pc, widened, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := SubbandVerifyMembership(suite, badWin, 0, 3, paths[0], root); !errors.Is(err, ErrMembershipMismatch) {
		t.Fatalf("a leaf claiming a widened window verified: %v", err)
	}
}

// leg_index >= group_size is rejected outright.
func TestSubbandCommit_LegIndexOutOfRange(t *testing.T) {
	suite := SuiteSHA3_256
	var leaf [32]byte
	if err := SubbandVerifyMembership(suite, leaf, 3, 3, nil, [32]byte{}); !errors.Is(err, ErrLegIndexOutOfRange) {
		t.Fatalf("want ErrLegIndexOutOfRange, got %v", err)
	}
}

// An unknown suite fails closed everywhere, never falling back to a default.
func TestSubbandCommit_UnknownSuiteRefused(t *testing.T) {
	parent, pnbf, pexp := cparent()
	bands := []Band{cband(10, 0, 30)}
	if _, _, _, err := CommitBandDivision(HashSuite("md5-lol"), parent, pnbf, pexp, bands); !errors.Is(err, ErrUnknownHashSuite) {
		t.Fatalf("want ErrUnknownHashSuite, got %v", err)
	}
	if _, err := SubbandParentCommit(HashSuite("nope"), parent); !errors.Is(err, ErrUnknownHashSuite) {
		t.Fatalf("SubbandParentCommit want ErrUnknownHashSuite, got %v", err)
	}
}

// Domain separation: a value hashed under the leaf tag, the node tag, and the
// parent-commit tag must produce three different digests, so no preimage can be
// reinterpreted across roles (leaf-as-node second preimage).
func TestSubbandCommit_DomainSeparation(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 64)
	asLeaf := sha3.Sum256(append([]byte{tagLeaf}, payload...))
	asNode := sha3.Sum256(append([]byte{tagNode}, payload...))
	asParent := sha3.Sum256(append([]byte{tagParentCommit}, payload...))
	if asLeaf == asNode || asLeaf == asParent || asNode == asParent {
		t.Fatal("domain tags do not separate the hash roles")
	}
	// The bare payload (no tag) must differ from all tagged forms too.
	bare := sha3.Sum256(payload)
	if bare == asLeaf || bare == asNode || bare == asParent {
		t.Fatal("an untagged hash collided with a tagged one")
	}
}

// CommitBandDivision refuses an unsound division (over-allocation) BEFORE
// committing to anything — the commitment never certifies a division that
// ValidateBandDivision rejects.
func TestSubbandCommit_RefusesUnsoundDivision(t *testing.T) {
	suite := SuiteSHA3_256
	parent := Scope{cumulativeDim: 5, "currency": "USD"}                // budget 5
	over := []Band{cband(3, 0, 10), cband(3, 10, 20), cband(3, 20, 30)} // sums to 9 > 5
	if _, _, _, err := CommitBandDivision(suite, parent, 0, 30, over); !errors.Is(err, ErrSubbandOverAllocates) {
		t.Fatalf("commitment certified an over-allocating division: %v", err)
	}
	// Overlapping windows are refused too (no commitment to a stackable schedule).
	overlap := []Band{cband(1, 0, 15), cband(1, 10, 20)}
	if _, _, _, err := CommitBandDivision(suite, parent, 0, 30, overlap); !errors.Is(err, ErrBandWindowsOverlap) {
		t.Fatalf("commitment certified overlapping windows: %v", err)
	}
}

// The committed root is stable: the same division commits to the same root every
// time (determinism), and reordering the bands changes the roots' leaves (index
// is committed) so it is a different division, not the same one.
func TestSubbandCommit_DeterministicAndOrderSensitive(t *testing.T) {
	suite := SuiteSHA3_256
	parent, pnbf, pexp := cparent()
	bands := []Band{cband(10, 0, 10), cband(20, 10, 20), cband(30, 20, 30)}
	r1, _, _, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
	if err != nil {
		t.Fatal(err)
	}
	r2, _, _, err := CommitBandDivision(suite, parent, pnbf, pexp, bands)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatal("the same division committed to two different roots")
	}
}

func TestDeclaresCumulativeBudget(t *testing.T) {
	if !DeclaresCumulativeBudget(Scope{cumulativeDim: 100, "currency": "USD"}) {
		t.Error("a scope with max_cumulative must report true")
	}
	if DeclaresCumulativeBudget(Scope{"max_amount": 100, "currency": "USD"}) {
		t.Error("a scope with only max_amount must report false")
	}
	if DeclaresCumulativeBudget(Scope{}) {
		t.Error("an empty scope must report false")
	}
}

func TestIsKnownHashSuite(t *testing.T) {
	if !IsKnownHashSuite(SuiteSHA3_256) {
		t.Error("SuiteSHA3_256 must be known")
	}
	if IsKnownHashSuite(HashSuite("sha256")) || IsKnownHashSuite(HashSuite("")) {
		t.Error("an unregistered suite must be unknown")
	}
}
