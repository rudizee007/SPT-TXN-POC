package tbac

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
)

// ── Sub-band group-root commitment (design §7.2 / SUBBAND-GROUP-ROOT-DESIGN) ──
//
// A parent that divides its max_cumulative budget commits, in its signed claims,
// to ONE Merkle root over the N slice leaves; every spendable slice proves
// membership. ValidateBandDivision proves the leaves' budgets sum to <= the
// parent budget, so the committed set IS the whole cumulative authority and its
// total is bounded BY CONSTRUCTION — statelessly, offline, with no (N+1)th slice
// and no second division of the same parent.
//
// The hash is a VERSIONED suite carried in the parent's subband_hash_suite
// claim, so migrating to another hash is a version bump rather than a redesign:
// existing roots stay valid under the suite that made them. We start on SHA3-256
// (a Keccak sponge — structurally unrelated to the SHA-2 family the RFC 6962
// audit-log Merkle uses, so a whole-family break in one does not take the other).

// HashSuite names the hash backing a group-root commitment. It is stored beside
// the root so a verifier hashes with the same function the issuer committed with.
type HashSuite string

// SuiteSHA3_256 is the launch suite. Add a suite here (never repurpose one) to
// migrate; the label in subband_hash_suite selects it.
const SuiteSHA3_256 HashSuite = "sha3-256"

// Domain separation: a leaf can never be reinterpreted as an internal node or as
// a parent-budget commitment, because each is hashed under a distinct one-byte
// prefix. Without this, a 64-byte leaf preimage could be presented as an internal
// node (or vice versa) and the tree's second-preimage resistance would leak.
const (
	tagLeaf         byte = 0x00
	tagNode         byte = 0x01
	tagParentCommit byte = 0x02
)

var (
	// ErrUnknownHashSuite: a suite label no build understands. Fails closed —
	// an unrecognized suite is never treated as "probably fine, use the default".
	ErrUnknownHashSuite = errors.New("unknown sub-band hash suite")
	// ErrEmptyGroup: a division with no leaves has no root to commit.
	ErrEmptyGroup = errors.New("sub-band group has no leaves")
	// ErrLegIndexOutOfRange: a slice claims a position outside [0, group_size).
	ErrLegIndexOutOfRange = errors.New("sub-band leg index out of range for group size")
	// ErrGroupSizeMismatch: group_size disagrees with the committed leaf count.
	ErrGroupSizeMismatch = errors.New("sub-band group size does not match the committed leaf count")
	// ErrMembershipMismatch: the recomputed root does not equal the committed
	// root — the slice is not a member of the committed division. This is the
	// refusal that stops an (N+1)th slice and a second division.
	ErrMembershipMismatch = errors.New("sub-band leaf is not a member of the committed group root")
	// ErrCumulativeNotNumeric: a scope offered for commitment has a
	// non-numeric max_cumulative (ValidateIssuance should have caught it upstream;
	// fail closed here rather than commit to a value we cannot canonicalize).
	ErrCumulativeNotNumeric = errors.New("sub-band commitment: max_cumulative is not numeric")
)

// DeclaresCumulativeBudget reports whether a scope carries a max_cumulative
// budget — the dimension a group-root commitment divides. Issuance uses it to
// refuse a subband commitment on a scope that has no cumulative budget to
// divide, and the verifier uses it to decide when the per-hop membership check
// applies. It is the exported view of the internal dimension name so callers in
// cattoken / cttoken / verifier need not hardcode the string.
func DeclaresCumulativeBudget(s Scope) bool {
	_, ok := s[cumulativeDim]
	return ok
}

// IsKnownHashSuite reports whether a suite label is one this build understands.
// Issuance uses it to fail closed — a CAT is never signed committing to a suite
// no verifier can reproduce.
func IsKnownHashSuite(s HashSuite) bool {
	_, err := s.sum(nil)
	return err == nil
}

// sum dispatches the suite to its hash. New suites slot in here.
func (s HashSuite) sum(data []byte) ([32]byte, error) {
	switch s {
	case SuiteSHA3_256:
		return sha3.Sum256(data), nil
	default:
		return [32]byte{}, fmt.Errorf("%w: %q", ErrUnknownHashSuite, s)
	}
}

// canonicalMoney renders a money value as the exact, normalized big.Rat string
// (lowest terms), so 3, "3" and 3.0 all commit identically and no precision is
// lost for large values. This is the single canonical form the commitment binds.
func canonicalMoney(v any) (string, error) {
	r, ok := toRat(v)
	if !ok {
		return "", ErrCumulativeNotNumeric
	}
	return r.RatString(), nil
}

// lp appends a length-prefixed byte string (u32 big-endian length, then bytes),
// so concatenated variable-length fields are unambiguous.
func lp(buf []byte, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf = append(buf, n[:]...)
	return append(buf, b...)
}

func be64(buf []byte, v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return append(buf, b[:]...)
}

func be32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

// SubbandParentCommit binds a division to ONE parent's budget and currency. It
// is folded into every leaf so a leaf minted for a $100/USD budget cannot be
// replayed as a member of a division of a different budget or currency (design
// §2, decision D3).
//
// It deliberately does NOT bind the parent's validity window. The commitment
// must be reconstructible by a stateless verifier from the parent token alone,
// and a division's window is a caller concept not carried on the token; binding
// it would force the window onto the token or make the leaf unverifiable. Cross-
// parent replay is already prevented independently: a slice is cryptographically
// pinned to its issuing CAT by the chain's spt_cat_ref / spt_parent_hash links,
// so it cannot be presented under a different parent even when two parents share
// a budget and currency.
func SubbandParentCommit(suite HashSuite, parent Scope) ([32]byte, error) {
	budget, err := canonicalMoney(parent[cumulativeDim])
	if err != nil {
		return [32]byte{}, err
	}
	currency, _ := parent["currency"].(string)
	var pre []byte
	pre = append(pre, tagParentCommit)
	pre = lp(pre, []byte(currency))
	pre = lp(pre, []byte(budget))
	return suite.sum(pre)
}

// SubbandLeaf is the committed tuple of one slice: its parent binding, its
// cumulative budget and currency, its window, and its position (legIndex of
// groupSize). Deterministic and length-unambiguous.
func SubbandLeaf(suite HashSuite, parentCommit [32]byte, band Band, legIndex, groupSize uint32) ([32]byte, error) {
	cum, err := canonicalMoney(band.Scope[cumulativeDim])
	if err != nil {
		return [32]byte{}, err
	}
	currency, _ := band.Scope["currency"].(string)
	var pre []byte
	pre = append(pre, tagLeaf)
	pre = append(pre, parentCommit[:]...)
	pre = lp(pre, []byte(currency))
	pre = lp(pre, []byte(cum))
	pre = be64(pre, band.NotBefore)
	pre = be64(pre, band.Expiry)
	pre = be32(pre, legIndex)
	pre = be32(pre, groupSize)
	return suite.sum(pre)
}

// node hashes two children under the internal-node tag.
func (s HashSuite) node(left, right [32]byte) ([32]byte, error) {
	pre := make([]byte, 0, 1+64)
	pre = append(pre, tagNode)
	pre = append(pre, left[:]...)
	pre = append(pre, right[:]...)
	return s.sum(pre)
}

// SubbandGroupRoot builds the Merkle root over the leaves in index order. An odd
// node at a level is carried up unchanged; group_size is committed separately so
// the tree shape is never ambiguous.
func SubbandGroupRoot(suite HashSuite, leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, ErrEmptyGroup
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				n, err := suite.node(level[i], level[i+1])
				if err != nil {
					return [32]byte{}, err
				}
				next = append(next, n)
			} else {
				next = append(next, level[i]) // carry the odd node up
			}
		}
		level = next
	}
	return level[0], nil
}

// SubbandMerklePath returns the sibling hashes on the path from leaf `index` to
// the root, bottom-up. Orientation is not stored: the verifier derives it from
// the index and group_size, so the path reveals only sibling hashes, never the
// other slices' tuples ("one of a fixed set without seeing the set").
func SubbandMerklePath(suite HashSuite, leaves [][32]byte, index int) ([][32]byte, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyGroup
	}
	if index < 0 || index >= len(leaves) {
		return nil, ErrLegIndexOutOfRange
	}
	var path [][32]byte
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	pos := index
	for len(level) > 1 {
		if sib := pos ^ 1; sib < len(level) {
			path = append(path, level[sib])
		} // else: pos is an unpaired odd node, carried up, no sibling
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				n, err := suite.node(level[i], level[i+1])
				if err != nil {
					return nil, err
				}
				next = append(next, n)
			} else {
				next = append(next, level[i])
			}
		}
		level = next
		pos /= 2
	}
	return path, nil
}

// SubbandVerifyMembership recomputes the root from a single leaf, its position,
// and the sibling path, and checks it equals the committed root. It reconstructs
// the per-level sizes from groupSize alone, so it knows exactly which levels
// carried an odd node (no sibling) — the same shape the issuer built. Returns nil
// only when the leaf is genuinely member `legIndex` of the committed group.
func SubbandVerifyMembership(suite HashSuite, leaf [32]byte, legIndex, groupSize uint32, path [][32]byte, root [32]byte) error {
	if groupSize == 0 {
		return ErrEmptyGroup
	}
	if legIndex >= groupSize {
		return ErrLegIndexOutOfRange
	}
	h := leaf
	pos := legIndex
	levelLen := groupSize
	pi := 0
	for levelLen > 1 {
		if sib := pos ^ 1; sib < levelLen {
			if pi >= len(path) {
				return fmt.Errorf("%w: path too short", ErrMembershipMismatch)
			}
			var n [32]byte
			var err error
			if pos%2 == 0 {
				n, err = suite.node(h, path[pi])
			} else {
				n, err = suite.node(path[pi], h)
			}
			if err != nil {
				return err
			}
			h = n
			pi++
		} // else: odd node carried up unchanged, no sibling consumed
		pos /= 2
		levelLen = (levelLen + 1) / 2
	}
	if pi != len(path) {
		return fmt.Errorf("%w: path longer than the tree", ErrMembershipMismatch)
	}
	if h != root {
		return ErrMembershipMismatch
	}
	return nil
}

// CommitBandDivision is the issuance-side helper: it validates the division
// (ValidateBandDivision — Σ slices <= parent budget, windows non-overlapping and
// inside the parent) and, only if sound, builds the parent commitment, the N
// leaves, the group root and each slice's membership path. Everything a caller
// needs to mint the parent's subband_group_root claim and each slice's
// membership claims, computed once, atomically.
func CommitBandDivision(suite HashSuite, parent Scope, parentNbf, parentExp int64, bands []Band) (root [32]byte, leaves [][32]byte, paths [][][32]byte, err error) {
	if _, err = suite.sum(nil); err != nil { // reject an unknown suite before any work
		return [32]byte{}, nil, nil, err
	}
	if _, err = ValidateBandDivision(parent, parentNbf, parentExp, bands); err != nil {
		return [32]byte{}, nil, nil, err
	}
	parentCommit, err := SubbandParentCommit(suite, parent)
	if err != nil {
		return [32]byte{}, nil, nil, err
	}
	n := uint32(len(bands))
	leaves = make([][32]byte, len(bands))
	for i, b := range bands {
		leaf, lerr := SubbandLeaf(suite, parentCommit, b, uint32(i), n)
		if lerr != nil {
			return [32]byte{}, nil, nil, lerr
		}
		leaves[i] = leaf
	}
	root, err = SubbandGroupRoot(suite, leaves)
	if err != nil {
		return [32]byte{}, nil, nil, err
	}
	paths = make([][][32]byte, len(bands))
	for i := range bands {
		p, perr := SubbandMerklePath(suite, leaves, i)
		if perr != nil {
			return [32]byte{}, nil, nil, perr
		}
		paths[i] = p
	}
	return root, leaves, paths, nil
}
