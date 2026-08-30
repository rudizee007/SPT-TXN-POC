package audit

// merkle_rfc6962_test.go — known-answer and property tests for the Merkle
// tree in merkle.go, validated against RFC 6962 §2.1 / §2.1.1 rather than
// against this package's own output.
//
// # Why this file exists
//
// merkle_proof_test.go asserts that this implementation agrees with itself:
// MerkleProof feeds VerifyInclusion and both are built from the same
// hashLeaf/hashInterior pair. That is a round-trip test. It passes unchanged
// if the leaf and interior prefixes are swapped, if the prefixes are dropped
// entirely, or if left and right siblings are exchanged — every one of which
// is an interoperability break, and the last of which is a second-preimage
// hazard. A transparency log whose roots do not match RFC 6962 cannot be
// checked by any third-party auditor tooling, which is the entire point of
// publishing one.
//
// # Where the expected values come from
//
// RFC 6962 §2.1 defines the Merkle Tree Hash:
//
//	MTH({})      = SHA-256()
//	MTH({d(0)})  = SHA-256(0x00 || d(0))
//	MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//	             where k is the largest power of two strictly less than n
//
// §2.1.1 defines the audit path PATH(m, D[n]) by the same recursion.
//
// The vectors below are computed from those two definitions over leaves whose
// entry hashes are deliberately trivial — entry i has a 32-byte hash equal to
// the byte i repeated 32 times — so any reviewer can reproduce every constant
// with coreutils alone and without running this code. For example:
//
//	L0 = SHA-256(0x00 || 32 x 0x00):
//	     head -c 33 /dev/zero | sha256sum
//	     -> 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
//
//	root(n=2) = SHA-256(0x01 || L0 || L1):
//	     { printf '\x01'; printf '<L0hex><L1hex>' | xxd -r -p; } | sha256sum
//	     -> 28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444
//
// Every constant in this file was produced twice by independent means (a
// literal transcription of the RFC recursion, and the shell composition
// above) and the two agreed. Nothing here was read out of merkle.go.
//
// # Deliberate omissions
//
//   - There is NO golden-file update mechanism and there must never be one.
//     A regeneration flag would let a future change to merkle.go rewrite its
//     own specification.
//   - MTH({}) is NOT asserted. RFC 6962 §2.1 defines it as SHA-256 of the
//     empty string (e3b0c442...b855); MerkleRoot returns nil for empty input.
//     That divergence is reported to the maintainer rather than frozen here as
//     expected behaviour. What IS asserted is the security-relevant part: an
//     empty tree proves nothing (TestVerifyInclusion_EmptyTreeProvesNothing).
//   - Consistency proofs (RFC 6962 §2.1.2) are not tested because this package
//     does not implement them; Witness.Cosign recomputes prefix roots from the
//     full log instead (witness.go, documented there).
//
// # Anti-vacuity discipline
//
// Every test in this file asserts BOTH directions — what must verify and what
// must not — and reports the number of cases it actually exercised in each
// direction, failing if either count is below the expected minimum. A test
// that silently stops covering anything is worse than no test: a one-sided
// suite once let an SSRF filter reject the entire IPv4 space unnoticed,
// because nothing ever asserted that a legitimate address was accepted.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
)

// ── RFC 6962 reference oracle (test-only) ────────────────────────────────────
//
// A literal transcription of the recursions in RFC 6962 §2.1 and §2.1.1. It
// shares no code with merkle.go: it splits top-down at the largest power of
// two below n, where merkle.go pairs bottom-up and promotes an unpaired node.
// The two constructions are supposed to describe the same tree; proving that
// over many shapes is the point of TestMerkleRoot_RFC6962_Differential.
//
// The oracle is not trusted on its own — TestRFC6962_Oracle_MatchesHandDerived
// pins it to the hex constants above before any differential test uses it.

func rfcLeafData(i int) []byte { return bytes.Repeat([]byte{byte(i)}, 32) }

func rfcLeaves(n int) [][]byte {
	d := make([][]byte, n)
	for i := range d {
		d[i] = rfcLeafData(i)
	}
	return d
}

// rfcEntries builds audit entries whose Hash fields are the rfcLeafData
// values, so MerkleRoot/MerkleProof operate on exactly the leaves the RFC
// oracle is given.
func rfcEntries(n int) []Entry {
	es := make([]Entry, n)
	for i := range es {
		es[i] = Entry{Seq: uint64(i + 1), Hash: rfcLeafData(i)}
	}
	return es
}

// rfcMTH is RFC 6962 §2.1, transcribed.
func rfcMTH(d [][]byte) []byte {
	n := len(d)
	if n == 0 {
		s := sha256.Sum256(nil) // MTH({}) = SHA-256()
		return s[:]
	}
	if n == 1 {
		s := sha256.Sum256(append([]byte{0x00}, d[0]...))
		return s[:]
	}
	k := 1
	for k*2 < n { // largest power of two strictly less than n
		k *= 2
	}
	left, right := rfcMTH(d[:k]), rfcMTH(d[k:])
	b := make([]byte, 0, 1+len(left)+len(right))
	b = append(b, 0x01)
	b = append(b, left...)
	b = append(b, right...)
	s := sha256.Sum256(b)
	return s[:]
}

// rfcPATH is RFC 6962 §2.1.1, transcribed. Returns sibling hashes leaf-upward.
func rfcPATH(m int, d [][]byte) [][]byte {
	n := len(d)
	if n == 1 && m == 0 {
		return nil
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	if m < k {
		return append(rfcPATH(m, d[:k]), rfcMTH(d[k:]))
	}
	return append(rfcPATH(m-k, d[k:]), rfcMTH(d[:k]))
}

// ── hand-derived constants ───────────────────────────────────────────────────

// rfcKATLeafHex[i] = SHA-256(0x00 || 32 x byte(i)), RFC 6962 §2.1 MTH({d(i)}).
var rfcKATLeafHex = [8]string{
	"7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9", // L0
	"dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e", // L1
	"cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa", // L2
	"acaa04663a8547a2f70c60cc18f9378796b13c4f9a08f70d6adae662365b30c6", // L3
	"1da033bf8927ed69376d91533748494f7f5e88c20603dede2afc9bfd43d46f17", // L4
	"f3ab555d06a67b08ab25039fdbe2a6fcb305c83bc165492ce81d3dea13ec1fbf", // L5
	"511c6562982c9bfa05ba4145ca5f2bba85a11a178a4131b5cebde26dd9ffe704", // L6
	"0a958d726efea0a71eb66b07c78738717b22d1fbd44756e82803a5ed461e13f9", // L7
}

// Interior nodes named for the leaf ranges they cover. N(a,b) = SHA-256(0x01 || a || b).
const (
	katN01   = "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444" // N(L0,L1)
	katN23   = "fc264939b1ac77b06378c5ece54a7b57b6b6c821eb80627bb674d8785c8dc8ca" // N(L2,L3)
	katN45   = "f1c176552a35e1d035f843d463220b6c85a90ea7f6644980630a6f71a3330ed3" // N(L4,L5)
	katN67   = "3ebd606fb49a3b46ea6025f6ca81438c59c6644eff2a753ae4b564ffbf0eb06a" // N(L6,L7)
	katN0123 = "fdea52008cdae79fa8bf806261959e23f5e11681646a2fa2bc9b5e56b32030a2" // N(N01,N23)  = MTH(D[0:4])
	katN4567 = "2e2d377b6f1faa1bbb10885d1232b4be13d48ed90a1db9d78ea9caf2c9e8ef43" // N(N45,N67)  = MTH(D[4:8])
	katN456  = "1f3f95843413191fe7521996b6b1e4147d703b1702c475a478ad25a6f6b415b4" // N(N45,L6)   = MTH(D[4:7])
)

// rfcKATRootHex maps tree size n to MTH(D[n]), derived as shown.
//
//	n=1: MTH({d0})                                    = L0
//	n=2: k=1  -> N(MTH[0:1], MTH[1:2])                = N(L0, L1)
//	n=3: k=2  -> N(MTH[0:2], MTH[2:3])                = N(N01, L2)
//	n=4: k=2  -> N(MTH[0:2], MTH[2:4])                = N(N01, N23)
//	n=5: k=4  -> N(MTH[0:4], MTH[4:5])                = N(N0123, L4)
//	n=7: k=4  -> N(MTH[0:4], MTH[4:7]); MTH[4:7] k=2  = N(N0123, N(N45, L6))
//	n=8: k=4  -> N(MTH[0:4], MTH[4:8])                = N(N0123, N4567)
var rfcKATRootHex = map[int]string{
	1: "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9",
	2: "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444",
	3: "ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620",
	4: "fdea52008cdae79fa8bf806261959e23f5e11681646a2fa2bc9b5e56b32030a2",
	5: "85e20cac1f02fda7bcdb2fc3f908568c57018c77815f1fa361acad13994f08bf",
	7: "7318881c41fce3c1de3640df8e8c110c93f43f686b74204a9d1ad5b8c71c2047",
	8: "f907f23f76aa01b755a614d31ef9832909f44638b4590073301e61e6d01f9a1d",
}

// katSizes are the sizes for which hand-derived vectors exist. n=0 is covered
// separately (see the "Deliberate omissions" note at the top of this file).
var katSizes = []int{1, 2, 3, 4, 5, 7, 8}

// rfcKATPathHex[n][m] is PATH(m, D[n]) per RFC 6962 §2.1.1, leaf-upward.
// Each element is named in the comment so the derivation can be followed.
var rfcKATPathHex = map[int][][]string{
	1: {
		{}, // PATH(0, D[1]) = {}
	},
	2: {
		{rfcKATLeafHex[1]}, // m=0: sibling L1
		{rfcKATLeafHex[0]}, // m=1: sibling L0
	},
	3: {
		{rfcKATLeafHex[1], rfcKATLeafHex[2]}, // m=0: L1, then MTH(D[2:3])=L2
		{rfcKATLeafHex[0], rfcKATLeafHex[2]}, // m=1: L0, then L2
		{katN01},                             // m=2: MTH(D[0:2])=N01
	},
	4: {
		{rfcKATLeafHex[1], katN23}, // m=0: L1, N23
		{rfcKATLeafHex[0], katN23}, // m=1: L0, N23
		{rfcKATLeafHex[3], katN01}, // m=2: L3, N01
		{rfcKATLeafHex[2], katN01}, // m=3: L2, N01
	},
	5: {
		{rfcKATLeafHex[1], katN23, rfcKATLeafHex[4]}, // m=0: L1, N23, MTH(D[4:5])=L4
		{rfcKATLeafHex[0], katN23, rfcKATLeafHex[4]}, // m=1
		{rfcKATLeafHex[3], katN01, rfcKATLeafHex[4]}, // m=2
		{rfcKATLeafHex[2], katN01, rfcKATLeafHex[4]}, // m=3
		{katN0123}, // m=4: MTH(D[0:4]) only
	},
	7: {
		{rfcKATLeafHex[1], katN23, katN456}, // m=0: L1, N23, MTH(D[4:7])
		{rfcKATLeafHex[0], katN23, katN456}, // m=1
		{rfcKATLeafHex[3], katN01, katN456}, // m=2
		{rfcKATLeafHex[2], katN01, katN456}, // m=3
		{rfcKATLeafHex[5], rfcKATLeafHex[6], katN0123}, // m=4: L5, MTH(D[6:7])=L6, MTH(D[0:4])
		{rfcKATLeafHex[4], rfcKATLeafHex[6], katN0123}, // m=5
		{katN45, katN0123},                             // m=6: MTH(D[4:6])=N45, MTH(D[0:4])
	},
	8: {
		{rfcKATLeafHex[1], katN23, katN4567}, // m=0
		{rfcKATLeafHex[0], katN23, katN4567}, // m=1
		{rfcKATLeafHex[3], katN01, katN4567}, // m=2
		{rfcKATLeafHex[2], katN01, katN4567}, // m=3
		{rfcKATLeafHex[5], katN67, katN0123}, // m=4
		{rfcKATLeafHex[4], katN67, katN0123}, // m=5
		{rfcKATLeafHex[7], katN45, katN0123}, // m=6
		{rfcKATLeafHex[6], katN45, katN0123}, // m=7
	},
}

// ── coverage accounting ──────────────────────────────────────────────────────

// rfcCoverage records how many cases a test actually exercised in each
// direction, so a reader can see the test was not vacuous over an empty set.
type rfcCoverage struct{ accepted, rejected int }

func (c *rfcCoverage) mustCover(t *testing.T, minAccepted, minRejected int, unit string) {
	t.Helper()
	t.Logf("denominator: %d must-ACCEPT and %d must-REJECT %s exercised", c.accepted, c.rejected, unit)
	if c.accepted < minAccepted {
		t.Fatalf("VACUOUS TEST: %d must-accept %s exercised, expected at least %d", c.accepted, unit, minAccepted)
	}
	if c.rejected < minRejected {
		t.Fatalf("VACUOUS TEST: %d must-reject %s exercised, expected at least %d", c.rejected, unit, minRejected)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant %q: %v", s, err)
	}
	return b
}

func decodeHexPath(t *testing.T, hs []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(hs))
	for i, s := range hs {
		out[i] = mustDecodeHex(t, s)
	}
	return out
}

func clonePath(p [][]byte) [][]byte {
	out := make([][]byte, len(p))
	for i, e := range p {
		out[i] = append([]byte(nil), e...)
	}
	return out
}

func pathHex(p [][]byte) string {
	parts := make([]string, len(p))
	for i, e := range p {
		parts[i] = hex.EncodeToString(e)
	}
	return "[" + fmt.Sprint(parts) + "]"
}

// ── 1. the oracle is pinned to the hand-derived constants ────────────────────

// TestRFC6962_Oracle_MatchesHandDerived checks the test-only RFC transcription
// against the hex constants derived by hand above, BEFORE any other test uses
// it as an oracle. If this fails, the oracle is wrong and every differential
// result below is meaningless.
func TestRFC6962_Oracle_MatchesHandDerived(t *testing.T) {
	var cov rfcCoverage

	for i, want := range rfcKATLeafHex {
		got := hex.EncodeToString(rfcMTH([][]byte{rfcLeafData(i)}))
		if got != want {
			t.Errorf("oracle MTH({d(%d)}) = %s, RFC derivation says %s", i, got, want)
		}
		cov.accepted++
	}
	for _, n := range katSizes {
		got := hex.EncodeToString(rfcMTH(rfcLeaves(n)))
		if got != rfcKATRootHex[n] {
			t.Errorf("oracle MTH(D[%d]) = %s, RFC derivation says %s", n, got, rfcKATRootHex[n])
		}
		cov.accepted++
		for m := 0; m < n; m++ {
			gotPath := rfcPATH(m, rfcLeaves(n))
			wantPath := decodeHexPath(t, rfcKATPathHex[n][m])
			if pathHex(gotPath) != pathHex(wantPath) {
				t.Errorf("oracle PATH(%d, D[%d]) = %s, RFC derivation says %s",
					m, n, pathHex(gotPath), pathHex(wantPath))
			}
			cov.accepted++
		}
	}

	// Other direction: the oracle must distinguish trees. Every pair of
	// distinct sizes must give distinct roots, so an oracle that returned a
	// constant would fail here rather than agree with everything.
	for _, n := range katSizes {
		for _, m := range katSizes {
			if n == m {
				continue
			}
			if bytes.Equal(rfcMTH(rfcLeaves(n)), rfcMTH(rfcLeaves(m))) {
				t.Errorf("oracle roots for n=%d and n=%d collide", n, m)
			}
			cov.rejected++
		}
	}

	// 8 leaves + 7 roots + 30 paths = 45 accepts; 7*6 = 42 rejects.
	cov.mustCover(t, 45, 42, "oracle vectors")
}

// ── 2. known-answer tests against merkle.go ──────────────────────────────────

// TestMerkleRoot_RFC6962_KnownAnswers pins MerkleRoot to the RFC-derived root
// for each hand-derived tree size, and asserts the roots are pairwise distinct
// so a degenerate implementation (constant, or ignoring its input) cannot pass.
func TestMerkleRoot_RFC6962_KnownAnswers(t *testing.T) {
	var cov rfcCoverage

	for _, n := range katSizes {
		got := hex.EncodeToString(MerkleRoot(rfcEntries(n)))
		if got != rfcKATRootHex[n] {
			t.Errorf("MerkleRoot(n=%d) = %s\n  RFC 6962 §2.1 derivation says %s", n, got, rfcKATRootHex[n])
		}
		cov.accepted++
	}
	for _, n := range katSizes {
		rn := MerkleRoot(rfcEntries(n))
		for _, m := range katSizes {
			if n == m {
				continue
			}
			if bytes.Equal(rn, MerkleRoot(rfcEntries(m))) {
				t.Errorf("MerkleRoot(n=%d) == MerkleRoot(n=%d): the root does not depend on the log", n, m)
			}
			cov.rejected++
		}
	}

	cov.mustCover(t, len(katSizes), len(katSizes)*(len(katSizes)-1), "root vectors")
}

// TestMerkleRoot_RFC6962_PrefixesAreCorrectAndNotSwapped pins the two domain
// separation tags to their RFC values through the public API. A round-trip
// test cannot see a prefix swap; this can.
func TestMerkleRoot_RFC6962_PrefixesAreCorrectAndNotSwapped(t *testing.T) {
	var cov rfcCoverage
	d0, d1 := rfcLeafData(0), rfcLeafData(1)

	// n=1 pins the LEAF prefix: MTH({d0}) = SHA-256(0x00 || d0).
	wantLeaf := sha256.Sum256(append([]byte{0x00}, d0...))
	if !bytes.Equal(MerkleRoot(rfcEntries(1)), wantLeaf[:]) {
		t.Error("single-leaf root is not SHA-256(0x00 || d(0)) — leaf prefix wrong")
	}
	cov.accepted++

	// Must NOT be the unprefixed hash, nor the interior prefix.
	for _, wrong := range [][]byte{
		func() []byte { s := sha256.Sum256(d0); return s[:] }(),
		func() []byte { s := sha256.Sum256(append([]byte{0x01}, d0...)); return s[:] }(),
	} {
		if bytes.Equal(MerkleRoot(rfcEntries(1)), wrong) {
			t.Errorf("single-leaf root equals a non-RFC construction %s", hex.EncodeToString(wrong))
		}
		cov.rejected++
	}

	// n=2 pins the INTERIOR prefix and the left/right order.
	l0 := sha256.Sum256(append([]byte{0x00}, d0...))
	l1 := sha256.Sum256(append([]byte{0x00}, d1...))
	right := append(append([]byte{0x01}, l0[:]...), l1[:]...)
	wantNode := sha256.Sum256(right)
	if !bytes.Equal(MerkleRoot(rfcEntries(2)), wantNode[:]) {
		t.Error("two-leaf root is not SHA-256(0x01 || L0 || L1) — interior prefix or order wrong")
	}
	cov.accepted++

	// Must NOT be the unprefixed concat, the leaf-prefixed concat, or the
	// order-swapped node. The last is the one a round-trip test cannot catch.
	for _, wrong := range [][]byte{
		func() []byte { s := sha256.Sum256(append(append([]byte{}, l0[:]...), l1[:]...)); return s[:] }(),
		func() []byte {
			s := sha256.Sum256(append(append([]byte{0x00}, l0[:]...), l1[:]...))
			return s[:]
		}(),
		func() []byte {
			s := sha256.Sum256(append(append([]byte{0x01}, l1[:]...), l0[:]...))
			return s[:]
		}(),
	} {
		if bytes.Equal(MerkleRoot(rfcEntries(2)), wrong) {
			t.Errorf("two-leaf root equals a non-RFC construction %s", hex.EncodeToString(wrong))
		}
		cov.rejected++
	}

	cov.mustCover(t, 2, 5, "prefix constructions")
}

// TestMerkleProof_RFC6962_KnownAuditPaths pins MerkleProof to the RFC-derived
// audit path, element for element, and checks that VerifyInclusion accepts the
// RFC path (not merely the path this package produced) and rejects that same
// path against every other tree's root.
func TestMerkleProof_RFC6962_KnownAuditPaths(t *testing.T) {
	var cov rfcCoverage

	for _, n := range katSizes {
		es := rfcEntries(n)
		root := mustDecodeHex(t, rfcKATRootHex[n])
		for m := 0; m < n; m++ {
			wantPath := decodeHexPath(t, rfcKATPathHex[n][m])

			got, err := MerkleProof(es, m)
			if err != nil {
				t.Fatalf("MerkleProof(n=%d, m=%d): %v", n, m, err)
			}
			if pathHex(got) != pathHex(wantPath) {
				t.Errorf("MerkleProof(n=%d, m=%d) = %s\n  RFC 6962 §2.1.1 derivation says %s",
					n, m, pathHex(got), pathHex(wantPath))
			}
			cov.accepted++

			// The RFC's own path must verify, independent of MerkleProof.
			if !VerifyInclusion(es[m].Hash, m, n, wantPath, root) {
				t.Errorf("VerifyInclusion rejected the RFC-derived path for n=%d m=%d", n, m)
			}
			cov.accepted++

			// ...and must not verify against any other tree's root.
			for _, other := range katSizes {
				if other == n {
					continue
				}
				if VerifyInclusion(es[m].Hash, m, n, wantPath, mustDecodeHex(t, rfcKATRootHex[other])) {
					t.Errorf("path for n=%d m=%d verified against the root of n=%d", n, m, other)
				}
				cov.rejected++
			}
		}
	}

	// 30 paths x 2 accepts = 60; 30 paths x 6 other roots = 180 rejects.
	cov.mustCover(t, 60, 180, "audit-path vectors")
}

// TestMerkleRoot_RFC6962_Differential compares this implementation against the
// RFC recursion over every tree size in 1..64 and every leaf index. The two
// build the tree in opposite directions — RFC splits top-down at the largest
// power of two, merkle.go pairs bottom-up and promotes unpaired nodes — so
// agreement across all these shapes is meaningful evidence, not a tautology.
func TestMerkleRoot_RFC6962_Differential(t *testing.T) {
	var cov rfcCoverage
	const maxN = 64

	for n := 1; n <= maxN; n++ {
		d := rfcLeaves(n)
		es := rfcEntries(n)

		if !bytes.Equal(MerkleRoot(es), rfcMTH(d)) {
			t.Errorf("n=%d: MerkleRoot = %s, RFC MTH = %s",
				n, hex.EncodeToString(MerkleRoot(es)), hex.EncodeToString(rfcMTH(d)))
		}
		cov.accepted++

		for m := 0; m < n; m++ {
			got, err := MerkleProof(es, m)
			if err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if pathHex(got) != pathHex(rfcPATH(m, d)) {
				t.Errorf("n=%d m=%d: MerkleProof = %s, RFC PATH = %s",
					n, m, pathHex(got), pathHex(rfcPATH(m, d)))
			}
			cov.accepted++
		}

		// Other direction: this tree's root must differ from every smaller
		// tree's root, so an implementation that ignored later entries would
		// be caught here rather than agreeing with the oracle vacuously.
		if n > 1 {
			if bytes.Equal(MerkleRoot(es), MerkleRoot(rfcEntries(n-1))) {
				t.Errorf("n=%d and n=%d produce the same root", n, n-1)
			}
			cov.rejected++
		}
	}

	// 64 roots + 2080 paths = 2144 accepts; 63 rejects.
	cov.mustCover(t, 2144, 63, "differential comparisons")
}

// TestMerkleRoot_NoLastNodeSelfDuplication is the CVE-2012-2459 property that
// merkle.go's header claims: an unpaired node is promoted unchanged, never
// hashed with itself. If it were self-duplicated, a tree of n leaves and a
// tree of n+1 leaves whose last leaf repeats would share a root, and the log
// would admit two different histories with one commitment.
func TestMerkleRoot_NoLastNodeSelfDuplication(t *testing.T) {
	var cov rfcCoverage

	for n := 2; n <= 32; n++ {
		es := rfcEntries(n)
		dup := append(append([]Entry{}, es...), Entry{Seq: uint64(n + 1), Hash: rfcLeafData(n - 1)})

		if bytes.Equal(MerkleRoot(es), MerkleRoot(dup)) {
			t.Errorf("n=%d: duplicating the last leaf did not change the root (CVE-2012-2459 shape)", n)
		}
		cov.rejected++

		// Positive control for the same input: the honest root is still the
		// RFC root, so the inequality above is not coming from a broken build.
		if !bytes.Equal(MerkleRoot(es), rfcMTH(rfcLeaves(n))) {
			t.Errorf("n=%d: root diverged from the RFC oracle", n)
		}
		cov.accepted++
	}

	cov.mustCover(t, 31, 31, "duplicate-last-leaf shapes")
}

// ── 3. property tests ────────────────────────────────────────────────────────

// TestProperty_EveryLeafIsProvable: for a tree of size n, every leaf's
// inclusion proof verifies against the root. The rejecting direction is
// asserted on the same inputs: an empty path must NOT verify for any leaf in
// a tree with more than one leaf, so a VerifyInclusion that returned true
// unconditionally fails this test.
func TestProperty_EveryLeafIsProvable(t *testing.T) {
	var cov rfcCoverage
	const maxN = 64

	for n := 1; n <= maxN; n++ {
		es := rfcEntries(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: MerkleProof: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, proof, root) {
				t.Errorf("n=%d i=%d: leaf is in the tree but does not prove", n, i)
			}
			cov.accepted++

			if n > 1 {
				if VerifyInclusion(es[i].Hash, i, n, nil, root) {
					t.Errorf("n=%d i=%d: an EMPTY audit path proved inclusion", n, i)
				}
				cov.rejected++
			}
		}
	}

	// 2080 accepts (sum 1..64); 2079 rejects.
	cov.mustCover(t, 2080, 2079, "leaf/proof pairs")
}

// TestProperty_ProofDoesNotTransferBetweenLeaves: a proof issued for leaf i
// never verifies for a different leaf j, whether j's hash is presented at
// index i or at its own index j. Both are checked, plus the accepting control
// that each leaf's own proof still verifies over the same inputs.
func TestProperty_ProofDoesNotTransferBetweenLeaves(t *testing.T) {
	var cov rfcCoverage
	const maxN = 24

	for n := 1; n <= maxN; n++ {
		es := rfcEntries(n)
		root := MerkleRoot(es)
		proofs := make([][][]byte, n)
		for i := range proofs {
			p, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			proofs[i] = p
		}

		for i := 0; i < n; i++ {
			if !VerifyInclusion(es[i].Hash, i, n, proofs[i], root) {
				t.Errorf("n=%d i=%d: own proof failed", n, i)
			}
			cov.accepted++

			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				// leaf j presented at index i under i's proof
				if VerifyInclusion(es[j].Hash, i, n, proofs[i], root) {
					t.Errorf("n=%d: leaf %d proved at index %d using index %d's path", n, j, i, i)
				}
				// leaf j presented at its own index j, but under i's proof
				if VerifyInclusion(es[j].Hash, j, n, proofs[i], root) {
					t.Errorf("n=%d: index %d's path proved leaf %d at index %d", n, i, j, j)
				}
				cov.rejected += 2
			}
		}
	}

	// 300 accepts (sum 1..24); 9200 rejects.
	cov.mustCover(t, 300, 9200, "leaf-substitution trials")
}

// TestProperty_AnySingleLeafBitFlipBreaksTheProof: mutating any single bit of
// a leaf's entry hash breaks that leaf's proof. All 32 bytes x 8 bits are
// exercised, so a verifier that compared only a prefix of the digest fails.
// The unmutated leaf is asserted to verify for every case, giving the
// accepting direction on the same inputs.
func TestProperty_AnySingleLeafBitFlipBreaksTheProof(t *testing.T) {
	var cov rfcCoverage

	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 16} {
		es := rfcEntries(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, proof, root) {
				t.Fatalf("n=%d i=%d: baseline proof does not verify; the mutations below prove nothing", n, i)
			}
			cov.accepted++

			for b := 0; b < len(es[i].Hash); b++ {
				for bit := 0; bit < 8; bit++ {
					mut := append([]byte(nil), es[i].Hash...)
					mut[b] ^= 1 << bit
					if VerifyInclusion(mut, i, n, proof, root) {
						t.Errorf("n=%d i=%d: flipping byte %d bit %d still proved inclusion", n, i, b, bit)
					}
					cov.rejected++
				}
			}
		}
	}

	// 46 leaves across the sizes above: 46 accepts, 46*256 = 11776 rejects.
	cov.mustCover(t, 46, 11776, "leaf bit-flips")
}

// TestProperty_AnySingleProofBitFlipBreaksVerification: mutating any single
// bit of any hash in the audit path breaks verification. Same both-direction
// discipline as above.
func TestProperty_AnySingleProofBitFlipBreaksVerification(t *testing.T) {
	var cov rfcCoverage

	for _, n := range []int{2, 3, 4, 5, 7, 8, 16} {
		es := rfcEntries(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, proof, root) {
				t.Fatalf("n=%d i=%d: baseline proof does not verify; the mutations below prove nothing", n, i)
			}
			cov.accepted++

			for e := 0; e < len(proof); e++ {
				for b := 0; b < len(proof[e]); b++ {
					for bit := 0; bit < 8; bit++ {
						mut := clonePath(proof)
						mut[e][b] ^= 1 << bit
						if VerifyInclusion(es[i].Hash, i, n, mut, root) {
							t.Errorf("n=%d i=%d: flipping path[%d] byte %d bit %d still verified", n, i, e, b, bit)
						}
						cov.rejected++
					}
				}
			}
		}
	}

	// 45 (n,i) pairs -> 45 accepts; 136 path elements x 256 bits = 34816 rejects.
	cov.mustCover(t, 45, 34816, "audit-path bit-flips")
}

// TestProperty_AppendDoesNotInvalidateOldProofs: append-only means a proof
// already handed to a relying party keeps verifying against the root it was
// issued under, forever. The rejecting direction is that the same old proof
// must NOT verify against the NEW root — otherwise the root would not be a
// commitment to the log's contents at all.
func TestProperty_AppendDoesNotInvalidateOldProofs(t *testing.T) {
	var cov rfcCoverage
	const maxN = 20

	for n := 1; n <= maxN; n++ {
		oldEntries := rfcEntries(n)
		oldRoot := MerkleRoot(oldEntries)
		oldProofs := make([][][]byte, n)
		for i := range oldProofs {
			p, err := MerkleProof(oldEntries, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			oldProofs[i] = clonePath(p)
		}

		for _, k := range []int{1, 2, 3} {
			newEntries := rfcEntries(n + k)
			newRoot := MerkleRoot(newEntries)

			for i := 0; i < n; i++ {
				// The old proof still verifies under the old (count, root).
				if !VerifyInclusion(oldEntries[i].Hash, i, n, oldProofs[i], oldRoot) {
					t.Errorf("n=%d k=%d i=%d: previously issued proof stopped verifying against the old root", n, k, i)
				}
				// A fresh proof verifies under the new (count, root).
				fresh, err := MerkleProof(newEntries, i)
				if err != nil {
					t.Fatalf("n=%d k=%d i=%d: %v", n, k, i, err)
				}
				if !VerifyInclusion(newEntries[i].Hash, i, n+k, fresh, newRoot) {
					t.Errorf("n=%d k=%d i=%d: fresh proof does not verify against the new root", n, k, i)
				}
				cov.accepted += 2

				// The old proof must not verify against the new root.
				if VerifyInclusion(oldEntries[i].Hash, i, n, oldProofs[i], newRoot) {
					t.Errorf("n=%d k=%d i=%d: a stale proof verified against the NEW root", n, k, i)
				}
				cov.rejected++
			}
		}
	}

	// sum(1..20) = 210 indices x 3 values of k = 630 -> 1260 accepts, 630 rejects.
	cov.mustCover(t, 1260, 630, "append-extension trials")
}

// ── 4. negative and malformed-input tests ────────────────────────────────────

// TestVerifyInclusion_RejectsMalformedProofLengths: truncating or padding the
// audit path must be rejected. Padding matters specifically because a verifier
// that stops as soon as it reaches the root, without checking that the whole
// path was consumed, accepts a proof with arbitrary trailing garbage.
func TestVerifyInclusion_RejectsMalformedProofLengths(t *testing.T) {
	var cov rfcCoverage
	zero := make([]byte, 32)

	for _, n := range []int{2, 3, 4, 5, 7, 8, 16} {
		es := rfcEntries(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, proof, root) {
				t.Fatalf("n=%d i=%d: baseline proof does not verify", n, i)
			}
			cov.accepted++

			// Truncated by one element (and to empty, when longer).
			if VerifyInclusion(es[i].Hash, i, n, proof[:len(proof)-1], root) {
				t.Errorf("n=%d i=%d: a truncated path verified", n, i)
			}
			cov.rejected++
			if len(proof) > 1 {
				if VerifyInclusion(es[i].Hash, i, n, nil, root) {
					t.Errorf("n=%d i=%d: an empty path verified", n, i)
				}
				cov.rejected++
			}

			// Padded with a trailing element that should never be consumed.
			padded := append(clonePath(proof), zero)
			if VerifyInclusion(es[i].Hash, i, n, padded, root) {
				t.Errorf("n=%d i=%d: a path with a trailing extra element verified", n, i)
			}
			cov.rejected++

			// A duplicated first element (same length family, wrong content).
			if len(proof) > 1 {
				dupFirst := clonePath(proof)
				copy(dupFirst[1], dupFirst[0])
				if VerifyInclusion(es[i].Hash, i, n, dupFirst, root) {
					t.Errorf("n=%d i=%d: a path with a duplicated element verified", n, i)
				}
				cov.rejected++
			}
		}
	}

	// 45 (n,i) pairs -> 45 accepts; 172 malformed variants rejected.
	cov.mustCover(t, 45, 172, "malformed-length trials")
}

// TestVerifyInclusion_RejectsOutOfRangeIndex covers the explicit guard in
// VerifyInclusion (index < 0, index >= count, count == 0) and the matching
// guard in MerkleProof, in both directions.
func TestVerifyInclusion_RejectsOutOfRangeIndex(t *testing.T) {
	var cov rfcCoverage

	for _, n := range []int{1, 2, 3, 4, 5, 7, 8} {
		es := rfcEntries(n)
		root := MerkleRoot(es)

		for i := 0; i < n; i++ {
			p, err := MerkleProof(es, i)
			if err != nil {
				t.Errorf("MerkleProof(n=%d, %d) must succeed for an in-range index: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, p, root) {
				t.Errorf("n=%d i=%d: in-range proof must verify", n, i)
			}
			cov.accepted++
		}

		anyProof, err := MerkleProof(es, 0)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		for _, bad := range []struct {
			index, count int
			why          string
		}{
			{-1, n, "negative index"},
			{n, n, "index == count"},
			{n + 1, n, "index > count"},
			{0, 0, "count == 0"},
			{-1, 0, "negative index and zero count"},
		} {
			if VerifyInclusion(es[0].Hash, bad.index, bad.count, anyProof, root) {
				t.Errorf("n=%d: VerifyInclusion accepted %s (index=%d count=%d)", n, bad.why, bad.index, bad.count)
			}
			cov.rejected++
		}

		for _, badIdx := range []int{-1, n, n + 1} {
			if _, err := MerkleProof(es, badIdx); err == nil {
				t.Errorf("n=%d: MerkleProof(index=%d) must return an out-of-range error", n, badIdx)
			}
			cov.rejected++
		}
	}

	// 30 accepts; 7 sizes x (5 + 3) = 56 rejects.
	cov.mustCover(t, 30, 56, "range-guard trials")
}

// TestVerifyInclusion_EmptyTreeProvesNothing. RFC 6962 §2.1 defines MTH({}) as
// SHA-256 of the empty string; MerkleRoot returns nil instead. That divergence
// is a question for the maintainer and is deliberately NOT frozen here. What
// this test does pin is the part that matters for enforcement: nothing is ever
// provably included in an empty log, under either candidate root, and
// MerkleProof refuses to issue a proof at all.
func TestVerifyInclusion_EmptyTreeProvesNothing(t *testing.T) {
	var cov rfcCoverage

	rfcEmpty := sha256.Sum256(nil)
	candidateRoots := [][]byte{nil, {}, rfcEmpty[:], make([]byte, 32)}
	leaves := [][]byte{nil, {}, rfcLeafData(0), rfcLeafData(7)}
	paths := [][][]byte{nil, {}, {rfcLeafData(0)}, {rfcLeafData(0), rfcLeafData(1)}}

	for _, root := range candidateRoots {
		for _, leaf := range leaves {
			for _, p := range paths {
				for _, idx := range []int{-1, 0, 1, 7} {
					if VerifyInclusion(leaf, idx, 0, p, root) {
						t.Errorf("empty tree: VerifyInclusion accepted index=%d against root %s",
							idx, hex.EncodeToString(root))
					}
					cov.rejected++
				}
			}
		}
	}

	for _, idx := range []int{-1, 0, 1} {
		if _, err := MerkleProof(nil, idx); err == nil {
			t.Errorf("MerkleProof over an empty log must fail for index %d", idx)
		}
		if _, err := MerkleProof([]Entry{}, idx); err == nil {
			t.Errorf("MerkleProof over a zero-length log must fail for index %d", idx)
		}
		cov.rejected += 2
	}

	// Accepting control: the same VerifyInclusion accepts a real one-leaf tree,
	// so the rejections above are not "this function always says no".
	one := rfcEntries(1)
	if !VerifyInclusion(one[0].Hash, 0, 1, nil, MerkleRoot(one)) {
		t.Error("VerifyInclusion rejected a valid single-leaf tree; the empty-tree rejections above prove nothing")
	}
	cov.accepted++

	// 4*4*4*4 = 256 plus 6 = 262 rejects, 1 accept.
	cov.mustCover(t, 1, 262, "empty-tree trials")
}

// TestVerifyInclusion_CountIsNotBoundByTheRoot documents and pins an API
// contract that callers must respect.
//
// An RFC 6962 root does not commit to the tree SIZE; it commits to the tree
// CONTENTS. The verifier replays the tree shape from the caller-supplied
// count, so two different counts that produce the SAME shape for a given index
// are indistinguishable, and both verify. Concretely: a proof for index 0 in a
// 5-leaf tree also verifies when the count is claimed to be 6, 7 or 8, because
// index 0 sits under three sibling hashes in all four shapes.
//
// The security consequence is that `count` must come from the SIGNED tree head
// (SignedRoot.Count, which is covered by the signature) and never from the
// party presenting the proof. cmd/receiptverify does exactly that.
//
// Both directions are asserted over the same enumeration: where the RFC audit
// path lengths differ, the wrong count MUST be rejected; where they coincide,
// it is expected to be accepted. If the accepted set ever becomes empty this
// test fails as vacuous; if the rejected direction ever weakens, it fails too.
func TestVerifyInclusion_CountIsNotBoundByTheRoot(t *testing.T) {
	var cov rfcCoverage
	const maxN = 20

	for n := 1; n <= maxN; n++ {
		es := rfcEntries(n)
		d := rfcLeaves(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			wantLen := len(rfcPATH(i, d))

			for c := 1; c <= maxN; c++ {
				if c == n || i >= c {
					continue
				}
				sameShape := len(rfcPATH(i, rfcLeaves(c))) == wantLen
				got := VerifyInclusion(es[i].Hash, i, c, proof, root)
				if sameShape {
					if !got {
						t.Errorf("n=%d i=%d c=%d: same RFC path length but verification failed", n, i, c)
					}
					cov.accepted++
				} else {
					if got {
						t.Errorf("n=%d i=%d c=%d: a claimed count with a different tree shape was accepted", n, i, c)
					}
					cov.rejected++
				}
			}
		}
	}

	// Over n,c in 1..20: 756 same-shape counts accepted, 1904 different-shape
	// counts rejected. Both classes are large, so neither direction is vacuous.
	cov.mustCover(t, 756, 1904, "claimed-count trials")
}

// TestMerkleProof_DuplicateLeafContentAndAppendUniqueness.
//
// Two entries with byte-identical hashes are genuinely interchangeable in a
// Merkle tree — that is a property of the construction, not a defect. What
// stops it mattering here is that audit entries are never byte-identical:
// Entry.computeHash mixes in Seq and PrevHash, so appending the same event
// twice yields two distinct leaves. This test asserts that end of it, and that
// with distinct leaves no index confusion is possible.
func TestMerkleProof_DuplicateLeafContentAndAppendUniqueness(t *testing.T) {
	var cov rfcCoverage

	l, err := Open(filepath.Join(t.TempDir(), "dup.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const n = 8
	for i := 0; i < n; i++ {
		// Byte-identical event, appended n times.
		if _, err := l.Append("txn_receipt", "same-subject", map[string]string{"rule_path": "same.rule"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	entries := l.Entries()
	if len(entries) != n {
		t.Fatalf("entries = %d, want %d", len(entries), n)
	}

	seen := map[string]int{}
	for i, e := range entries {
		h := hex.EncodeToString(e.Hash)
		if prev, dup := seen[h]; dup {
			t.Fatalf("entries %d and %d have identical hashes despite Seq/PrevHash chaining", prev, i)
		}
		seen[h] = i
		cov.accepted++
	}

	root := MerkleRoot(entries)
	proofs := make([][][]byte, n)
	for i := range proofs {
		p, err := MerkleProof(entries, i)
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		proofs[i] = p
		if !VerifyInclusion(entries[i].Hash, i, n, p, root) {
			t.Errorf("entry %d does not prove against the root", i)
		}
		cov.accepted++
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if VerifyInclusion(entries[j].Hash, i, n, proofs[i], root) {
				t.Errorf("entry %d proved at index %d despite identical event content", j, i)
			}
			cov.rejected++
		}
	}

	// 16 accepts (8 uniqueness + 8 proofs); 8*7 = 56 rejects.
	cov.mustCover(t, 16, 56, "duplicate-event trials")
}
