package audit

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func mkEntries(n int) []Entry {
	es := make([]Entry, n)
	for i := range es {
		h := sha256.Sum256([]byte(fmt.Sprintf("entry-%d", i)))
		es[i] = Entry{Seq: uint64(i), Hash: h[:]}
	}
	return es
}

func TestMerkleProof_AllIndices(t *testing.T) {
	// Test odd and even counts so the promotion rule is exercised.
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9} {
		es := mkEntries(n)
		root := MerkleRoot(es)
		for i := 0; i < n; i++ {
			proof, err := MerkleProof(es, i)
			if err != nil {
				t.Fatalf("n=%d i=%d proof: %v", n, i, err)
			}
			if !VerifyInclusion(es[i].Hash, i, n, proof, root) {
				t.Fatalf("n=%d i=%d: inclusion failed to verify", n, i)
			}
		}
	}
}

func TestMerkleProof_RejectsWrongEntry(t *testing.T) {
	es := mkEntries(6)
	root := MerkleRoot(es)
	proof, _ := MerkleProof(es, 2)
	// right proof, wrong leaf
	bad := sha256.Sum256([]byte("not in the tree"))
	if VerifyInclusion(bad[:], 2, 6, proof, root) {
		t.Fatal("verified a leaf that is not in the tree")
	}
	// right leaf, wrong index
	if VerifyInclusion(es[2].Hash, 3, 6, proof, root) {
		t.Fatal("verified against the wrong index")
	}
}

func TestMerkleProof_OutOfRange(t *testing.T) {
	es := mkEntries(3)
	if _, err := MerkleProof(es, 3); err == nil {
		t.Fatal("expected out-of-range error")
	}
}
