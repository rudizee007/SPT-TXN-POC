package audit

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func edkey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func entriesN(n int) []Entry {
	es := make([]Entry, n)
	prev := genesis()
	for i := 0; i < n; i++ {
		e := Entry{Seq: uint64(i), Time: int64(i), Type: "txn_receipt", Subject: string(rune('a' + i%26)), PrevHash: prev}
		e.Hash = e.computeHash()
		es[i] = e
		prev = e.Hash
	}
	return es
}

func TestWitness_CosignAndVerify(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, w1Priv := edkey(t)
	_, w2Priv := edkey(t)
	w1, _ := NewWitness("witness-1", w1Priv)
	w2, _ := NewWitness("witness-2", w2Priv)

	entries := entriesN(10)
	sr := PublishRoot(entries, opPriv)

	s1, err := w1.Cosign(sr, opPub, entries)
	if err != nil {
		t.Fatalf("w1 cosign: %v", err)
	}
	s2, err := w2.Cosign(sr, opPub, entries)
	if err != nil {
		t.Fatalf("w2 cosign: %v", err)
	}

	cr := CosignedRoot{SignedRoot: sr, OperatorPub: opPub, Cosigs: []WitnessSig{s1, s2}}
	set := map[string]ed25519.PublicKey{"witness-1": w1.Public(), "witness-2": w2.Public()}

	if err := VerifyCosigned(cr, opPub, set, 2); err != nil {
		t.Fatalf("2-of-2 verify failed: %v", err)
	}
	if err := VerifyCosigned(cr, opPub, set, 1); err != nil {
		t.Fatalf("1 threshold failed: %v", err)
	}
	// Threshold above available co-signers fails.
	if err := VerifyCosigned(cr, opPub, set, 3); !errors.Is(err, ErrThreshold) {
		t.Fatalf("threshold 3 should fail: %v", err)
	}
}

func TestWitness_RefusesRewrittenHistory(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)

	// Witness attests the log at count 10.
	entries := entriesN(10)
	sr10 := PublishRoot(entries, opPriv)
	if _, err := w.Cosign(sr10, opPub, entries); err != nil {
		t.Fatal(err)
	}

	// Operator rewrites entry 3 and re-signs a fork of the SAME length. This is
	// a validly operator-signed tree head over a DIFFERENT history.
	forked := entriesN(10)
	forked[3].Subject = "TAMPERED"
	forked[3].Hash = forked[3].computeHash()
	srFork := PublishRoot(forked, opPriv)
	if VerifyRoot(srFork, opPub) != true {
		t.Fatal("forked root should carry a valid operator signature")
	}
	// The witness must REFUSE to co-sign it: its prefix at count 10 does not
	// reproduce the previously attested root.
	if _, err := w.Cosign(srFork, opPub, forked); !errors.Is(err, ErrNotAppendOnly) {
		t.Fatalf("witness co-signed a rewritten history: %v", err)
	}
}

func TestWitness_RefusesRegression(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)

	entries := entriesN(20)
	if _, err := w.Cosign(PublishRoot(entries, opPriv), opPub, entries); err != nil {
		t.Fatal(err)
	}
	// A later head that covers FEWER entries (truncation) is refused.
	shorter := entries[:15]
	if _, err := w.Cosign(PublishRoot(shorter, opPriv), opPub, shorter); !errors.Is(err, ErrNotAppendOnly) {
		t.Fatalf("witness accepted a truncated log: %v", err)
	}
}

func TestWitness_AcceptsAppendOnlyGrowth(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)

	e10 := entriesN(10)
	if _, err := w.Cosign(PublishRoot(e10, opPriv), opPub, e10); err != nil {
		t.Fatal(err)
	}
	// Genuine append: first 10 entries identical, plus more.
	e25 := entriesN(25)
	if _, err := w.Cosign(PublishRoot(e25, opPriv), opPub, e25); err != nil {
		t.Fatalf("witness rejected a legitimate append: %v", err)
	}
}

func TestWitness_RejectsBadOperatorSig(t *testing.T) {
	opPub, _ := edkey(t)
	_, otherPriv := edkey(t) // NOT the operator key
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)

	entries := entriesN(5)
	srBad := PublishRoot(entries, otherPriv) // signed by the wrong key
	if _, err := w.Cosign(srBad, opPub, entries); !errors.Is(err, ErrOperatorSig) {
		t.Fatalf("witness co-signed under an invalid operator signature: %v", err)
	}
}

func TestWitness_RejectsLogNotMatchingRoot(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)

	entries := entriesN(10)
	sr := PublishRoot(entries, opPriv)
	// Present a different log than the one the root commits to.
	other := entriesN(10)
	other[0].Subject = "different"
	other[0].Hash = other[0].computeHash()
	if _, err := w.Cosign(sr, opPub, other); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("witness co-signed a root the presented log does not reproduce: %v", err)
	}
}

func TestVerifyCosigned_IgnoresUnknownAndDuplicateWitnesses(t *testing.T) {
	opPub, opPriv := edkey(t)
	_, wPriv := edkey(t)
	w, _ := NewWitness("w", wPriv)
	_, roguePriv := edkey(t)
	rogue, _ := NewWitness("rogue", roguePriv)

	entries := entriesN(8)
	sr := PublishRoot(entries, opPriv)
	s, _ := w.Cosign(sr, opPub, entries)
	rs, _ := rogue.Cosign(sr, opPub, entries)

	set := map[string]ed25519.PublicKey{"w": w.Public()} // rogue NOT in the set

	// Duplicates of the same witness count once; the unknown rogue doesn't count.
	cr := CosignedRoot{SignedRoot: sr, OperatorPub: opPub, Cosigs: []WitnessSig{s, s, rs}}
	if err := VerifyCosigned(cr, opPub, set, 2); !errors.Is(err, ErrThreshold) {
		t.Fatalf("duplicate/unknown co-sigs inflated the count: %v", err)
	}
	if err := VerifyCosigned(cr, opPub, set, 1); err != nil {
		t.Fatalf("one genuine known witness should satisfy threshold 1: %v", err)
	}
}
