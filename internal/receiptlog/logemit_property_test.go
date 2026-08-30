package receiptlog

// logemit_property_test.go — property and negative tests for the emitter path:
// receipt -> signature -> hash-chained audit entry -> Merkle inclusion proof
// against a published, signed tree head.
//
// Scope note. The RFC 6962 tree itself lives in pkg/audit (merkle.go); its
// known-answer and differential tests against the RFC are in
// pkg/audit/merkle_rfc6962_test.go. This file covers the seam that only exists
// here: that what LogEmitter.Emit returns is exactly what the transparency log
// committed to, that a decision is never reported as recorded unless it
// durably was, and that neither the receipt nor its log entry can be altered
// afterwards without the proof failing.
//
// Anti-vacuity discipline. Every test asserts BOTH what must be accepted and
// what must be rejected, and reports the number of cases it exercised in each
// direction. A test that only ever asserts refusal passes just as happily when
// the implementation refuses everything — which is how a one-sided suite once
// let a filter reject the entire address space unnoticed. mustCover() fails the
// test if either denominator falls below the expected count.
//
// There is deliberately no golden-file or -update mechanism anywhere here.

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// ── helpers ──────────────────────────────────────────────────────────────────

type emitCoverage struct{ accepted, rejected int }

func (c *emitCoverage) mustCover(t *testing.T, minAccepted, minRejected int, unit string) {
	t.Helper()
	t.Logf("denominator: %d must-ACCEPT and %d must-REJECT %s exercised", c.accepted, c.rejected, unit)
	if c.accepted < minAccepted {
		t.Fatalf("VACUOUS TEST: %d must-accept %s exercised, expected at least %d", c.accepted, unit, minAccepted)
	}
	if c.rejected < minRejected {
		t.Fatalf("VACUOUS TEST: %d must-reject %s exercised, expected at least %d", c.rejected, unit, minRejected)
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func openLog(t *testing.T, name string) *audit.Log {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// newReceipt builds a receipt that alternates decision/class so both the
// PERMIT/ok and the DENY/violation and DENY/unavailable shapes reach the log.
func newReceipt(t *testing.T, i int) *receipt.Receipt {
	t.Helper()
	dec, class, rule := receipt.DecisionPermit, receipt.ClassOK, "authorize.ok"
	switch i % 3 {
	case 1:
		dec, class, rule = receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch"
	case 2:
		dec, class, rule = receipt.DecisionDeny, receipt.ClassUnavailable, "policy.engine-timeout"
	}
	r, err := receipt.New(
		"pep.test."+strconv.Itoa(i), dec, class, rule,
		receipt.TokenHash("tok-"+strconv.Itoa(i)),
		receipt.TokenHash("policy-"+strconv.Itoa(i)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// emitN emits n receipts through a fresh emitter and returns the emitter's
// reported hashes alongside the log entries.
func emitN(t *testing.T, n int, priv ed25519.PrivateKey, l *audit.Log) ([]string, []audit.Entry) {
	t.Helper()
	em, err := NewLogEmitter(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		h, err := em.Emit(newReceipt(t, i))
		if err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
		hashes[i] = h
	}
	entries := l.Entries()
	if len(entries) != n {
		t.Fatalf("log has %d entries after %d emits", len(entries), n)
	}
	return hashes, entries
}

// ── construction guards ──────────────────────────────────────────────────────

// TestNewLogEmitter_GuardsBothWays: a nil log or a wrong-sized key is refused,
// and a correctly-sized key with an open log is accepted. Without the accepting
// half, a constructor that refused everything would pass.
func TestNewLogEmitter_GuardsBothWays(t *testing.T) {
	var cov emitCoverage
	_, priv := newKey(t)
	l := openLog(t, "guards.jsonl")

	if em, err := NewLogEmitter(l, priv); err != nil || em == nil {
		t.Fatalf("a valid log and key must be accepted: em=%v err=%v", em, err)
	}
	cov.accepted++

	badKeys := [][]byte{
		nil,
		{},
		make([]byte, 1),
		make([]byte, ed25519.PrivateKeySize-1),
		make([]byte, ed25519.PrivateKeySize+1),
		make([]byte, ed25519.PublicKeySize), // a public key passed by mistake
		make([]byte, ed25519.SeedSize),      // a seed passed by mistake
	}
	for i, k := range badKeys {
		if em, err := NewLogEmitter(l, ed25519.PrivateKey(k)); err == nil || em != nil {
			t.Errorf("bad key %d (len %d) must be refused, got em=%v err=%v", i, len(k), em, err)
		}
		cov.rejected++
	}
	if em, err := NewLogEmitter(nil, priv); err == nil || em != nil {
		t.Error("a nil audit log must be refused")
	}
	cov.rejected++
	if em, err := NewLogEmitter(nil, nil); err == nil || em != nil {
		t.Error("a nil log and nil key must be refused")
	}
	cov.rejected++

	cov.mustCover(t, 1, 9, "constructor arguments")
}

// ── the emitted hash is what the log committed to ────────────────────────────

// TestEmit_ReturnedHashIsTheLoggedSubject: the value Emit hands back is the
// locator an auditor will use, so it must be exactly the log entry's subject
// and exactly the receipt's own hash — and it must be distinct for every
// emission, so no receipt can displace another's evidence. Distinctness of the
// LOG entry hashes is asserted separately: those chain in Seq and PrevHash, so
// they stay distinct even for byte-identical decisions (which is the case
// pkg/audit's TestMerkleProof_DuplicateLeafContentAndAppendUniqueness covers).
func TestEmit_ReturnedHashIsTheLoggedSubject(t *testing.T) {
	var cov emitCoverage
	const n = 32
	_, priv := newKey(t)
	l := openLog(t, "subjects.jsonl")
	hashes, entries := emitN(t, n, priv, l)

	seen := map[string]int{}
	for i := range entries {
		if entries[i].Subject != hashes[i] {
			t.Errorf("entry %d subject %q != hash returned by Emit %q", i, entries[i].Subject, hashes[i])
		}
		if entries[i].Type != EventType {
			t.Errorf("entry %d type %q != %q", i, entries[i].Type, EventType)
		}
		if entries[i].Detail["receipt_hash"] != hashes[i] {
			t.Errorf("entry %d detail receipt_hash %q != %q", i, entries[i].Detail["receipt_hash"], hashes[i])
		}
		cov.accepted += 3

		if prev, dup := seen[hashes[i]]; dup {
			t.Errorf("emissions %d and %d produced the same receipt hash %q", prev, i, hashes[i])
		}
		seen[hashes[i]] = i
	}

	// Rejecting direction: no emitted hash equals any OTHER emission's hash,
	// and no log entry's chain hash repeats either.
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if hashes[i] == hashes[j] {
				t.Errorf("receipt hashes %d and %d collide", i, j)
			}
			if bytes.Equal(entries[i].Hash, entries[j].Hash) {
				t.Errorf("log entry hashes %d and %d collide", i, j)
			}
			cov.rejected += 2
		}
	}

	if err := l.Verify(); err != nil {
		t.Fatalf("hash chain broken after %d emits: %v", n, err)
	}
	cov.accepted++

	// 32*3 + 1 = 97 accepts; 32*31*2 = 1984 rejects.
	cov.mustCover(t, 97, 1984, "emitted receipts")
}

// ── inclusion over every prefix of the log ───────────────────────────────────

// TestProperty_EveryEmittedReceiptIsProvableAtEveryTreeSize.
//
// A published tree head commits to a prefix of the log. For every prefix size
// m and every receipt i < m, the receipt must prove inclusion under that head;
// and once issued, that proof must keep verifying against that head no matter
// how much the log grows afterwards. The rejecting direction, asserted on the
// same inputs: the proof issued under head m must NOT verify against a later
// head, since a tree head that accepted proofs from a different log state would
// not be a commitment to anything.
func TestProperty_EveryEmittedReceiptIsProvableAtEveryTreeSize(t *testing.T) {
	var cov emitCoverage
	const n = 32
	pub, priv := newKey(t)
	l := openLog(t, "prefixes.jsonl")
	_, entries := emitN(t, n, priv, l)

	finalRoot := audit.MerkleRoot(entries)

	for m := 1; m <= n; m++ {
		prefix := entries[:m]
		sr := audit.PublishRoot(prefix, priv)
		if sr.Count != m {
			t.Fatalf("PublishRoot(count=%d) reported %d", m, sr.Count)
		}
		if !audit.VerifyRoot(sr, pub) {
			t.Fatalf("m=%d: published root does not verify under the log key", m)
		}
		cov.accepted++

		for i := 0; i < m; i++ {
			proof, err := audit.MerkleProof(prefix, i)
			if err != nil {
				t.Fatalf("m=%d i=%d: %v", m, i, err)
			}
			// Count is taken from the SIGNED head, never from a presenter.
			if !audit.VerifyInclusion(prefix[i].Hash, i, sr.Count, proof, sr.Root) {
				t.Errorf("m=%d i=%d: emitted receipt does not prove under its own tree head", m, i)
			}
			cov.accepted++

			if m < n {
				if audit.VerifyInclusion(prefix[i].Hash, i, sr.Count, proof, finalRoot) {
					t.Errorf("m=%d i=%d: a proof under head %d verified against the final head %d", m, i, m, n)
				}
				cov.rejected++
			}
		}
	}

	// 32 heads + sum(1..32)=528 inclusion checks = 560 accepts;
	// sum(1..31) = 496 rejects.
	cov.mustCover(t, 560, 496, "prefix/receipt pairs")
}

// TestProperty_TamperedLogEntryLosesItsProof: flipping any single bit of a
// logged entry hash destroys that entry's inclusion proof under the published
// head. All 32 bytes x 8 bits are covered for the first eight entries, so a
// verifier comparing only part of the digest fails here. The untampered entry
// is asserted to verify for each of those entries, giving the accepting half.
func TestProperty_TamperedLogEntryLosesItsProof(t *testing.T) {
	var cov emitCoverage
	const n = 12
	pub, priv := newKey(t)
	l := openLog(t, "tamper.jsonl")
	_, entries := emitN(t, n, priv, l)

	sr := audit.PublishRoot(entries, priv)
	if !audit.VerifyRoot(sr, pub) {
		t.Fatal("published root does not verify")
	}

	for i := 0; i < 8; i++ {
		proof, err := audit.MerkleProof(entries, i)
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if !audit.VerifyInclusion(entries[i].Hash, i, sr.Count, proof, sr.Root) {
			t.Fatalf("entry %d: baseline proof does not verify; the mutations below prove nothing", i)
		}
		cov.accepted++

		for b := 0; b < len(entries[i].Hash); b++ {
			for bit := 0; bit < 8; bit++ {
				mut := append([]byte(nil), entries[i].Hash...)
				mut[b] ^= 1 << bit
				if audit.VerifyInclusion(mut, i, sr.Count, proof, sr.Root) {
					t.Errorf("entry %d: flipping byte %d bit %d still proved inclusion", i, b, bit)
				}
				cov.rejected++
			}
		}
	}

	// 8 accepts; 8*32*8 = 2048 rejects.
	cov.mustCover(t, 8, 2048, "entry bit-flips")
}

// TestProperty_TamperedSignedHeadIsRejected: the published head binds root,
// count and time together under one signature. Altering any of the three, or
// the signature itself, or presenting a different public key, must be
// rejected. The accepting half — every honest head over every prefix verifies
// under the log key — is asserted in the same loop, so a VerifyRoot that
// rejected everything would fail rather than pass.
func TestProperty_TamperedSignedHeadIsRejected(t *testing.T) {
	var cov emitCoverage
	const n = 16
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	l := openLog(t, "head.jsonl")
	_, entries := emitN(t, n, priv, l)

	for m := 1; m <= n; m++ {
		sr := audit.PublishRoot(entries[:m], priv)
		if !audit.VerifyRoot(sr, pub) {
			t.Fatalf("m=%d: honest head must verify", m)
		}
		cov.accepted++

		// A different key must not validate this head.
		if audit.VerifyRoot(sr, otherPub) {
			t.Errorf("m=%d: head verified under an unrelated public key", m)
		}
		cov.rejected++

		// Each field, mutated independently.
		badRoot := sr
		badRoot.Root = append([]byte(nil), sr.Root...)
		badRoot.Root[m%len(badRoot.Root)] ^= 0x01
		if audit.VerifyRoot(badRoot, pub) {
			t.Errorf("m=%d: head with a mutated root verified", m)
		}
		cov.rejected++

		badCount := sr
		badCount.Count = sr.Count + 1
		if audit.VerifyRoot(badCount, pub) {
			t.Errorf("m=%d: head with an inflated count verified", m)
		}
		cov.rejected++

		badTime := sr
		badTime.Time = sr.Time + 1
		if audit.VerifyRoot(badTime, pub) {
			t.Errorf("m=%d: head with a shifted timestamp verified", m)
		}
		cov.rejected++

		badSig := sr
		badSig.Sig = append([]byte(nil), sr.Sig...)
		badSig.Sig[m%len(badSig.Sig)] ^= 0x01
		if audit.VerifyRoot(badSig, pub) {
			t.Errorf("m=%d: head with a mutated signature verified", m)
		}
		cov.rejected++

		emptySig := sr
		emptySig.Sig = nil
		if audit.VerifyRoot(emptySig, pub) {
			t.Errorf("m=%d: head with no signature verified", m)
		}
		cov.rejected++
	}

	// 16 accepts; 16*6 = 96 rejects.
	cov.mustCover(t, 16, 96, "signed-head mutations")
}

// ── the receipt itself ───────────────────────────────────────────────────────

// TestEmit_SignsWithTheLogKeyAndNoOther: every emitted receipt verifies under
// the log public key and under no other key, and any post-hoc edit — including
// one that keeps the decision/class pairing legal — invalidates the signature
// AND changes the receipt hash, so the edited receipt no longer matches the
// subject that was logged.
func TestEmit_SignsWithTheLogKeyAndNoOther(t *testing.T) {
	var cov emitCoverage
	const n = 12
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	l := openLog(t, "sig.jsonl")

	em, err := NewLogEmitter(l, priv)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
		r := newReceipt(t, i)
		h, err := em.Emit(r)
		if err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
		if err := r.Verify(pub); err != nil {
			t.Errorf("receipt %d does not verify under the log key: %v", i, err)
		}
		if got, err := r.Hash(); err != nil || got != h {
			t.Errorf("receipt %d: Hash() = %q err=%v, Emit returned %q", i, got, err, h)
		}
		cov.accepted += 2

		if err := r.Verify(otherPub); err == nil {
			t.Errorf("receipt %d verified under an unrelated public key", i)
		}
		cov.rejected++

		// Post-hoc edits. Each must break the signature and change the hash.
		for _, edit := range []struct {
			name  string
			apply func(*receipt.Receipt)
		}{
			// Swapping "violation" for "unavailable" keeps the pairing legal
			// but turns an attack into an outage in the evidence record. This
			// is the edit a dishonest operator actually wants.
			{"class violation->unavailable", func(x *receipt.Receipt) {
				if x.Class == receipt.ClassViolation {
					x.Class = receipt.ClassUnavailable
				} else if x.Class == receipt.ClassUnavailable {
					x.Class = receipt.ClassViolation
				} else {
					x.RulePath = "authorize.ok.rewritten"
				}
			}},
			{"rule path", func(x *receipt.Receipt) { x.RulePath += ".rewritten" }},
			{"pep identity", func(x *receipt.Receipt) { x.PEP += ".other" }},
			{"policy hash", func(x *receipt.Receipt) { x.PolicyHash = receipt.TokenHash("substituted-policy") }},
			{"token hash", func(x *receipt.Receipt) { x.TokenHash = receipt.TokenHash("substituted-token") }},
			{"timestamp", func(x *receipt.Receipt) { x.TS += 3600 }},
			{"nonce", func(x *receipt.Receipt) { x.Nonce = receipt.TokenHash("replaced-nonce") }},
			{"jurisdiction added", func(x *receipt.Receipt) { x.Jurisdiction = "VARA" }},
			{"intent digest added", func(x *receipt.Receipt) { x.IntentDigest = receipt.TokenHash("some-intent") }},
		} {
			edited := *r
			edit.apply(&edited)

			if err := edited.Verify(pub); err == nil {
				t.Errorf("receipt %d: edit %q still verified under the log key", i, edit.name)
			}
			eh, err := edited.Hash()
			if err != nil {
				t.Errorf("receipt %d: edit %q: Hash: %v", i, edit.name, err)
			} else if eh == h {
				t.Errorf("receipt %d: edit %q did not change the receipt hash", i, edit.name)
			}
			cov.rejected += 2
		}
	}

	// 12*2 = 24 accepts; 12*(1 + 9*2) = 228 rejects.
	cov.mustCover(t, 24, 228, "receipt signatures and edits")
}

// ── fail-closed ──────────────────────────────────────────────────────────────

// TestEmit_FailsClosedWhenTheLogCannotAccept.
//
// Emit's contract is that a nil error means the decision is durably recorded.
// The inverse matters more: when the log cannot accept the entry, Emit must
// return an error AND must not leave a partial record behind, because the
// decision core turns that error into DENY(unavailable). If Emit reported
// success, or half-appended, an unrecorded decision would be served.
//
// Both directions are asserted against the same emitter: appends succeed while
// the log is open, and fail without side effects once it is not.
func TestEmit_FailsClosedWhenTheLogCannotAccept(t *testing.T) {
	var cov emitCoverage
	_, priv := newKey(t)

	l, err := audit.Open(filepath.Join(t.TempDir(), "failclosed.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	em, err := NewLogEmitter(l, priv)
	if err != nil {
		t.Fatal(err)
	}

	const good = 5
	for i := 0; i < good; i++ {
		if _, err := em.Emit(newReceipt(t, i)); err != nil {
			t.Fatalf("emit %d must succeed while the log is open: %v", i, err)
		}
		cov.accepted++
	}
	if n := len(l.Entries()); n != good {
		t.Fatalf("expected %d entries, got %d", good, n)
	}
	before := l.Entries()
	rootBefore := audit.MerkleRoot(before)

	// The log's file is no longer writable.
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for i := 0; i < 5; i++ {
		h, err := em.Emit(newReceipt(t, 100+i))
		if err == nil {
			t.Errorf("emit %d after close reported success (hash %q) — a decision would be served unrecorded", i, h)
		}
		if h != "" {
			t.Errorf("emit %d after close returned a non-empty locator %q alongside its error", i, h)
		}
		cov.rejected += 2

		after := l.Entries()
		if len(after) != good {
			t.Fatalf("a failed emit changed the log length: %d -> %d", good, len(after))
		}
		if !bytes.Equal(audit.MerkleRoot(after), rootBefore) {
			t.Fatal("a failed emit changed the Merkle root — the log was partially mutated")
		}
		cov.rejected++
	}

	// The surviving log is still internally consistent and still provable.
	if err := l.Verify(); err != nil {
		t.Fatalf("chain broken after failed emits: %v", err)
	}
	cov.accepted++
	for i := range before {
		p, err := audit.MerkleProof(before, i)
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if !audit.VerifyInclusion(before[i].Hash, i, len(before), p, rootBefore) {
			t.Errorf("entry %d stopped proving after the failed emits", i)
		}
		cov.accepted++
	}

	// 5 + 1 + 5 = 11 accepts; 5*3 = 15 rejects.
	cov.mustCover(t, 11, 15, "fail-closed emissions")
}

// TestEmit_AcceptsEveryValidDecisionShape: all three legal decision/class
// pairings reach the log and verify, and every mislabeled pairing is refused
// before a receipt can exist at all — so the log length after the run is
// exactly the number of legal shapes. Operators must be able to tell an
// outage (DENY/unavailable) from an attack (DENY/violation) in the evidence,
// which only holds if the mislabeled combinations are unconstructible.
func TestEmit_AcceptsEveryValidDecisionShape(t *testing.T) {
	var cov emitCoverage
	pub, priv := newKey(t)
	l := openLog(t, "shapes.jsonl")
	em, err := NewLogEmitter(l, priv)
	if err != nil {
		t.Fatal(err)
	}

	shapes := []struct{ decision, class, rule string }{
		{receipt.DecisionPermit, receipt.ClassOK, "authorize.ok"},
		{receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch"},
		{receipt.DecisionDeny, receipt.ClassUnavailable, "policy.engine-timeout"},
	}
	for i, s := range shapes {
		r, err := receipt.New("pep.shapes", s.decision, s.class, s.rule,
			receipt.TokenHash("t"), receipt.TokenHash("p"))
		if err != nil {
			t.Fatalf("shape %d must be constructible: %v", i, err)
		}
		h, err := em.Emit(r)
		if err != nil || h == "" {
			t.Fatalf("shape %d must be emitted: h=%q err=%v", i, h, err)
		}
		if err := r.Verify(pub); err != nil {
			t.Errorf("shape %d does not verify: %v", i, err)
		}
		cov.accepted += 2
	}

	// Rejecting direction: mislabeled pairings never reach the log at all,
	// so the entry count stays at exactly the number of valid shapes.
	bad := []struct{ decision, class string }{
		{receipt.DecisionPermit, receipt.ClassViolation},
		{receipt.DecisionPermit, receipt.ClassUnavailable},
		{receipt.DecisionDeny, receipt.ClassOK},
		{receipt.DecisionPermit, ""},
		{receipt.DecisionDeny, ""},
		{"ALLOW", receipt.ClassOK},
		{"", receipt.ClassOK},
		{"permit", receipt.ClassOK},
	}
	for i, b := range bad {
		if _, err := receipt.New("pep.shapes", b.decision, b.class, "some.rule",
			receipt.TokenHash("t"), receipt.TokenHash("p")); err == nil {
			t.Errorf("mislabeled pairing %d (%q/%q) must not be constructible", i, b.decision, b.class)
		}
		cov.rejected++
	}
	if n := len(l.Entries()); n != len(shapes) {
		t.Fatalf("log has %d entries, expected exactly the %d valid shapes", n, len(shapes))
	}
	cov.rejected++

	// 6 accepts; 9 rejects.
	cov.mustCover(t, 6, 9, "decision/class shapes")
}

// ── the audit detail carries no payload ──────────────────────────────────────

// TestEmit_AuditDetailCarriesOnlyHashesAndEnums: every logged detail value is
// either an enum this package defines or a hash the receipt already published,
// so the transparency log stays free of payloads. The accepting half is that
// the expected keys ARE present — a log entry that carried nothing would
// trivially satisfy "carries no payload".
func TestEmit_AuditDetailCarriesOnlyHashesAndEnums(t *testing.T) {
	var cov emitCoverage
	const n = 9
	_, priv := newKey(t)
	l := openLog(t, "detail.jsonl")
	hashes, entries := emitN(t, n, priv, l)

	required := []string{"receipt_v", "receipt_hash", "pep", "decision", "class", "rule_path", "token_hash", "policy_hash"}
	for i, e := range entries {
		for _, k := range required {
			if _, ok := e.Detail[k]; !ok {
				t.Errorf("entry %d is missing detail key %q", i, k)
			}
			cov.accepted++
		}
		if e.Detail["receipt_hash"] != hashes[i] {
			t.Errorf("entry %d receipt_hash does not match the emitted locator", i)
		}
		cov.accepted++

		switch e.Detail["decision"] {
		case receipt.DecisionPermit, receipt.DecisionDeny:
		default:
			t.Errorf("entry %d has a non-enum decision %q", i, e.Detail["decision"])
		}
		switch e.Detail["class"] {
		case receipt.ClassOK, receipt.ClassViolation, receipt.ClassUnavailable:
		default:
			t.Errorf("entry %d has a non-enum class %q", i, e.Detail["class"])
		}
		cov.accepted += 2

		// Rejecting direction: the PII keys the audit package refuses must
		// never appear, and Append must refuse them if a caller tries.
		for _, forbidden := range []string{"amount", "name", "account", "pan", "iban", "dob"} {
			if _, present := e.Detail[forbidden]; present {
				t.Errorf("entry %d carries a PII detail key %q", i, forbidden)
			}
			cov.rejected++
		}
	}

	for _, forbidden := range []string{"amount", "name", "account", "pan", "iban", "dob", "AMOUNT", "Dob"} {
		if _, err := l.Append(EventType, "subject", map[string]string{forbidden: "x"}); err == nil {
			t.Errorf("Append must refuse the PII key %q", forbidden)
		}
		cov.rejected++
	}
	if n2 := len(l.Entries()); n2 != n {
		t.Fatalf("refused appends still grew the log: %d -> %d", n, n2)
	}
	cov.rejected++

	// 9*(8+1+2) = 99 accepts; 9*6 + 8 + 1 = 63 rejects.
	cov.mustCover(t, 99, 63, "audit detail fields")
}
