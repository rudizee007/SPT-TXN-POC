package cattoken_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// A CAT that declares a max_cumulative budget may commit, in its signed claims,
// to ONE Merkle group root over a pre-division of that budget (§7.2). The
// commitment must round-trip through Issue and survive a Verify (the signature
// covers it), so a downstream verifier can trust the human's authority fixed it.
func TestIssue_SubbandCommitment(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	// A $100 budget over [0,30) divided into three $10 day-bands.
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "currency": "USD"}
	bands := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 0, Expiry: 10},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 10, Expiry: 20},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: 20, Expiry: 30},
	}
	root, _, _, err := tbac.CommitBandDivision(tbac.SuiteSHA3_256, tbac.Scope(budget), 0, 30, bands)
	if err != nil {
		t.Fatalf("CommitBandDivision: %v", err)
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: 24 * time.Hour, HolderPublicKey: holderPub,
		SubbandGroupRoot: root[:], SubbandGroupSize: 3, SubbandHashSuite: tbac.SuiteSHA3_256,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("Issue with subband commitment: %v", err)
	}

	wantRoot := hex.EncodeToString(root[:])
	if got, _ := cat.Claims["subband_group_root"].(string); got != wantRoot {
		t.Fatalf("subband_group_root claim = %q, want %q", got, wantRoot)
	}
	if got, _ := cat.Claims["subband_hash_suite"].(string); got != string(tbac.SuiteSHA3_256) {
		t.Fatalf("subband_hash_suite claim = %q, want %q", got, tbac.SuiteSHA3_256)
	}

	// Survives verification (the signature covers the commitment).
	claims, err := cattoken.Verify(cat.Token, issuerPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["subband_group_root"] != wantRoot {
		t.Fatal("subband_group_root did not survive verify")
	}
}

// A commitment on a scope with no cumulative budget is refused — there is
// nothing to divide, and a group root with no budget behind it is meaningless.
func TestIssue_SubbandCommitment_RequiresCumulativeBudget(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)
	var root [32]byte
	for i := range root {
		root[i] = 0xAB
	}
	_, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"max_amount": 100, "currency": "USD"}, // no max_cumulative
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
		SubbandGroupRoot: root[:], SubbandGroupSize: 3, SubbandHashSuite: tbac.SuiteSHA3_256,
	}, issuerPriv)
	if err == nil {
		t.Fatal("a subband commitment on a scope with no max_cumulative budget must be refused")
	}
}

// Malformed commitment inputs fail closed: wrong root length, zero size, unknown suite.
func TestIssue_SubbandCommitment_MalformedRefused(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "currency": "USD"}
	base := cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
		SubbandGroupSize: 3, SubbandHashSuite: tbac.SuiteSHA3_256,
	}
	var root [32]byte

	r1 := base
	r1.SubbandGroupRoot = []byte{1, 2, 3} // wrong length
	if _, err := cattoken.Issue(r1, issuerPriv); err == nil {
		t.Fatal("a non-32-byte group root must be refused")
	}

	r2 := base
	r2.SubbandGroupRoot = root[:]
	r2.SubbandGroupSize = 0 // zero size
	if _, err := cattoken.Issue(r2, issuerPriv); err == nil {
		t.Fatal("a zero group size must be refused")
	}

	r3 := base
	r3.SubbandGroupRoot = root[:]
	r3.SubbandHashSuite = tbac.HashSuite("sha256") // unknown suite
	if _, err := cattoken.Issue(r3, issuerPriv); err == nil {
		t.Fatal("an unknown hash suite must be refused")
	}
}
