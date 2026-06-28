package zkproof_test

import (
	"fmt"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// testRegistry builds a full depth-VASPTreeDepth (256-leaf) registered-CT-issuer
// tree containing the given issuer member-IDs (the rest are padding sentinels).
func testRegistry(t *testing.T, issuers ...[]byte) *zkproof.MerkleTree {
	t.Helper()
	const n = 1 << zkproof.VASPTreeDepth
	members := make([][]byte, n)
	copy(members, issuers)
	for i := len(issuers); i < n; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	tree, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return tree
}

var (
	issuerA = []byte("domain-a.authorg/ct_issuer")
	issuerB = []byte("domain-b.execorg/ct_issuer")
	issuerC = []byte("domain-c.agentorg/ct_issuer")
)

// A valid 3-hop chain (10000 -> 8000 -> 5000, same currency, depth 3) whose every
// hop is issued by a registered CT-issuer proves and verifies; a wrong declared
// depth is rejected.
func TestChain_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA, issuerB, issuerC)
	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: 840, Issuer: issuerA}, // root CAT ceiling
		{MaxAmount: 8000, Currency: 840, Issuer: issuerB},  // CT
		{MaxAmount: 5000, Currency: 840, Issuer: issuerC},  // leaf (agent)
	}
	proof, h0, cleaf, regRoot, err := art.ProveChain([]byte("alice-human-anchor"), []byte("salt-xyz"), 3, hops, reg)
	if err != nil {
		t.Fatalf("prove (valid chain): %v", err)
	}
	if err := art.VerifyChain(proof, h0, cleaf, regRoot, 3); err != nil {
		t.Fatalf("verify (valid chain) failed: %v", err)
	}
	if err := art.VerifyChain(proof, h0, cleaf, regRoot, 2); err == nil {
		t.Error("verify accepted a wrong maxDepth")
	}
}

// A child whose ceiling exceeds its parent violates attenuation — proving must fail.
func TestChain_RejectsWidening(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA, issuerB)
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840, Issuer: issuerA},
		{MaxAmount: 9000, Currency: 840, Issuer: issuerB}, // widens above parent — escalation
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a widening (scope-escalating) chain")
	}
}

// Switching currency mid-chain violates the currency-equality constraint.
func TestChain_RejectsCurrencySwitch(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA, issuerB)
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840, Issuer: issuerA},
		{MaxAmount: 5000, Currency: 978, Issuer: issuerB}, // currency changed
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a currency switch mid-chain")
	}
}

// A chain longer than the declared delegation depth allows is rejected.
func TestChain_RejectsTooDeep(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA, issuerB, issuerC)
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840, Issuer: issuerA},
		{MaxAmount: 5000, Currency: 840, Issuer: issuerB},
		{MaxAmount: 3000, Currency: 840, Issuer: issuerC},
	}
	// 3 hops need depth >= 2; declaring maxDepth=1 must be refused.
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 1, hops, reg); err == nil {
		t.Error("prove accepted a chain deeper than maxDepth")
	}
}

// A hop whose issuer is NOT in the registered-CT-issuer registry cannot be proved
// (F1, phase 1: every active hop must be issued by a registry-listed issuer).
func TestChain_RejectsUnregisteredIssuer(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA) // issuerB intentionally NOT registered
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840, Issuer: issuerA},
		{MaxAmount: 5000, Currency: 840, Issuer: issuerB}, // unregistered issuer
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a hop issued by an unregistered issuer")
	}
}

// A proof made against one registry must not verify against a different registry
// root (the public RegRoot binds the proof to the verifier's trusted issuer set).
func TestChain_RejectsWrongRegRoot(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	reg := testRegistry(t, issuerA, issuerB)
	hops := []zkproof.ChainHop{
		{MaxAmount: 8000, Currency: 840, Issuer: issuerA},
		{MaxAmount: 5000, Currency: 840, Issuer: issuerB},
	}
	proof, h0, cleaf, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	// A different registry (different members) yields a different root.
	other := testRegistry(t, issuerC)
	if err := art.VerifyChain(proof, h0, cleaf, other.Root(), 3); err == nil {
		t.Error("verify accepted a proof against the wrong registry root")
	}
}
