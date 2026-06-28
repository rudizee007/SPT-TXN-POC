package verifier_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// The optional ZK N-hop seam is gnark-free in the verifier package and accepts a
// real zkproof verifier by injection. Crucially, the leaf-scope commitment is
// derived from the (presented) leaf scope, so the proof is BOUND to it: a proof
// only verifies for the exact leaf scope it was made for.
func TestChainVerifierFunc_Injection(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	usd := zkproof.CurrencyCode("USD")

	// The verifier's own trusted registered-CT-issuer set (F1, phase 1).
	const regSize = 1 << zkproof.VASPTreeDepth
	members := make([][]byte, regSize)
	members[0] = []byte("domain-a.authorg/ct_issuer")
	members[1] = []byte("domain-b.execorg/ct_issuer")
	members[2] = []byte("domain-c.agentorg/ct_issuer")
	for i := 3; i < regSize; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	reg, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: usd, Issuer: members[0]},
		{MaxAmount: 8000, Currency: usd, Issuer: members[1]},
		{MaxAmount: 5000, Currency: usd, Issuer: members[2]}, // leaf
	}
	proof, h0, _, regRoot, err := art.ProveChain([]byte("alice-anchor"), []byte("salt"), 3, hops, reg)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Exactly what a Domain B operator injects: derive CLeaf from the leaf scope,
	// and bind the proof to the operator's OWN trusted registry root (regRoot is
	// captured from the operator's registry, not carried in the proof).
	var cv verifier.ChainVerifierFunc = func(p []byte, anchor *big.Int, leafMax uint64, leafCur string, d uint64) error {
		cleaf := zkproof.LeafScopeCommitment(leafMax, zkproof.CurrencyCode(leafCur))
		return art.VerifyChain(p, anchor, cleaf, regRoot, d)
	}

	// Bound to the real leaf scope (5000 USD, depth 3) → verifies.
	if err := cv(proof, h0, 5000, "USD", 3); err != nil {
		t.Fatalf("valid proof rejected through the seam: %v", err)
	}
	// A different claimed leaf scope must NOT verify (the CLeaf binding).
	if err := cv(proof, h0, 9999, "USD", 3); err == nil {
		t.Error("proof accepted for a leaf scope it was not made for")
	}
	// A different currency must NOT verify.
	if err := cv(proof, h0, 5000, "EUR", 3); err == nil {
		t.Error("proof accepted for a different currency")
	}

	// The engine carries the injected verifier.
	eng := verifier.New(nil)
	eng.ChainVerifier = cv
	if eng.ChainVerifier == nil {
		t.Error("engine did not retain the injected ChainVerifier")
	}
}
