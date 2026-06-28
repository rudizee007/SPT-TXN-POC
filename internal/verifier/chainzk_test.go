package verifier_test

import (
	"math/big"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// The optional ZK N-hop seam is gnark-free in the verifier package and accepts a
// real zkproof verifier by injection: zkproof.Artifacts.VerifyChain satisfies
// verifier.ChainVerifierFunc, validates a genuine chain proof, and rejects a
// tampered one.
func TestChainVerifierFunc_Injection(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: 840},
		{MaxAmount: 8000, Currency: 840},
		{MaxAmount: 5000, Currency: 840},
	}
	proof, h0, cleaf, err := art.ProveChain([]byte("alice-anchor"), []byte("salt"), 3, hops)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// The exact injection a Domain B operator would do: wrap the pinned verifier.
	var cv verifier.ChainVerifierFunc = func(p []byte, a, b *big.Int, d uint64) error {
		return art.VerifyChain(p, a, b, d)
	}

	if err := cv(proof, h0, cleaf, 3); err != nil {
		t.Fatalf("valid proof rejected through the injection seam: %v", err)
	}

	bad := append([]byte(nil), proof...)
	bad[len(bad)-1] ^= 0xff
	if err := cv(bad, h0, cleaf, 3); err == nil {
		t.Error("tampered proof accepted through the injection seam")
	}

	// And the engine carries the injected verifier.
	eng := verifier.New(nil)
	eng.ChainVerifier = cv
	if eng.ChainVerifier == nil {
		t.Error("engine did not retain the injected ChainVerifier")
	}
}
