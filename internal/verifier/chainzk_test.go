package verifier_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"

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

	// The verifier's own trusted registered-CT-issuer set (F1). Each hop carries
	// a real Baby Jubjub signature from a registered issuer over its scope.
	const regSize = 1 << zkproof.VASPTreeDepth
	type iss struct {
		priv *eddsabn254.PrivateKey
		pub  []byte
	}
	mk := func() iss {
		p, e := eddsabn254.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatalf("keygen: %v", e)
		}
		return iss{priv: p, pub: p.PublicKey.Bytes()}
	}
	sign := func(s iss, amt, cur uint64) []byte {
		var m fr.Element
		m.SetBigInt(zkproof.LeafScopeCommitment(amt, cur))
		sig, e := s.priv.Sign(m.Marshal(), gchash.MIMC_BN254.New())
		if e != nil {
			t.Fatalf("sign: %v", e)
		}
		return sig
	}
	issuers := []iss{mk(), mk(), mk()}
	members := make([][]byte, regSize)
	for i, s := range issuers {
		leaf, e := zkproof.IssuerLeaf(s.pub)
		if e != nil {
			t.Fatalf("issuer leaf: %v", e)
		}
		members[i] = leaf.Bytes()
	}
	for i := len(issuers); i < regSize; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	reg, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: usd, IssuerPub: issuers[0].pub, Sig: sign(issuers[0], 10000, usd)},
		{MaxAmount: 8000, Currency: usd, IssuerPub: issuers[1].pub, Sig: sign(issuers[1], 8000, usd)},
		{MaxAmount: 5000, Currency: usd, IssuerPub: issuers[2].pub, Sig: sign(issuers[2], 5000, usd)}, // leaf
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
