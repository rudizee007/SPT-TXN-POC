package verifier_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"

	"github.com/rudizee007/spt-txn-poc/internal/verifier"
	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
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
	// The root now arrives as a PARAMETER rather than being captured, so the
	// engine can perturb it and prove the closure binds it.
	var cv verifier.ChainVerifierFunc = func(p []byte, anchor, root *big.Int, leafMax uint64, leafCur string, d uint64) error {
		cleaf := zkproof.LeafScopeCommitment(leafMax, zkproof.CurrencyCode(leafCur))
		return art.VerifyChain(p, anchor, cleaf, root, d)
	}

	// Bound to the real leaf scope (5000 USD, depth 3) → verifies.
	if err := cv(proof, h0, regRoot, 5000, "USD", 3); err != nil {
		t.Fatalf("valid proof rejected through the seam: %v", err)
	}
	// A different claimed leaf scope must NOT verify (the CLeaf binding).
	if err := cv(proof, h0, regRoot, 9999, "USD", 3); err == nil {
		t.Error("proof accepted for a leaf scope it was not made for")
	}
	// A different currency must NOT verify.
	if err := cv(proof, h0, regRoot, 5000, "EUR", 3); err == nil {
		t.Error("proof accepted for a different currency")
	}

	vec := verifier.ChainSelfTestVector{
		Proof: proof, H0: h0, LeafMaxAmount: 5000, LeafCurrency: "USD", MaxDepth: 3,
	}

	// A correctly-wired verifier passes the whole battery and ZK mode enables.
	eng := verifier.New(nil)
	if err := eng.EnableChainZK(cv, regRoot, 5*time.Minute, vec); err != nil {
		t.Fatalf("a correctly-wired verifier was refused: %v", err)
	}

	// An unbounded leaf window is refused. Without a bound, a revoked
	// intermediate keeps granting authority until the original grant expires,
	// and this path never consults its status — so "unbounded" is the exact
	// state the parameter exists to prevent, and a zero value must not be
	// silently read as "no limit".
	engNoBound := verifier.New(nil)
	if err := engNoBound.EnableChainZK(cv, regRoot, 0, vec); err == nil {
		t.Fatal("SECURITY: ZK mode enabled with an unbounded leaf window")
	}
	if err := engNoBound.EnableChainZK(cv, regRoot, -time.Second, vec); err == nil {
		t.Fatal("SECURITY: ZK mode enabled with a negative leaf window")
	}

	// And the battery is not decorative. A closure that ignores the registry
	// root — the exact mistake the parameter was added to expose, and the shape
	// cmd/zk-bench models — must be REFUSED, not merely warned about.
	ignoresRoot := func(p []byte, anchor, _ *big.Int, leafMax uint64, leafCur string, d uint64) error {
		cleaf := zkproof.LeafScopeCommitment(leafMax, zkproof.CurrencyCode(leafCur))
		return art.VerifyChain(p, anchor, cleaf, regRoot, d) // captured, not the argument
	}
	eng2 := verifier.New(nil)
	if err := eng2.EnableChainZK(ignoresRoot, regRoot, 5*time.Minute, vec); err == nil {
		t.Fatal("SECURITY: a verifier that ignores the trusted issuer root was enabled; " +
			"it would accept a chain signed by keys the prover chose")
	}

	// A verifier that ignores the leaf scope must be refused too — same
	// principle, different binding.
	ignoresLeaf := func(p []byte, anchor, root *big.Int, _ uint64, _ string, d uint64) error {
		cleaf := zkproof.LeafScopeCommitment(5000, zkproof.CurrencyCode("USD"))
		return art.VerifyChain(p, anchor, cleaf, root, d)
	}
	eng3 := verifier.New(nil)
	if err := eng3.EnableChainZK(ignoresLeaf, regRoot, 5*time.Minute, vec); err == nil {
		t.Fatal("SECURITY: a verifier that ignores the presented leaf scope was enabled")
	}
}
