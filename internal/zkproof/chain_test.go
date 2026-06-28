package zkproof_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// testIssuer is a registered CT-issuer holding a Baby Jubjub signing key.
type testIssuer struct {
	priv *eddsabn254.PrivateKey
	pub  []byte
}

func newIssuer(t *testing.T) testIssuer {
	t.Helper()
	p, err := eddsabn254.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return testIssuer{priv: p, pub: p.PublicKey.Bytes()}
}

// sign produces this issuer's EdDSA signature over a hop's scope commitment.
func (iss testIssuer) sign(t *testing.T, maxAmount, currency uint64) []byte {
	t.Helper()
	var m fr.Element
	m.SetBigInt(zkproof.LeafScopeCommitment(maxAmount, currency))
	sig, err := iss.priv.Sign(m.Marshal(), gchash.MIMC_BN254.New())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// hop builds a fully-signed chain hop issued by iss.
func hop(t *testing.T, iss testIssuer, maxAmount, currency uint64) zkproof.ChainHop {
	t.Helper()
	return zkproof.ChainHop{
		MaxAmount: maxAmount, Currency: currency,
		IssuerPub: iss.pub, Sig: iss.sign(t, maxAmount, currency),
	}
}

// testRegistry builds a full depth-VASPTreeDepth (256-leaf) registered-CT-issuer
// tree whose leaves are IssuerLeaf(pub) for the given issuers (rest are padding).
func testRegistry(t *testing.T, pubs ...[]byte) *zkproof.MerkleTree {
	t.Helper()
	const n = 1 << zkproof.VASPTreeDepth
	members := make([][]byte, n)
	for i, pub := range pubs {
		leaf, err := zkproof.IssuerLeaf(pub)
		if err != nil {
			t.Fatalf("issuer leaf: %v", err)
		}
		members[i] = leaf.Bytes()
	}
	for i := len(pubs); i < n; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	tree, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return tree
}

// A valid 3-hop chain (10000 -> 8000 -> 5000, same currency, depth 3), each hop
// signed by a registered CT-issuer, proves and verifies; a wrong declared depth
// is rejected.
func TestChain_ProveVerify(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a, b, c := newIssuer(t), newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub, c.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 10000, 840), // root CAT ceiling
		hop(t, b, 8000, 840),  // CT
		hop(t, c, 5000, 840),  // leaf (agent)
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
	a, b := newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		hop(t, b, 9000, 840), // widens above parent — escalation
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
	a, b := newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		hop(t, b, 5000, 978), // currency changed
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
	a, b, c := newIssuer(t), newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub, c.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		hop(t, b, 5000, 840),
		hop(t, c, 3000, 840),
	}
	// 3 hops need depth >= 2; declaring maxDepth=1 must be refused.
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 1, hops, reg); err == nil {
		t.Error("prove accepted a chain deeper than maxDepth")
	}
}

// A hop whose issuer is NOT in the registered-CT-issuer registry cannot be proved.
func TestChain_RejectsUnregisteredIssuer(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a, b := newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub) // b intentionally NOT registered
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		hop(t, b, 5000, 840), // unregistered issuer
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a hop issued by an unregistered issuer")
	}
}

// F1 phase 2: naming a registered issuer is not enough — the hop must carry that
// issuer's actual signature. A hop claiming issuer b but signed by issuer a fails.
func TestChain_RejectsWrongSigner(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a, b := newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		{MaxAmount: 5000, Currency: 840, IssuerPub: b.pub, Sig: a.sign(t, 5000, 840)}, // b named, a signed
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a hop signed by a different issuer than it names")
	}
}

// F1 phase 2: the signature binds the scope. A hop claiming 5000 but carrying a
// signature over 4000 (same registered issuer) fails.
func TestChain_RejectsScopeNotSigned(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a, b := newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		{MaxAmount: 5000, Currency: 840, IssuerPub: b.pub, Sig: b.sign(t, 4000, 840)}, // signed 4000, claims 5000
	}
	if _, _, _, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg); err == nil {
		t.Error("prove accepted a hop whose scope was not the one signed")
	}
}

// A proof made against one registry must not verify against a different registry
// root (the public RegRoot binds the proof to the verifier's trusted issuer set).
func TestChain_RejectsWrongRegRoot(t *testing.T) {
	art, err := zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a, b, c := newIssuer(t), newIssuer(t), newIssuer(t)
	reg := testRegistry(t, a.pub, b.pub)
	hops := []zkproof.ChainHop{
		hop(t, a, 8000, 840),
		hop(t, b, 5000, 840),
	}
	proof, h0, cleaf, _, err := art.ProveChain([]byte("a"), []byte("s"), 3, hops, reg)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	other := testRegistry(t, c.pub) // different members → different root
	if err := art.VerifyChain(proof, h0, cleaf, other.Root(), 3); err == nil {
		t.Error("verify accepted a proof against the wrong registry root")
	}
}
