// cmd/zk-bench — isolated ZK primitive benchmark for the SPT-Txn v2 crypto choice.
//
// Measures constraints / compile / setup / prove / verify / proof-size for a
// representative circuit (N sequential 2-input field hashes) across the two
// decision axes:
//
//   hash:  MiMC      vs  Poseidon2
//   curve: BN254     vs  BLS12-381
//
// It deliberately uses a throwaway circuit (not the production circuits) so the
// benchmark cannot affect deployed code. The output is the empirical basis for
// the -02 "we measured and chose" table and the CBOM "measured" column.
//
// Run:  go run ./cmd/zk-bench            (default 200 hashes)
//       go run ./cmd/zk-bench -iters 500
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"time"

	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

// hashBench computes a chain of Iters two-input hashes and constrains the result
// to be non-zero. Iters/UseP2 are plain config fields (not gnark Variables) and
// are ignored by the witness schema.
type hashBench struct {
	Pre   frontend.Variable `gnark:",secret"`
	Iters int
	UseP2 bool
}

func (c *hashBench) Define(api frontend.API) error {
	cur := c.Pre
	if c.UseP2 {
		h, err := poseidon2.New(api)
		if err != nil {
			return err
		}
		for i := 0; i < c.Iters; i++ {
			h.Reset()
			h.Write(cur, cur)
			cur = h.Sum()
		}
	} else {
		h, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}
		for i := 0; i < c.Iters; i++ {
			h.Reset()
			h.Write(cur, cur)
			cur = h.Sum()
		}
	}
	api.AssertIsDifferent(cur, 0)
	return nil
}

func run(curveName string, curve ecc.ID, useP2 bool, iters int) {
	hashName := "MiMC"
	if useP2 {
		hashName = "Poseidon2"
	}
	circ := &hashBench{Iters: iters, UseP2: useP2}

	t := time.Now()
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circ)
	if err != nil {
		fmt.Printf("%-10s %-10s  compile FAILED: %v\n", hashName, curveName, err)
		return
	}
	compileT := time.Since(t)
	nc := ccs.GetNbConstraints()

	t = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("%-10s %-10s  setup FAILED: %v\n", hashName, curveName, err)
		return
	}
	setupT := time.Since(t)

	w := &hashBench{Pre: 12345, Iters: iters, UseP2: useP2}
	full, err := frontend.NewWitness(w, curve.ScalarField())
	if err != nil {
		fmt.Printf("%-10s %-10s  witness FAILED: %v\n", hashName, curveName, err)
		return
	}
	pub, _ := full.Public()

	t = time.Now()
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		fmt.Printf("%-10s %-10s  prove FAILED: %v\n", hashName, curveName, err)
		return
	}
	proveT := time.Since(t)

	var buf bytes.Buffer
	_, _ = proof.WriteTo(&buf)
	proofSize := buf.Len()

	t = time.Now()
	verr := groth16.Verify(proof, vk, pub)
	verifyT := time.Since(t)
	ok := "ok"
	if verr != nil {
		ok = "VERIFY-FAIL"
	}

	fmt.Printf("%-10s %-10s  cons=%-7d  compile=%-9s setup=%-9s prove=%-9s verify=%-9s proof=%dB  %s\n",
		hashName, curveName, nc,
		compileT.Round(time.Millisecond), setupT.Round(time.Millisecond),
		proveT.Round(time.Millisecond), verifyT.Round(time.Microsecond),
		proofSize, ok)
}

func main() {
	iters := flag.Int("iters", 200, "number of sequential 2-input hashes in the bench circuit")
	prod := flag.Bool("prod", false, "benchmark the production circuits (commitment, threshold, chain) instead of the hash comparison")
	flag.Parse()

	if *prod {
		benchProd()
		return
	}

	fmt.Printf("=== zk-bench: %d sequential 2-input hashes · Groth16 ===\n", *iters)
	for _, useP2 := range []bool{false, true} {
		run("BN254", ecc.BN254, useP2, *iters)
		run("BLS12-381", ecc.BLS12_381, useP2, *iters)
	}
}

// benchProd reports real metrics (constraints / setup / prove / verify / proof
// size) for the production circuits, including the agentic delegation-chain
// proof — the empirical table for a paper/grant. Each does a representative
// Setup + Prove + Verify on Poseidon2/BN254 (the deployed configuration).
func benchProd() {
	fmt.Println("=== zk-bench: production circuits · Groth16 / BN254 / Poseidon2 ===")

	// commitment: knowledge of (id, randomness) behind a humanAnchor.
	t := time.Now()
	a, err := zkproof.Setup(zkproof.CircuitCommitment)
	if err != nil {
		log.Fatalf("commitment setup: %v", err)
	}
	st := time.Since(t)
	t = time.Now()
	cp, anc, err := a.ProveCommitment([]byte("id-material"), []byte("randomness"))
	if err != nil {
		log.Fatalf("commitment prove: %v", err)
	}
	pt := time.Since(t)
	t = time.Now()
	if err := a.VerifyCommitment(cp, anc); err != nil {
		log.Fatalf("commitment verify: %v", err)
	}
	reportProd("commitment", a.NbConstraints(), st, pt, time.Since(t), len(cp))

	// threshold: amount >= threshold, amount hidden.
	t = time.Now()
	a, err = zkproof.Setup(zkproof.CircuitThreshold)
	if err != nil {
		log.Fatalf("threshold setup: %v", err)
	}
	st = time.Since(t)
	t = time.Now()
	tp, commit, err := a.ProveThreshold(5000, []byte("blinding"), 1000)
	if err != nil {
		log.Fatalf("threshold prove: %v", err)
	}
	pt = time.Since(t)
	t = time.Now()
	if err := a.VerifyThreshold(tp, commit, 1000); err != nil {
		log.Fatalf("threshold verify: %v", err)
	}
	reportProd("threshold", a.NbConstraints(), st, pt, time.Since(t), len(tp))

	// chain: agentic delegation-chain attenuation, intermediate scopes hidden,
	// each active hop proven to carry a registered CT-issuer's Baby Jubjub
	// signature over its scope (F1, phase 2).
	const regSize = 1 << zkproof.VASPTreeDepth
	type benchIssuer struct {
		priv *eddsabn254.PrivateKey
		pub  []byte
	}
	mkIssuer := func() benchIssuer {
		p, e := eddsabn254.GenerateKey(rand.Reader)
		if e != nil {
			log.Fatalf("chain keygen: %v", e)
		}
		return benchIssuer{priv: p, pub: p.PublicKey.Bytes()}
	}
	signHop := func(iss benchIssuer, amt, cur uint64) []byte {
		var m fr.Element
		m.SetBigInt(zkproof.LeafScopeCommitment(amt, cur))
		s, e := iss.priv.Sign(m.Marshal(), gchash.MIMC_BN254.New())
		if e != nil {
			log.Fatalf("chain sign: %v", e)
		}
		return s
	}
	issuers := []benchIssuer{mkIssuer(), mkIssuer(), mkIssuer()}
	members := make([][]byte, regSize)
	for i, iss := range issuers {
		leaf, e := zkproof.IssuerLeaf(iss.pub)
		if e != nil {
			log.Fatalf("chain issuer leaf: %v", e)
		}
		members[i] = leaf.Bytes()
	}
	for i := len(issuers); i < regSize; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	reg, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		log.Fatalf("chain registry: %v", err)
	}
	hops := []zkproof.ChainHop{
		{MaxAmount: 10000, Currency: 840, IssuerPub: issuers[0].pub, Sig: signHop(issuers[0], 10000, 840)},
		{MaxAmount: 8000, Currency: 840, IssuerPub: issuers[1].pub, Sig: signHop(issuers[1], 8000, 840)},
		{MaxAmount: 5000, Currency: 840, IssuerPub: issuers[2].pub, Sig: signHop(issuers[2], 5000, 840)},
	}
	t = time.Now()
	a, err = zkproof.Setup(zkproof.CircuitChain)
	if err != nil {
		log.Fatalf("chain setup: %v", err)
	}
	st = time.Since(t)
	t = time.Now()
	chp, h0, cleaf, regRoot, err := a.ProveChain([]byte("alice-anchor"), []byte("salt"), 3, hops, reg)
	if err != nil {
		log.Fatalf("chain prove: %v", err)
	}
	pt = time.Since(t)
	t = time.Now()
	if err := a.VerifyChain(chp, h0, cleaf, regRoot, 3); err != nil {
		log.Fatalf("chain verify: %v", err)
	}
	reportProd("chain", a.NbConstraints(), st, pt, time.Since(t), len(chp))
}

func reportProd(name string, cons int, setup, prove, verify time.Duration, size int) {
	fmt.Printf("%-12s cons=%-6d setup=%-9s prove=%-9s verify=%-9s proof=%dB\n",
		name, cons, setup.Round(time.Millisecond), prove.Round(time.Millisecond),
		verify.Round(time.Microsecond), size)
}
