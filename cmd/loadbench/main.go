// Command loadbench measures the throughput and latency of the SPT-Txn hot path,
// so an integrator (e.g. an AI-agent platform issuing/verifying authorizations at
// machine scale) gets MEASURED numbers rather than estimates.
//
// It benchmarks the operations that actually dominate each path:
//
//   - Ed25519 sign   — minting an SPT-Txn action token (issue side)
//   - Ed25519 verify — the per-hop signature check the cleartext eight-step does
//   - SHA-256        — canonical/context hashing per verify
//   - ZK chain verify — Groth16/BN254 N-hop delegation proof verification (privacy path)
//   - ZK chain prove  — proof GENERATION (the expensive, amortized-per-session op)
//
// Each cheap op is run single-threaded and in parallel (GOMAXPROCS workers) to
// show horizontal scaling. ZK verify is also run in parallel. Proving is timed
// serially over a few iterations (it is slow and done once per delegation chain,
// not per action).
//
// Usage:
//
//	go run ./cmd/loadbench               # full run (includes ZK)
//	go run ./cmd/loadbench -d 5s         # 5s per cheap benchmark
//	go run ./cmd/loadbench -zk=false     # skip the ZK circuit (fast)
//	go run ./cmd/loadbench -hops 4 -proofs 12
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

func main() {
	dur := flag.Duration("d", 3*time.Second, "duration per cheap benchmark")
	doZK := flag.Bool("zk", true, "include the ZK chain prove/verify benchmark")
	hops := flag.Int("hops", 3, "delegation-chain length for the ZK benchmark")
	nProofs := flag.Int("proofs", 8, "number of proofs to time for the prove benchmark")
	flag.Parse()

	// silence gnark's per-proof debug logging so the benchmark output is clean.
	// gnark uses its own logger instance, not the global zerolog level, so
	// SetGlobalLevel does nothing here — logger.Set is the correct knob.
	logger.Set(zerolog.Nop())

	cores := runtime.GOMAXPROCS(0)
	fmt.Printf("SPT-Txn throughput benchmark\n")
	fmt.Printf("cores (GOMAXPROCS)=%d  duration/op=%s  go=%s\n\n", cores, *dur, runtime.Version())

	// ── cheap primitives ────────────────────────────────────────────────────
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	msg := make([]byte, 256) // a representative compact-token signing input
	_, _ = rand.Read(msg)
	sig := ed25519.Sign(priv, msg)

	fmt.Printf("%-26s %-10s %14s %12s\n", "operation", "mode", "ops/sec", "latency")
	fmt.Printf("%s\n", line())

	report("Ed25519 sign (mint)", "1 core", run1(*dur, func() { _ = ed25519.Sign(priv, msg) }))
	report("Ed25519 sign (mint)", fmt.Sprintf("%d cores", cores), runN(*dur, cores, func() { _ = ed25519.Sign(priv, msg) }))

	report("Ed25519 verify", "1 core", run1(*dur, func() { _ = ed25519.Verify(pub, msg, sig) }))
	report("Ed25519 verify", fmt.Sprintf("%d cores", cores), runN(*dur, cores, func() { _ = ed25519.Verify(pub, msg, sig) }))

	report("SHA-256 (256B)", "1 core", run1(*dur, func() { _ = sha256.Sum256(msg) }))
	report("SHA-256 (256B)", fmt.Sprintf("%d cores", cores), runN(*dur, cores, func() { _ = sha256.Sum256(msg) }))

	if !*doZK {
		fmt.Printf("\n(ZK skipped: -zk=false)\n")
		interpret(*hops)
		return
	}

	// ── ZK chain proof ──────────────────────────────────────────────────────
	fmt.Printf("%s\n", line())
	fmt.Printf("building a %d-hop chain + Groth16 setup (one-time)…\n", *hops)
	must(ensureIssuers(*hops))
	art, err := zkproof.Setup(zkproof.CircuitChain)
	must(err)
	depth := uint64(*hops)
	reg := mustReg(*hops)
	hopsData := chainHops(*hops)
	proof, h0, cleaf, regRoot, err := art.ProveChain([]byte("anchor"), []byte("salt"), depth, hopsData, reg)
	must(err)

	// verify throughput (the per-action privacy-path cost)
	verify := func() { _ = art.VerifyChain(proof, h0, cleaf, regRoot, depth) }
	report("ZK chain verify", "1 core", run1batch(*dur, 1, verify))
	report("ZK chain verify", fmt.Sprintf("%d cores", cores), runNbatch(*dur, cores, 1, verify))

	// prove timing (the expensive, once-per-chain op)
	var sum time.Duration
	for i := 0; i < *nProofs; i++ {
		t0 := time.Now()
		_, _, _, _, err := art.ProveChain([]byte("anchor"), []byte("salt"), depth, hopsData, reg)
		must(err)
		sum += time.Since(t0)
	}
	avg := sum / time.Duration(*nProofs)
	fmt.Printf("%-26s %-10s %14s %12s\n", "ZK chain prove", "1 core",
		fmt.Sprintf("%.1f", 1.0/avg.Seconds()), fmtdur(avg))

	interpret(*hops)
}

// ── throughput runners ──────────────────────────────────────────────────────

type result struct {
	opsPerSec float64
	perOp     time.Duration
}

func run1(d time.Duration, fn func()) result      { return run1batch(d, 256, fn) }
func runN(d time.Duration, w int, fn func()) result { return runNbatch(d, w, 256, fn) }

func run1batch(d time.Duration, batch int, fn func()) result {
	start := time.Now()
	deadline := start.Add(d)
	var n int64
	for time.Now().Before(deadline) {
		for i := 0; i < batch; i++ {
			fn()
		}
		n += int64(batch)
	}
	el := time.Since(start)
	return result{float64(n) / el.Seconds(), el / time.Duration(max64(n, 1))}
}

func runNbatch(d time.Duration, workers, batch int, fn func()) result {
	var total int64
	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(d)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c int64
			for time.Now().Before(deadline) {
				for i := 0; i < batch; i++ {
					fn()
				}
				c += int64(batch)
			}
			atomic.AddInt64(&total, c)
		}()
	}
	wg.Wait()
	el := time.Since(start)
	// aggregate latency = wall time / total ops, across all workers
	return result{float64(total) / el.Seconds(), el / time.Duration(max64(total/int64(workers), 1))}
}

func report(op, mode string, r result) {
	fmt.Printf("%-26s %-10s %14s %12s\n", op, mode, human(r.opsPerSec), fmtdur(r.perOp))
}

// ── ZK chain construction (mirrors internal/zkproof chain test setup) ────────

type issuer struct {
	priv *eddsabn254.PrivateKey
	pub  []byte
}

func newIssuer() (issuer, error) {
	p, err := eddsabn254.GenerateKey(rand.Reader)
	if err != nil {
		return issuer{}, err
	}
	return issuer{priv: p, pub: p.PublicKey.Bytes()}, nil
}

func (is issuer) sign(maxAmount, currency uint64) ([]byte, error) {
	var m fr.Element
	m.SetBigInt(zkproof.LeafScopeCommitment(maxAmount, currency))
	return is.priv.Sign(m.Marshal(), gchash.MIMC_BN254.New())
}

// global issuer set so chainHops + mustReg stay consistent within a run.
var gIssuers []issuer

func ensureIssuers(n int) error {
	if len(gIssuers) >= n {
		return nil
	}
	gIssuers = gIssuers[:0]
	for i := 0; i < n; i++ {
		is, err := newIssuer()
		if err != nil {
			return err
		}
		gIssuers = append(gIssuers, is)
	}
	return nil
}

func ceiling(i int) uint64 { return uint64(10000 - i*1000) } // non-increasing (attenuating)

func chainHops(n int) []zkproof.ChainHop {
	hops := make([]zkproof.ChainHop, n)
	for i := 0; i < n; i++ {
		sig, _ := gIssuers[i].sign(ceiling(i), 840)
		hops[i] = zkproof.ChainHop{
			MaxAmount: ceiling(i), Currency: 840,
			IssuerPub: gIssuers[i].pub, Sig: sig,
		}
	}
	return hops
}

func mustReg(n int) *zkproof.MerkleTree {
	const leaves = 1 << zkproof.VASPTreeDepth
	members := make([][]byte, leaves)
	for i := 0; i < n; i++ {
		leaf, err := zkproof.IssuerLeaf(gIssuers[i].pub)
		must(err)
		members[i] = leaf.Bytes()
	}
	for i := n; i < leaves; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	tree, err := zkproof.BuildVASPRegistry(members)
	must(err)
	return tree
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ── formatting helpers ──────────────────────────────────────────────────────

func line() string { return "-----------------------------------------------------------------" }

func human(x float64) string {
	switch {
	case x >= 1e6:
		return fmt.Sprintf("%.2fM", x/1e6)
	case x >= 1e3:
		return fmt.Sprintf("%.1fk", x/1e3)
	default:
		return fmt.Sprintf("%.0f", x)
	}
}

func fmtdur(d time.Duration) string {
	switch {
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	case d >= time.Microsecond:
		return fmt.Sprintf("%.2fµs", float64(d)/float64(time.Microsecond))
	default:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func interpret(hops int) {
	fmt.Printf("\nWhat this means for agentic scale:\n")
	fmt.Printf("  • Minting an action token and verifying it are Ed25519 ops — cheap and\n")
	fmt.Printf("    horizontally scalable; the cleartext eight-step ≈ %d sig-verifies + hashing.\n", hops)
	fmt.Printf("  • The ZK chain proof is generated ONCE per delegation chain/session and\n")
	fmt.Printf("    amortized over every action that agent takes — verify is the per-action cost.\n")
	fmt.Printf("  • Use the cleartext chain for intra-org agent swarms; reserve ZK for cross-org\n")
	fmt.Printf("    or when the delegation path must stay private.\n")
}
