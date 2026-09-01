// Command x402-headersize measures what the SPT-Txn authorization-provenance
// extension actually costs on the wire in an x402 v2 PAYMENT-SIGNATURE header.
//
// This exists because a size claim in a standards thread has to be a
// measurement, not arithmetic done on paper. Every number this prints comes
// from a real Groth16 proof over the real chain circuit, a real BN254 field
// element, and a real SHA-256 -- produced by this process, on this run.
//
// WHAT IS MEASURED
//
//	human_anchor      a BN254 field element (32 B), base64url
//	scope_binding     SHA-256 over JCS of the request identity, HTTP method,
//	                  RFC 9530 content digest, and the SELECTED
//	                  PaymentRequirements tuple, base64url
//	zk_proof          Groth16 over BN254, chain circuit, gnark serialization,
//	                  base64url
//	envelope          the extensions wrapper the attestation travels inside
//	PAYMENT-SIGNATURE base64 of the whole PaymentPayload, with and without
//
// WHAT IS NOT MEASURED, and why
//
//	travel_rule is optional and is an IVMS101 SD-JWT whose size is a function
//	of how many attributes the sender discloses. There is no single honest
//	number for it, so it is omitted rather than given a made-up one. Measure it
//	against a concrete disclosure set if a deployment needs the figure.
//
// Delegation depth costs nothing, in bytes OR in time, and both halves were
// measured rather than assumed. Groth16 proofs are constant-size, so the bytes
// do not move. The proving time does not move either, because the circuit is
// FIXED-SIZE at MaxHops: hops beyond the declared depth are still constrained,
// just inactive. Measured 2026-09-01 at 1/2/4 hops: 153/162/169 ms, which is
// noise, and 164 B every time.
//
// An earlier version of this comment said depth "changes the proving time and
// nothing about the bytes". The run disagreed. Corrected here rather than
// quietly, because "does this grow with delegation depth" is the obvious next
// question from anyone reading the numbers, and the honest answer is better
// than the one I expected.
//
// Usage:
//
//	go run ./cmd/x402-headersize -artifacts zk
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	gchash "github.com/consensys/gnark-crypto/hash"

	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
	"github.com/rudizee007/spt-txn-poc/pkg/jcs"
)

// The baseline is the worked example from the x402 v2 exact-scheme spec, so the
// "without extension" column is the protocol's own reference payload rather
// than one chosen to flatter the delta.
const baselinePayload = `{
  "x402Version": 2,
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60
  },
  "payload": {
    "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
    "authorization": {
      "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      "value": "10000",
      "validAfter": "1740672089",
      "validBefore": "1740672154",
      "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
    }
  }
}`

func main() {
	dir := flag.String("artifacts", "zk", "directory holding chain.ccs/.pk/.vk")
	depth := flag.Int("hops", 3,
		"delegation hops to prove, 1..zkproof.MaxHops (changes proving time, not proof size)")
	flag.Parse()

	art, err := zkproof.Load(zkproof.CircuitChain, *dir)
	if err != nil {
		log.Fatalf("load circuit artifacts from %q: %v\n\n"+
			"Run cmd/zk-setup first, or point -artifacts at the directory holding them.", *dir, err)
	}

	proof, anchor, elapsed := proveChain(art, *depth)

	// scope_binding: SHA-256 over JCS of the request identity, the HTTP method,
	// the request-content digest, and the SELECTED PaymentRequirements tuple
	// that PaymentPayload.accepted names. Computed here from the baseline's own
	// accepted block, so it is the real preimage for the real payload below,
	// not a placeholder of the right length.
	//
	// method and content_digest were added after review in x402 issue 3086
	// (Silentpartnercoding, 2026-09-01). Binding only the resource URL lets GET
	// and POST to the same endpoint collide, and two different POST bodies
	// collide, which reproduces one layer up the exact gap this extension
	// exists to close. content_digest is RFC 9530 Content-Digest.
	//
	// Absent means OMITTED, not null: a request with no body leaves the member
	// out of the object entirely. Under JCS those are different bytes, so the
	// rule has to be stated or two conforming implementations disagree.
	//
	// None of this changes a single figure below, because scope_binding is a
	// hash output. That is the point worth making in the thread: the binding
	// got strictly stronger at zero cost on the wire.
	var base map[string]any
	if err := json.Unmarshal([]byte(baselinePayload), &base); err != nil {
		log.Fatalf("baseline payload: %v", err)
	}
	body := []byte(`{"report":"q3","format":"pdf"}`)
	bodySum := sha256.Sum256(body)
	preimage := map[string]any{
		"resource":       "https://api.example/v1/report",
		"method":         "POST",
		"content_digest": "sha-256=:" + base64.StdEncoding.EncodeToString(bodySum[:]) + ":",
		"accepted":       base["accepted"],
	}
	canon, err := jcs.Canonicalize(preimage)
	if err != nil {
		log.Fatalf("canonicalize scope_binding preimage: %v", err)
	}
	sb := sha256.Sum256(canon)

	anchorBytes := anchor.FillBytes(make([]byte, 32))
	b64 := base64.RawURLEncoding.EncodeToString

	attestation := map[string]any{
		"format":           "spt-txn/1",
		"human_anchor":     b64(anchorBytes),
		"scope_binding":    b64(sb[:]),
		"delegation_depth": *depth,
		"zk_proof":         b64(proof),
	}
	attJSON, err := jcs.Canonicalize(attestation)
	if err != nil {
		log.Fatalf("canonicalize attestation: %v", err)
	}

	// The payload as actually carried, extension included.
	base["extensions"] = map[string]any{
		"spt-txn/1": map[string]any{
			"info": map[string]any{"authz_attestation": attestation},
		},
	}
	withExt, err := json.Marshal(base)
	if err != nil {
		log.Fatalf("marshal payload: %v", err)
	}
	// Re-marshal the baseline through the same encoder, so the comparison is
	// between two compact encodings and not between compact and pretty-printed.
	delete(base, "extensions")
	withoutExt, err := json.Marshal(base)
	if err != nil {
		log.Fatalf("marshal baseline: %v", err)
	}

	hdrWith := base64.StdEncoding.EncodeToString(withExt)
	hdrWithout := base64.StdEncoding.EncodeToString(withoutExt)

	fmt.Printf("SPT-Txn x402 extension — measured header cost\n")
	fmt.Printf("measured %s  |  gnark Groth16 / BN254, chain circuit, %d hops, proved in %s\n\n",
		time.Now().UTC().Format("2006-01-02 15:04 MST"), *depth, elapsed.Round(time.Millisecond))

	fmt.Printf("%-42s %10s %10s\n", "component", "raw B", "encoded B")
	fmt.Printf("%-42s %10s %10s\n", "----------------------------------------", "------", "---------")
	row := func(name string, raw, enc int) { fmt.Printf("%-42s %10d %10d\n", name, raw, enc) }
	row("human_anchor (BN254 field element)", len(anchorBytes), len(b64(anchorBytes)))
	row("scope_binding (SHA-256)", len(sb), len(b64(sb[:])))
	row("zk_proof (Groth16 BN254, constant size)", len(proof), len(b64(proof)))
	fmt.Println()
	row("authz_attestation object (JCS)", len(attJSON), len(attJSON))
	envelope := (len(withExt) - len(withoutExt)) - len(attJSON)
	row("extensions envelope (wrapper keys only)", envelope, envelope)
	fmt.Println()
	row("PaymentPayload, no extension", len(withoutExt), len(hdrWithout))
	row("PaymentPayload, with extension", len(withExt), len(hdrWith))
	row("DELTA added by the extension", len(withExt)-len(withoutExt), len(hdrWith)-len(hdrWithout))

	fmt.Println()
	const budget = 8192
	fmt.Printf("PAYMENT-SIGNATURE header, base64 as carried: %d B\n", len(hdrWith))
	fmt.Printf("against a common 8 KB total-header cap:      %.1f%% of budget\n",
		100*float64(len(hdrWith))/budget)
	fmt.Printf("\nNotes\n")
	fmt.Printf("  * Delegation depth is free, in bytes and in time. Groth16 proofs\n")
	fmt.Printf("    are constant-size, and the circuit is fixed-size at %d hops, so\n",
		zkproof.MaxHops)
	fmt.Printf("    hops beyond the declared depth are constrained but inactive.\n")
	fmt.Printf("    Re-run with -hops to confirm: neither figure moves.\n")
	fmt.Printf("  * travel_rule is omitted. It is an optional IVMS101 SD-JWT whose\n")
	fmt.Printf("    size depends on how many attributes are disclosed, so there is no\n")
	fmt.Printf("    single honest figure for it.\n")
	fmt.Printf("  * The 8 KB figure is a common proxy/gateway default, not a standard.\n")
	fmt.Printf("    It is the constraint that bites in deployment, so it is the one\n")
	fmt.Printf("    worth reporting against.\n")
	os.Exit(0)
}

// proveChain produces a real proof over a real attenuating chain.
func proveChain(art *zkproof.Artifacts, hops int) (zkproof.ProofBytes, *big.Int, time.Duration) {
	if hops < 1 || hops > zkproof.MaxHops {
		log.Fatalf("-hops must be in [1,%d]: the circuit is fixed-size, which is what "+
			"keeps the proof constant-size", zkproof.MaxHops)
	}
	type issuer struct {
		priv *eddsabn254.PrivateKey
		pub  []byte
	}
	issuers := make([]issuer, hops)
	pubs := make([][]byte, hops)
	for i := range issuers {
		p, err := eddsabn254.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		issuers[i] = issuer{priv: p, pub: p.PublicKey.Bytes()}
		pubs[i] = issuers[i].pub
	}

	const n = 1 << zkproof.VASPTreeDepth
	members := make([][]byte, n)
	for i, pub := range pubs {
		leaf, err := zkproof.IssuerLeaf(pub)
		if err != nil {
			log.Fatalf("issuer leaf: %v", err)
		}
		members[i] = leaf.Bytes()
	}
	for i := len(pubs); i < n; i++ {
		members[i] = []byte(fmt.Sprintf("pad-%d", i))
	}
	reg, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		log.Fatalf("build registry: %v", err)
	}

	// A genuinely attenuating chain: each hop narrows, currency constant.
	chain := make([]zkproof.ChainHop, hops)
	amount := uint64(10000)
	for i := range chain {
		var m fr.Element
		m.SetBigInt(zkproof.LeafScopeCommitment(amount, 840))
		sig, err := issuers[i].priv.Sign(m.Marshal(), gchash.MIMC_BN254.New())
		if err != nil {
			log.Fatalf("sign hop %d: %v", i, err)
		}
		chain[i] = zkproof.ChainHop{
			MaxAmount: amount, Currency: 840,
			IssuerPub: issuers[i].pub, Sig: sig,
		}
		amount -= 1000
	}

	start := time.Now()
	proof, h0, _, _, err := art.ProveChain([]byte("measurement-anchor-material"),
		[]byte("measurement-salt"), uint64(hops), chain, reg)
	if err != nil {
		log.Fatalf("prove chain: %v", err)
	}
	return proof, h0, time.Since(start)
}
