// Command zk-solcalldata produces the calldata for
// AttestationVerifier.anchorVerified: it generates a real threshold proof
// (amount >= threshold, with the amount hidden), then prints the proof bytes,
// the public inputs [commitment, threshold], and a ready-to-run cast command.
//
// Run from the repo root with the pinned keys produced by zk-setup:
//
//	go run ./cmd/zk-solcalldata -dir ./zk -amount 5000 -threshold 1000 \
//	    -root 57ff6da2...1f7c -addr 0xYourAttestationVerifier
//
// Flip a byte in the printed proof and the on-chain call reverts — that's the
// "verify without revealing" property demonstrated on-chain.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

func main() {
	dir := flag.String("dir", "./zk", "directory with pinned setup keys (from zk-setup)")
	amount := flag.Uint64("amount", 5000, "secret amount (must be >= threshold)")
	threshold := flag.Uint64("threshold", 1000, "public threshold")
	root := flag.String("root", "", "32-byte attestation root to anchor (64 hex; e.g. from cmd/anchor)")
	addr := flag.String("addr", "<ADDR>", "deployed AttestationVerifier address")
	flag.Parse()

	log.SetPrefix("zk-solcalldata: ")
	log.SetFlags(0)

	art, err := zkproof.Load(zkproof.CircuitThreshold, *dir)
	if err != nil {
		log.Fatalf("load threshold keys from %s: %v (run zk-setup first)", *dir, err)
	}
	blinding := make([]byte, 32)
	if _, err := rand.Read(blinding); err != nil {
		log.Fatal(err)
	}
	proof, commitment, err := art.ProveThreshold(*amount, blinding, *threshold)
	if err != nil {
		log.Fatalf("prove: %v", err)
	}
	solProof, err := zkproof.MarshalProofSolidity(proof)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	r := strings.TrimPrefix(strings.ToLower(*root), "0x")
	if r == "" {
		r = strings.Repeat("0", 63) + "1" // placeholder non-zero root; pass -root for a real anchor
	}

	fmt.Println("AttestationVerifier.anchorVerified calldata — threshold circuit")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  amount (secret) : %d\n  threshold (pub) : %d\n", *amount, *threshold)
	fmt.Printf("  commitment      : %s\n", commitment.String())
	fmt.Printf("  proof (bytes)   : %s\n\n", solProof)
	fmt.Println("  cast send command:")
	fmt.Printf("    cast send %s \"anchorVerified(bytes,uint256[2],bytes32)\" \\\n", *addr)
	fmt.Printf("      %s \\\n", solProof)
	fmt.Printf("      \"[%s,%d]\" \\\n", commitment.String(), *threshold)
	fmt.Printf("      0x%s --rpc-url \"$RPC\" --private-key \"$PK\"\n", r)
	fmt.Println("\n  (tamper test: change one hex char in the proof bytes — the call reverts)")
}
