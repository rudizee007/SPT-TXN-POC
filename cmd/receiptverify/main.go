// Command receiptverify verifies a Transaction Receipt offline, for auditors:
//
//  1. the receipt signature against the log public key,
//  2. (optionally) the receipt's inclusion in a presented transparency log,
//  3. (optionally) the log's published signed Merkle root.
//
// Spec: docs/spec/RECEIPT-FORMAT.md §2.2. Exit code 0 only if every requested
// check holds. Unlike the PEP's uniform wire errors, this tool is maximally
// explicit about which check failed — it talks to auditors, not attackers.
//
// Usage:
//
//	receiptverify -receipt r.json -logpub <hex ed25519 pub>
//	receiptverify -receipt r.json -logpub <hex> -log audit.jsonl -root root.json
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rudizee007/spt-txn-poc/internal/audit"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

func main() {
	receiptPath := flag.String("receipt", "", "path to receipt JSON (required)")
	logPubHex := flag.String("logpub", "", "hex-encoded Ed25519 log public key (required)")
	logPath := flag.String("log", "", "path to transparency log JSONL (optional; enables inclusion check)")
	rootPath := flag.String("root", "", "path to signed Merkle root JSON (optional; requires -log)")
	flag.Parse()

	if *receiptPath == "" || *logPubHex == "" {
		flag.Usage()
		os.Exit(2)
	}

	logPub, err := decodePub(*logPubHex)
	if err != nil {
		fail("log public key: %v", err)
	}

	// ── 1. Receipt signature ─────────────────────────────────────────
	raw, err := os.ReadFile(*receiptPath)
	if err != nil {
		fail("read receipt: %v", err)
	}
	var r receipt.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		fail("decode receipt: %v", err)
	}
	if err := r.Verify(logPub); err != nil {
		fail("SIGNATURE: %v", err)
	}
	rHash, err := r.Hash()
	if err != nil {
		fail("receipt hash: %v", err)
	}
	fmt.Printf("ok  signature      %s decision=%s class=%s rule=%s\n", r.PEP, r.Decision, r.Class, r.RulePath)
	fmt.Printf("    receipt hash   %s\n", rHash)

	if *logPath == "" {
		fmt.Println("ok  (no log presented; inclusion not checked)")
		return
	}

	// ── 2. Inclusion in the presented log ────────────────────────────
	log, err := audit.Open(*logPath)
	if err != nil {
		fail("open log: %v", err)
	}
	defer log.Close()
	if err := log.Verify(); err != nil {
		fail("LOG CHAIN: %v", err)
	}
	entries := log.Entries()
	idx := -1
	for i, e := range entries {
		if e.Type == receiptlog.EventType && e.Subject == rHash {
			idx = i
			break
		}
	}
	if idx < 0 {
		fail("INCLUSION: receipt %s not found in presented log", rHash)
	}
	path, err := audit.MerkleProof(entries, idx)
	if err != nil {
		fail("INCLUSION: build proof: %v", err)
	}
	root := audit.MerkleRoot(entries)
	if !audit.VerifyInclusion(entries[idx].Hash, idx, len(entries), path, root) {
		fail("INCLUSION: proof does not verify against recomputed root")
	}
	fmt.Printf("ok  inclusion      entry %d of %d, hash-chain intact\n", idx, len(entries))

	if *rootPath == "" {
		fmt.Println("ok  (no signed root presented; publication not checked)")
		return
	}

	// ── 3. Published signed root ─────────────────────────────────────
	rootRaw, err := os.ReadFile(*rootPath)
	if err != nil {
		fail("read signed root: %v", err)
	}
	var sr audit.SignedRoot
	if err := json.Unmarshal(rootRaw, &sr); err != nil {
		fail("decode signed root: %v", err)
	}
	if !audit.VerifyRoot(sr, logPub) {
		fail("ROOT SIGNATURE: published root does not verify under the log key")
	}
	if sr.Count > len(entries) {
		fail("ROOT: published root covers %d entries but log presents %d", sr.Count, len(entries))
	}
	prefixRoot := audit.MerkleRoot(entries[:sr.Count])
	if hex.EncodeToString(prefixRoot) != hex.EncodeToString(sr.Root) {
		fail("ROOT: log prefix of %d entries does not reproduce the published root (history rewritten?)", sr.Count)
	}
	if idx >= sr.Count {
		fail("ROOT: receipt entry %d is newer than the published root (covers %d); present a newer root", idx, sr.Count)
	}
	prefixPath, err := audit.MerkleProof(entries[:sr.Count], idx)
	if err != nil {
		fail("ROOT: prefix proof: %v", err)
	}
	if !audit.VerifyInclusion(entries[idx].Hash, idx, sr.Count, prefixPath, sr.Root) {
		fail("ROOT: inclusion under the PUBLISHED root failed")
	}
	fmt.Printf("ok  published root count=%d time=%d — receipt provably included\n", sr.Count, sr.Time)
}

func decodePub(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
