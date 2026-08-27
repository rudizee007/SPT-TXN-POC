// Command conformance emits (and re-checks) deterministic SPT-Txn conformance
// vectors: the canonical spt_txn_context_hash for a fixed transaction on each
// chain, and the humanAnchor commitment for fixed identity material. These are
// the parts of the protocol that are fully deterministic (no signatures, no
// clocks), so any independent implementation can be checked against them.
//
//	go run ./cmd/conformance -write           # write docs/conformance-vectors.json
//	go run ./cmd/conformance -check           # re-derive and fail (exit 1) on drift
//
// `-check` belongs in CI: it proves the canonical encoding and the zkDID
// commitment have not changed underneath the published vectors.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
)

type ctxVec struct {
	Chain       string `json:"chain"`
	Originator  string `json:"originator"`
	Beneficiary string `json:"beneficiary"`
	Amount      string `json:"amount"`
	Currency    string `json:"currency"`
	Timestamp   int64  `json:"timestamp"`
	ContextHash string `json:"spt_txn_context_hash"`
}

type anchorVec struct {
	Secret      string `json:"secret"`
	Blinding    string `json:"blinding"`
	HumanAnchor string `json:"human_anchor"`
}

type vectors struct {
	Version       int         `json:"version"`
	Note          string      `json:"note"`
	ContextHashes []ctxVec    `json:"context_hashes"`
	HumanAnchors  []anchorVec `json:"human_anchors"`
}

// fixed sample transfers per chain (shape-valid for each adapter).
var samples = []struct{ chain, orig, ben, cur string }{
	{"xrpl", "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT", "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW", "USD"},
	{"ethereum", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH"},
	{"arbitrum", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH"},
	{"bsc", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "BNB"},
	{"morph", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH"},
	{"xlayer", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "OKB"},
	{"optimism", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH"},
	{"base", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH"},
	{"avalanche", "0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "AVAX"},
	{"xdc", "xdc0102030405060708090a0b0c0d0e0f1011121314", "xdcfFEEdDcCBbAa99887766554433221100ffEEddCc", "XDC"},
	{"starknet", "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "STRK"},
	{"aptos", "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "APT"},
	{"sui", "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "SUI"},
	{"solana", "BeWdnfiJ52LpaGudU6ZhGLVcpeBEYxHYewZC4DZopVi4", "HiHP5wBk1iVLMPM42MviMqBirdSbaaQ9Szida8tGwVR2", "SOL"},
	{"stellar", "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW", "G234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ", "XLM"},
	{"hedera", "0.0.1001", "0.0.2002", "HBAR"},
	{"algorand", "KNTKMJFYXI2B43M7G4LJ3KU5I452GORN3FCDDMFUEHF7Q3OBNND3OQENZE", "IGIOJAQMOL2F42RGONSM6ONMYZ2M22TNDZODKIOT7TK7IRXGCZXQMHEKQY", "ALGO"},
	{"polkadot", "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "DOT"},
}

var anchors = []struct{ secret, blinding string }{
	{"alice@example.org", "randomness-0001"},
	{"bob@example.org", "randomness-0002"},
}

const amount = "5000.00"
const ts = int64(1750000000)

func build() (vectors, error) {
	v := vectors{
		Version: 1,
		Note:    "Deterministic SPT-Txn conformance vectors: spt_txn_context_hash per chain (canonical preimage, SHA-256) and humanAnchor = zkdid.Compute(secret, blinding), the canonical 32-byte big-endian field element, hex-encoded to 64 characters. Signatures/timestamps in real tokens are not covered here.",
	}
	for _, s := range samples {
		l, err := ledger.Get(s.chain)
		if err != nil {
			return v, fmt.Errorf("get %s: %w", s.chain, err)
		}
		tc := ledger.TxnContext{Chain: s.chain, Originator: s.orig, Beneficiary: s.ben, Amount: amount, Currency: s.cur, Timestamp: ts}
		_, h, err := ledger.ContextHash(l, tc)
		if err != nil {
			return v, fmt.Errorf("context hash %s: %w", s.chain, err)
		}
		v.ContextHashes = append(v.ContextHashes, ctxVec{s.chain, s.orig, s.ben, amount, s.cur, ts, h})
	}
	for _, a := range anchors {
		// zkdid.Compute, not BigOf(...).Text(16).
		//
		// Text(16) renders a big.Int as MINIMAL hex: no leading zeros, variable
		// length. The published vector for alice@example.org was 63 characters
		// -- not a whole number of bytes, and impossible for a 32-byte value.
		// Roughly one anchor in sixteen starts with a zero nibble, so the
		// defect appeared for one of the two vectors and not the other.
		//
		// It never reached a token: zkdid.Compute marshals the field element
		// into a fixed [32]byte and Commitment.String hex-encodes all 32. Only
		// this file rendered it a second way -- and this file is the artifact
		// external implementers build against, which is the worst place to
		// publish a shape nothing else produces. An implementer padding a
		// 63-character anchor differently from us computes a different
		// humanAnchor commitment for the same person.
		//
		// Fixed by DELETING the second rendering rather than padding it: the
		// vector now comes from the same call the token does.
		h := zkdid.Compute([]byte(a.secret), []byte(a.blinding)).String()
		v.HumanAnchors = append(v.HumanAnchors, anchorVec{a.secret, a.blinding, h})
	}
	return v, nil
}

// classifyDrift explains WHICH KIND of drift occurred, because the two kinds
// need opposite responses and the byte comparison cannot tell them apart.
//
// STALE (additions only): a new chain or anchor was added and nobody re-ran
// `-write`. Every previously published hash is unchanged. Regenerate and commit.
//
// ENCODING CHANGED: a hash that was already published now computes differently.
// That is threat #1 in docs/THREAT-MODEL.md — the issuer and the verifier
// canonicalize a request differently and the result is authorization bypass.
// docs/conformance-vectors.json is the public interop contract, so a changed
// value means anyone who implemented against the docs disagrees with this code.
// NEVER regenerate to clear it.
//
// This function exists because the original check reported the ENCODING CHANGED
// message for every difference, and then did so for six weeks over three added
// rows (bsc/morph/xlayer, added 2026-06-30, one day after the vectors were last
// written). A gate whose only output is its worst case, fired for its most
// benign cause, stops being read — and this one stopped being read in the
// repository where canonicalization is the first-listed bug class.
func classifyDrift(have []byte, rederived vectors, path string) {
	var old vectors
	if err := json.Unmarshal(have, &old); err != nil {
		fmt.Fprintf(os.Stderr, "CONFORMANCE DRIFT: %s could not be parsed: %v\n", path, err)
		return
	}

	// Index the committed hashes by the identity of the case, not by position:
	// reordering is not drift, and treating it as such is another false alarm.
	type key struct{ chain, orig, benef, amount, currency string }
	oldCtx := map[key]string{}
	for _, c := range old.ContextHashes {
		oldCtx[key{c.Chain, c.Originator, c.Beneficiary, c.Amount, c.Currency}] = c.ContextHash
	}
	oldAnchor := map[string]string{}
	for _, a := range old.HumanAnchors {
		oldAnchor[a.Secret+"|"+a.Blinding] = a.HumanAnchor
	}

	var changed, added []string
	for _, c := range rederived.ContextHashes {
		k := key{c.Chain, c.Originator, c.Beneficiary, c.Amount, c.Currency}
		prev, ok := oldCtx[k]
		switch {
		case !ok:
			added = append(added, "context/"+c.Chain)
		case prev != c.ContextHash:
			changed = append(changed, fmt.Sprintf("context/%s: %s -> %s", c.Chain, prev, c.ContextHash))
		}
	}
	for _, a := range rederived.HumanAnchors {
		prev, ok := oldAnchor[a.Secret+"|"+a.Blinding]
		switch {
		case !ok:
			added = append(added, "anchor/"+a.Secret)
		case prev != a.HumanAnchor:
			changed = append(changed, fmt.Sprintf("anchor/%s: %s -> %s", a.Secret, prev, a.HumanAnchor))
		}
	}

	if len(changed) > 0 {
		fmt.Fprintf(os.Stderr,
			"CONFORMANCE DRIFT — ENCODING CHANGED. %d already-published value(s) now compute differently:\n",
			len(changed))
		for _, c := range changed {
			fmt.Fprintf(os.Stderr, "  %s\n", c)
		}
		fmt.Fprintf(os.Stderr,
			"\nThis is the canonicalization split in docs/THREAT-MODEL.md: an issuer on this\n"+
				"code and a verifier built from the published vectors compute different digests\n"+
				"over the same request. %s is public and is what integrators implement against.\n"+
				"DO NOT run -write to clear this. Find what changed the encoding.\n", path)
		return
	}

	fmt.Fprintf(os.Stderr,
		"CONFORMANCE DRIFT — VECTORS ARE STALE (additions only, no published value changed).\n")
	for _, a := range added {
		fmt.Fprintf(os.Stderr, "  + %s\n", a)
	}
	if n := len(old.ContextHashes) + len(old.HumanAnchors) - len(oldCtx) - len(oldAnchor); n != 0 {
		fmt.Fprintf(os.Stderr, "  (note: %d duplicate key(s) in the committed file)\n", n)
	}
	fmt.Fprintf(os.Stderr,
		"\nThe canonical encoding is unchanged. Regenerate and commit:\n"+
			"    go run ./cmd/conformance -write -o %s\n", path)
}

func main() {
	write := flag.Bool("write", false, "write the vectors file")
	check := flag.Bool("check", false, "re-derive and fail on drift")
	path := flag.String("o", "docs/conformance-vectors.json", "vectors file path")
	flag.Parse()

	v, err := build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out = append(out, '\n')

	switch {
	case *write:
		if err := os.WriteFile(*path, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %d context-hash + %d anchor vectors to %s\n", len(v.ContextHashes), len(v.HumanAnchors), *path)
	case *check:
		have, err := os.ReadFile(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		if string(have) != string(out) {
			classifyDrift(have, v, *path)
			os.Exit(1)
		}
		fmt.Println("conformance vectors OK (no drift)")
	default:
		fmt.Print(string(out))
	}
}
