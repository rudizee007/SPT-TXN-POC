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

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/zkhash"
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
		Note:    "Deterministic SPT-Txn conformance vectors: spt_txn_context_hash per chain (canonical preimage, SHA-256) and humanAnchor = zkhash.Commit(secret, blinding) hex. Signatures/timestamps in real tokens are not covered here.",
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
		h := zkhash.BigOf(zkhash.Commit([]byte(a.secret), []byte(a.blinding))).Text(16)
		v.HumanAnchors = append(v.HumanAnchors, anchorVec{a.secret, a.blinding, h})
	}
	return v, nil
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
			fmt.Fprintf(os.Stderr, "CONFORMANCE DRIFT: re-derived vectors differ from %s — the canonical encoding or commitment changed.\n", *path)
			os.Exit(1)
		}
		fmt.Println("conformance vectors OK (no drift)")
	default:
		fmt.Print(string(out))
	}
}
