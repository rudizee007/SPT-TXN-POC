// Command auditverify independently re-checks an SPT-Txn audit log: it recomputes
// the hash chain end-to-end and the SHA-256 Merkle root over all entries, and
// (optionally) compares that root to a value anchored on-chain. It is a
// third-party-runnable integrity check — it needs only the log file, no keys.
//
//	go run ./cmd/auditverify -log /var/spt-txn/audit/log.json
//	go run ./cmd/auditverify -log log.json -expect 0x<anchored-merkle-root>
//
// Exit 0 = chain intact (and root matches -expect, if given); non-zero otherwise.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/violetskysecurity/spt-txn-poc/internal/audit"
)

func main() {
	logPath := flag.String("log", "", "path to the audit log file")
	expect := flag.String("expect", "", "optional: an anchored Merkle root (hex) to compare against")
	flag.Parse()

	if *logPath == "" {
		fmt.Fprintln(os.Stderr, "error: -log is required")
		os.Exit(2)
	}

	l, err := audit.Open(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer l.Close()

	if err := l.Verify(); err != nil {
		fmt.Printf("hash-chain : BROKEN — %v\n", err)
		os.Exit(1)
	}
	entries := l.Entries()
	root := hex.EncodeToString(audit.MerkleRoot(entries))
	fmt.Printf("hash-chain : OK (%d entries, chain intact)\n", len(entries))
	fmt.Printf("merkle root: %s\n", root)

	if *expect != "" {
		want := strings.ToLower(strings.TrimPrefix(*expect, "0x"))
		if want == root {
			fmt.Println("anchored   : MATCH — the recomputed root equals the anchored value")
		} else {
			fmt.Printf("anchored   : MISMATCH\n  anchored: %s\n  computed: %s\n", want, root)
			os.Exit(1)
		}
	}
}
