// cmd/escrowkeygen — generate a hybrid escrow keypair (X25519 + ML-KEM-768).
//
// The escrow authority runs this once to produce the key that seals escrow
// envelopes (internal/escrow, Scheme 2). It writes three files:
//
//	escrow-x25519.pub  hex of the 32-byte X25519 public key
//	escrow-mlkem.pub   hex of the 1184-byte ML-KEM-768 encapsulation key
//	escrow.key         hex of the 96-byte PRIVATE key (mode 0600) — SECRET
//
// Register the two public halves with the Trust Registry:
//
//	regkey -iss <authority> -role escrow \
//	       -pub  <dir>/escrow-x25519.pub \
//	       -mlkem <dir>/escrow-mlkem.pub
//
// SECURITY: escrow.key is the material that can deanonymize every humanAnchor.
// Store it only in the escrow authority's hardened custody (HSM / restricted,
// disk-encrypted host); never commit it and never place it under the repo tree.
// In production the classical half should be FROST-thresholded and the ML-KEM
// half held under a smaller quorum / HSM (threshold ML-KEM is not yet
// standardized — see docs/PQ-ESCROW-HYBRID-KEM-SCOPE.md §5).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/violetskysecurity/spt-txn-poc/internal/escrow"
)

func main() {
	out := flag.String("out", ".", "output directory for the generated key files")
	force := flag.Bool("force", false, "overwrite existing key files")
	flag.Parse()

	// Create the output directory (0700 — it will hold the private key).
	if err := os.MkdirAll(*out, 0o700); err != nil {
		log.Fatalf("create output dir %s: %v", *out, err)
	}

	key, err := escrow.NewEscrowKey()
	if err != nil {
		log.Fatalf("generate escrow key: %v", err)
	}
	pub := key.PublicKey()

	x25519Path := filepath.Join(*out, "escrow-x25519.pub")
	mlkemPath := filepath.Join(*out, "escrow-mlkem.pub")
	privPath := filepath.Join(*out, "escrow.key")

	for _, p := range []string{x25519Path, mlkemPath, privPath} {
		if _, err := os.Stat(p); err == nil && !*force {
			log.Fatalf("%s already exists (use -force to overwrite)", p)
		}
	}

	if err := writeHex(x25519Path, pub.X25519Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	if err := writeHex(mlkemPath, pub.MlkemEncapKeyBytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	// Private key: owner-read/write only.
	if err := writeHex(privPath, key.Bytes(), 0o600); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("wrote:\n  %s  (X25519 public, %d bytes)\n  %s  (ML-KEM-768 encapsulation key, %d bytes)\n  %s  (PRIVATE key, %d bytes, mode 0600 — SECRET)\n",
		x25519Path, len(pub.X25519Bytes()),
		mlkemPath, len(pub.MlkemEncapKeyBytes()),
		privPath, len(key.Bytes()))
	fmt.Printf("\nregister the public halves:\n  regkey -iss <authority> -role escrow -pub %s -mlkem %s\n", x25519Path, mlkemPath)
	fmt.Printf("\nSECURITY: move %s into the escrow authority's hardened custody; never commit it.\n", privPath)
}

// writeHex writes b as a hex string (newline-terminated) with the given mode,
// creating the file exclusively so an unexpected pre-existing file is never
// silently reused (the caller has already handled -force by removing stale
// files is not done here; we rely on the stat check above and O_TRUNC).
func writeHex(path string, b []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile does not chmod an existing file; enforce mode explicitly so a
	// pre-existing (‑force) private key file cannot keep looser permissions.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
