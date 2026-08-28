// Command snapshot produces and checks signed trust-registry snapshots.
//
// A verifier that cannot check its own root of trust is not a security product —
// and neither is one whose operator cannot PRODUCE a root of trust to check.
// docs/spec/TRUST-REGISTRY-SNAPSHOT.md §8 puts verification, pinning, the format
// and the generator all on the free side for that reason. This is the generator.
//
// The whole operator path:
//
//	snapshot keygen -out ./publication            # once; guard the private half
//	snapshot sign   -registry /var/spt-txn/registry.json \
//	                -key ./publication.key -id snapshot-2026-08-26
//	snapshot verify -body /var/spt-txn/registry.json \
//	                -pub $(cat ./publication.pub)
//
// then pin ./publication.pub in every PEP. `sign` writes the manifest beside the
// body as "<body>.manifest.json", which is where every reader looks by default,
// so the signed pair cannot be separated by accident.
//
// The private key never leaves the operator. There is no hosted step here and no
// key escrow: distributing snapshots at fleet scale is the separate, paid
// concern, and it is not what makes a snapshot trustworthy.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `snapshot — produce and check signed trust-registry snapshots

  snapshot keygen -out PREFIX
      Generate an ed25519 publication keypair. Writes PREFIX.key (private,
      0600) and PREFIX.pub (public, hex). Pin PREFIX.pub in every PEP.

  snapshot sign -registry BODY -key PRIVATE -id ID [-prev PREV] [-out MANIFEST]
      Sign a registry body. Writes the manifest to BODY.manifest.json unless
      -out says otherwise.

  snapshot verify -body BODY -pub HEX[,HEX...] [-manifest PATH] [-max-age D]
      Check a snapshot the way a PEP will. Exit 0 only if it would load.
`)
	os.Exit(2)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "publication", "output path prefix")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	fatal(err, "generate key")

	// 0600 and nothing else. This key is the root of trust for every offline
	// verification in every PEP that pins it; a snapshot signed with a leaked
	// one is indistinguishable from a real one.
	fatal(os.WriteFile(*out+".key", []byte(hex.EncodeToString(priv)+"\n"), 0o600), "write private key")
	fatal(os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644), "write public key")

	fmt.Printf("publication keypair written\n")
	fmt.Printf("  private : %s.key   (0600 — this is the root of trust; back it up offline)\n", *out)
	fmt.Printf("  public  : %s.pub   %s\n", *out, hex.EncodeToString(pub))
	fmt.Printf("\nPin the public half in every PEP. Rotation: pin {old,new} together,\n")
	fmt.Printf("sign with new, drop old only after the last snapshot it signed has aged out.\n")
}

func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	registry := fs.String("registry", "", "path to the registry body (required)")
	keyPath := fs.String("key", "", "path to the publication private key, hex (required)")
	id := fs.String("id", "", "snapshot id (required; ASCII, alphanumerics and -_.:)")
	prev := fs.String("prev", "", "previous snapshot id, for rollback detection")
	out := fs.String("out", "", "manifest output path (default <registry>.manifest.json)")
	_ = fs.Parse(args)

	if *registry == "" || *keyPath == "" || *id == "" {
		fs.Usage()
		os.Exit(2)
	}

	priv := readPrivateKey(*keyPath)

	// Re-export through the registry rather than signing the file as it sits.
	// ExportBody emits records in a deterministic order, so signing the same
	// registry twice produces the same digest — a property an operator needs to
	// diff two snapshots, and one that map iteration order would deny them.
	reg, err := trustregistry.NewPersistentRegistry(*registry)
	fatal(err, "open registry")
	body, err := reg.ExportBody()
	fatal(err, "export body")
	issuerIDs := reg.IssuerIDs()
	_ = reg.Close()

	if len(issuerIDs) == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: this registry has no issuer records. The snapshot is valid and\n"+
			"         signs correctly, but a verifier loading it will deny every request.\n"+
			"         That is a fail-closed fixture, not a deployable trust anchor.\n")
	}

	// Write the canonical body back, so what is signed is what is shipped.
	fatal(os.WriteFile(*registry, body, 0o644), "write canonical body")

	var prevPtr *string
	if *prev != "" {
		prevPtr = prev
	}
	m, err := trustsnapshot.Sign(body, *id, time.Now(), issuerIDs, prevPtr, priv)
	fatal(err, "sign")

	raw, err := trustsnapshot.MarshalManifest(m)
	fatal(err, "marshal manifest")
	manifestPath := *out
	if manifestPath == "" {
		manifestPath = trustregistry.ManifestPathFor(*registry)
	}
	fatal(os.WriteFile(manifestPath, append(raw, '\n'), 0o644), "write manifest")

	fmt.Printf("signed snapshot %q\n", *id)
	fmt.Printf("  body     : %s (%d issuer(s), canonicalised in place)\n", *registry, len(issuerIDs))
	fmt.Printf("  manifest : %s\n", manifestPath)
	fmt.Printf("  digest   : %s\n", m.DigestHex)
	fmt.Printf("\nShip BOTH files. A body without its manifest authenticates nothing.\n")
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	body := fs.String("body", "", "path to the registry body (required)")
	manifest := fs.String("manifest", "", "path to the manifest (default <body>.manifest.json)")
	pubs := fs.String("pub", "", "pinned publication public key(s), hex, comma-separated (required)")
	maxAge := fs.Duration("max-age", 24*time.Hour, "staleness bound")
	allowStale := fs.Bool("allow-stale", false, "accept a stale snapshot (disconnected-segment degrade mode)")
	_ = fs.Parse(args)

	if *body == "" || *pubs == "" {
		fs.Usage()
		os.Exit(2)
	}
	mPath := *manifest
	if mPath == "" {
		mPath = trustregistry.ManifestPathFor(*body)
	}

	var pinned []ed25519.PublicKey
	for _, f := range strings.Split(*pubs, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		b, err := hex.DecodeString(f)
		fatal(err, "decode -pub")
		if len(b) != ed25519.PublicKeySize {
			fatal(fmt.Errorf("%d bytes, want %d", len(b), ed25519.PublicKeySize), "-pub")
		}
		pinned = append(pinned, ed25519.PublicKey(b))
	}

	reg, err := trustregistry.OpenVerified(mPath, *body, trustsnapshot.Options{
		PinnedKeys: pinned,
		MaxAge:     *maxAge,
		AllowStale: *allowStale,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(1)
	}
	ids := reg.IssuerIDs()
	_ = reg.Close()

	fmt.Printf("OK — the snapshot verifies and would load.\n")
	fmt.Printf("  body     : %s\n", *body)
	fmt.Printf("  manifest : %s\n", mPath)
	fmt.Printf("  pinned   : %d key(s)\n", len(pinned))
	fmt.Printf("  issuers  : %d — %s\n", len(ids), strings.Join(ids, ", "))
}

// readPrivateKey accepts the hex form keygen writes, and also a 32-byte seed,
// because that is what an operator who generated the key elsewhere is likely to
// have. Anything else is refused rather than guessed at.
func readPrivateKey(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path)
	fatal(err, "read private key")
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	fatal(err, "private key is not hex")
	switch len(b) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b)
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b)
	default:
		fatal(fmt.Errorf("%d bytes, want %d (private key) or %d (seed)", len(b), ed25519.PrivateKeySize, ed25519.SeedSize), "private key")
		return nil
	}
}

func fatal(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "snapshot: %s: %v\n", what, err)
		os.Exit(1)
	}
}
