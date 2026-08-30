// cmd/idp-verify — offline verification of an idp-bridge-issued CAT.
//
// Proves the second half of the identity-provider claim: a CAT minted by the
// bridge from a Keycloak token verifies OFFLINE — with no contact to Keycloak or
// the bridge — using only the issuer's registered public key. A tampered CAT is
// rejected. (The CAT -> CT -> TXN agent delegation is proven end-to-end by
// cmd/agentdemo, which the demo script runs next.)
//
//	go run ./cmd/idp-verify -cat "<CAT JWT>" -issuer-key "<64-hex issuer public key>"
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

// checksPerformed is the exact list of what verifyOffline establishes. It is
// printed with the result because the previous success line ("CAT verified
// OFFLINE") named no checks, and a reader supplies the missing list from what
// the surrounding documents promised rather than from what the code does.
var checksPerformed = []string{
	"JWT header alg is EdDSA",
	"Ed25519 signature is valid under the public key supplied on the command line",
	"exp is present and in the future",
	"txn_token_type is CAT",
}

// checksNotPerformed is the same list from the other side, and it is the more
// important of the two.
var checksNotPerformed = []string{
	"iss is NOT read — this tool has no notion of which issuers are legitimate",
	"Trust Registry membership is NOT consulted",
	"revocation / status list is NOT consulted",
	"holder binding is NOT checked — holder_key is printed, never verified",
	"the delegation chain and depth are NOT walked",
	"nbf / iat are NOT checked",
	"the capability scope is NOT evaluated against anything",
}

// verifyOffline checks the CAT against the issuer key using ONLY local crypto —
// no network, no identity-provider or bridge contact.
//
// "Offline" describes where the computation happens, not how much it proves.
// The trust anchor is a command-line argument, so the statement this function
// can support is: this blob is signed by the key you handed me, is not expired,
// and says CAT. Anyone who supplies a forged token together with its matching
// public key gets the same result, correctly. See checksNotPerformed.
func verifyOffline(tok string, pub ed25519.PublicKey) (map[string]any, error) {
	return cattoken.Verify(tok, pub)
}

func main() {
	cat := flag.String("cat", "", "the CAT (compact JWT) issued by idp-bridge")
	issuerKey := flag.String("issuer-key", "", "the CAT issuer's Ed25519 public key (64 hex chars) — from GET /issuer")
	flag.Parse()

	log.SetPrefix("idp-verify: ")
	log.SetFlags(0)

	if *cat == "" || *issuerKey == "" {
		log.Fatal("both -cat and -issuer-key are required")
	}
	pubBytes, err := hex.DecodeString(*issuerKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		log.Fatalf("-issuer-key must be %d hex chars (32-byte Ed25519 key)", ed25519.PublicKeySize*2)
	}
	pub := ed25519.PublicKey(pubBytes)

	// 1) OFFLINE verification — no Keycloak, no bridge, no network.
	claims, err := verifyOffline(*cat, pub)
	if err != nil {
		log.Fatalf("FAIL: offline verify rejected a CAT that should be valid: %v", err)
	}
	fmt.Println("✓ CAT signature and expiry check out, computed locally (no identity-provider contact, no network)")
	fmt.Println("    checked:")
	for _, c := range checksPerformed {
		fmt.Printf("      · %s\n", c)
	}
	fmt.Println("    NOT checked by this tool:")
	for _, c := range checksNotPerformed {
		fmt.Printf("      · %s\n", c)
	}
	fmt.Println("    The issuer key came from -issuer-key. This tool does not decide whether")
	fmt.Println("    that issuer should be trusted; obtain it out of band, not from the bridge")
	fmt.Println("    that minted the token.")
	pretty, _ := json.MarshalIndent(claims, "    ", "  ")
	fmt.Printf("    verified claims:\n    %s\n", pretty)
	fmt.Println("    (the human anchor, if present, is privacy-preserving — no PII on the wire)")

	// 2) NEGATIVE test — a tampered CAT must be rejected.
	bad := tamper(*cat)
	if _, err := verifyOffline(bad, pub); err == nil {
		log.Fatal("FAIL: offline verify ACCEPTED a tampered CAT")
	}
	fmt.Println("✓ tampered CAT rejected (signature check holds)")
	fmt.Println("\nProof: the identity-provider-issued credential is portable and offline-verifiable.")
	fmt.Println("Next — run  ./cmd/agentdemo  to see a CAT delegated to an AI agent with")
	fmt.Println("attenuating, revocable authority (CAT -> CT -> transaction-bound token).")
	os.Exit(0)
}

// tamper flips one character in the JWT payload segment.
func tamper(tok string) string {
	b := []byte(tok)
	// find the two dots; mutate a byte in the middle segment
	first, second := -1, -1
	for i, c := range b {
		if c == '.' {
			if first < 0 {
				first = i
			} else {
				second = i
				break
			}
		}
	}
	if first < 0 || second < 0 || second-first < 2 {
		return tok + "x"
	}
	mid := (first + second) / 2
	if b[mid] == 'A' {
		b[mid] = 'B'
	} else {
		b[mid] = 'A'
	}
	return string(b)
}
