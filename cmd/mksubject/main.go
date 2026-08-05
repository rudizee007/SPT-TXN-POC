// cmd/mksubject — issue a wallet "subject token" (identity assertion) signed by
// the ct_issuer signify key. This is the POC stand-in for the Domain A wallet
// that, after authenticating a human (OIDC, out of scope here), asserts their
// identity so the CAT issuer will mint a CAT (security review C3).
//
// Usage:
//
//	mksubject -sub alice [-iss domain-a.authorg] [-ttl-hours 1] \
//	          [-key /var/spt-txn/a/keys/ct-issuer.sec]
//
// Prints the compact JWT to stdout; pass it as "subject_token" to /cat/issue.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	keyPath := flag.String("key", "/var/spt-txn/a/keys/ct-issuer.sec", "signify secret key (ct_issuer)")
	iss := flag.String("iss", "domain-a.authorg", "issuer identifier")
	sub := flag.String("sub", "", "subject — the authenticated human's identifier")
	ttlH := flag.Int("ttl-hours", 1, "token lifetime in hours")
	flag.Parse()

	if *sub == "" {
		log.Fatal("-sub is required")
	}
	priv, err := loadSignifyPriv(*keyPath)
	if err != nil {
		log.Fatalf("load key: %v", err)
	}

	now := time.Now().UTC()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": *iss,
		"sub": *sub,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(*ttlH) * time.Hour).Unix(),
		"typ": "subject",
	})
	signingInput := b64(header) + "." + b64(claims)
	sig := ed25519.Sign(priv, []byte(signingInput))
	fmt.Println(signingInput + "." + b64(sig))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// loadSignifyPriv extracts the raw Ed25519 private key from an (unencrypted)
// signify secret key file. Mirrors catsvc's loader.
func loadSignifyPriv(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b64line string
	for _, l := range splitLines(data) {
		if len(l) > 10 && l[0] != 'u' { // skip "untrusted comment:"
			b64line = l
			break
		}
	}
	if b64line == "" {
		return nil, fmt.Errorf("no base64 line in %s", path)
	}
	raw, err := base64.StdEncoding.DecodeString(b64line)
	if err != nil {
		return nil, err
	}
	if len(raw) < 104 || string(raw[0:2]) != "Ed" {
		return nil, fmt.Errorf("not a signify Ed25519 secret key")
	}
	return ed25519.PrivateKey(raw[40:104]), nil
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := string(data[start:i])
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}
