// cmd/regkey — Register real signify public keys in the Trust Registry.
//
// Reads signify .pub files and updates the in-memory Trust Registry via
// the trsvc HTTP API. Run this once after trsvc starts to replace the
// zero-byte placeholder keys with the real keys from /var/spt-txn/*/keys/.
//
// Usage:
//
//	regkey -tr http://127.0.0.1:8081 -iss domain-a.authorg \
//	       -role ct_issuer -pub /var/spt-txn/a/keys/ct-issuer.pub
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	sock := flag.String("sock", "/var/spt-txn/sockets/tr-admin.sock", "trsvc admin Unix socket (registration is socket-only, owner 0600)")
	iss := flag.String("iss", "", "Issuer identifier")
	role := flag.String("role", "", "Role (ct_issuer|tts_issuer|escrow|audit)")
	pub := flag.String("pub", "", "Path to signify .pub (signing roles) or hex X25519 pub file (escrow)")
	mlkem := flag.String("mlkem", "", "Path to hex ML-KEM-768 encapsulation key (hybrid escrow only; from escrowkeygen)")
	flag.Parse()

	if *iss == "" || *role == "" || *pub == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *mlkem != "" && *role != "escrow" {
		log.Fatalf("-mlkem is valid only with -role escrow")
	}

	pubKey, err := loadPub(*pub)
	if err != nil {
		log.Fatalf("load public key: %v", err)
	}
	log.Printf("loaded X25519/Ed25519 public key: %s", hex.EncodeToString(pubKey))

	// Determine key type from role and whether an ML-KEM half was supplied.
	keyType := "Ed25519"
	if *role == "escrow" {
		keyType = "X25519"
	}

	// Call the Trust Registry update endpoint.
	body := map[string]any{
		"iss":        *iss,
		"role":       *role,
		"key_type":   keyType,
		"public_key": hex.EncodeToString(pubKey),
	}
	if *mlkem != "" {
		mlkemKey, err := loadHexKey(*mlkem)
		if err != nil {
			log.Fatalf("load ML-KEM encapsulation key: %v", err)
		}
		if len(mlkemKey) != 1184 {
			log.Fatalf("ML-KEM-768 encapsulation key must be 1184 bytes, got %d", len(mlkemKey))
		}
		keyType = "X25519+ML-KEM-768"
		body["key_type"] = keyType
		body["mlkem_encap_key"] = hex.EncodeToString(mlkemKey)
		log.Printf("hybrid escrow: loaded ML-KEM-768 encapsulation key (%d bytes)", len(mlkemKey))
	}
	bodyJSON, _ := json.Marshal(body)

	// Registration is served only on the local Unix socket, so dial it directly
	// rather than a TCP address. Access is gated by the socket's filesystem
	// permissions (review C1).
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", *sock)
			},
		},
	}
	url := "http://unix/tr/register"
	resp, err := client.Post(url, "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		log.Fatalf("POST %s (socket %s): %v", url, *sock, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Fatalf("register failed (%d): %v", resp.StatusCode, result)
	}
	log.Printf("registered %s / %s with key %s", *iss, *role, hex.EncodeToString(pubKey))
}

// loadPub reads a 32-byte public key from either a signify .pub file (signing
// roles and classical escrow) or a raw hex file (the X25519 half emitted by
// escrowkeygen for hybrid escrow). It tries the signify format first and falls
// back to hex.
func loadPub(path string) ([]byte, error) {
	if k, err := loadSignifyPub(path); err == nil {
		return k, nil
	}
	k, err := loadHexKey(path)
	if err != nil {
		return nil, fmt.Errorf("%s is neither a signify .pub nor a hex key: %w", path, err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("hex public key must be 32 bytes, got %d", len(k))
	}
	return k, nil
}

// loadHexKey reads a file containing a single hex string (whitespace/newlines
// ignored) and returns the decoded bytes.
func loadHexKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s := strings.Join(strings.Fields(string(data)), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode %s: %w", path, err)
	}
	return b, nil
}

// loadSignifyPub reads a signify .pub file and extracts the 32-byte
// Ed25519 public key.
//
// Signify public key format (base64-decoded):
//
//	[0:2]   algorithm ("Ed")
//	[2:10]  fingerprint (8 bytes)
//	[10:42] Ed25519 public key (32 bytes)
func loadSignifyPub(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var b64line string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "untrusted") {
			b64line = line
			break
		}
	}
	if b64line == "" {
		return nil, fmt.Errorf("no base64 line in %s", path)
	}

	raw, err := base64.StdEncoding.DecodeString(b64line)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 42 {
		return nil, fmt.Errorf("key too short: %d bytes", len(raw))
	}
	if string(raw[0:2]) != "Ed" {
		return nil, fmt.Errorf("unexpected algorithm: %q", raw[0:2])
	}

	return raw[10:42], nil
}
