// cmd/catsvc — Compliance Attestation Token issuer service.
//
// Listens on 127.0.0.1:8082. Reachable externally via relayd on :4444.
// Reads the ct_issuer signing key from /var/spt-txn/a/keys/ct-issuer.sec
// (signify format). Verifies the issuer is registered in the Trust Registry
// before issuing. Issues CATs signed with Ed25519.
//
// Endpoints:
//   POST /cat/issue   — issue a new CAT
//   GET  /cat/health  — liveness check
//
// POST /cat/issue request body (JSON):
//
//	{
//	  "issuer":               "domain-a.authorg",
//	  "subject":              "alice",
//	  "principal_name":       "alice",
//	  "scope":                {"action": "transfer", "max_amount": 10000},
//	  "delegation_depth_max": 3,
//	  "ttl_hours":            24,
//	  "holder_key_hex":       "<64-char hex Ed25519 public key>"
//	}
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
)

const (
	defaultAddr    = "127.0.0.1:8082"
	defaultKeyPath = "/var/spt-txn/a/keys/ct-issuer.sec"
	defaultTRAddr  = "http://127.0.0.1:8081"
)

func main() {
	addr    := envOr("SPT_CAT_ADDR",    defaultAddr)
	keyPath := envOr("SPT_CAT_KEY",     defaultKeyPath)
	trAddr  := envOr("SPT_TR_ADDR_URL", defaultTRAddr)

	log.SetPrefix("catsvc: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// ── Load signing key ───────────────────────────────────────────
	privKey, pubKey, err := loadSignifyKey(keyPath)
	if err != nil {
		log.Fatalf("load signing key: %v", err)
	}
	log.Printf("loaded ct-issuer key: %s", hex.EncodeToString(pubKey))

	// ── Connect to Trust Registry ──────────────────────────────────
	tr := &httpTrustRegistry{baseURL: trAddr}

	// Verify our issuer is registered before accepting requests.
	ctx := context.Background()
	rec, err := tr.Lookup(ctx, "domain-a.authorg", trustregistry.RoleCTIssuer)
	if err != nil {
		log.Fatalf("issuer not in Trust Registry: %v", err)
	}
	regPub := hex.EncodeToString(rec.PublicKey)
	myPub  := hex.EncodeToString(pubKey)
	if regPub != myPub {
		log.Fatalf("registered public key %s does not match loaded key %s", regPub, myPub)
	}
	log.Printf("issuer verified in Trust Registry: domain-a.authorg / ct_issuer")

	// ── HTTP mux ───────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/cat/health", handleHealth)
	mux.HandleFunc("/cat/issue",  handleIssue(privKey, pubKey))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("listening on %s", addr)

	// ── unveil + pledge (security review C4 / H4) ──────────────────
	// The signing key is already loaded into memory, the registry self-check is
	// done, and the listener is bound. unveil restricts the filesystem view to
	// ONLY the key path, so a bug in the issuer cannot read anything else on
	// disk — the mitigation for the key being unencrypted at rest (H4). pledge
	// then restricts the syscall set for serving (issuance signs from memory and
	// touches no files).
	unveil(keyPath, "r")
	unveilLock()
	if err := pledge("stdio rpath inet"); err != nil {
		log.Fatalf("pledge: %v", err)
	}

	// ── Graceful shutdown ──────────────────────────────────────────
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(done)
	}()

	log.Printf("ready")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	<-done
	log.Printf("stopped")
}

// ── Handlers ───────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "service": "catsvc"})
}

type issueRequest struct {
	SubjectToken       string         `json:"subject_token"` // identity SD-JWT (signed by the wallet/ct_issuer key)
	Issuer             string         `json:"issuer"`
	PrincipalName      string         `json:"principal_name"`
	Scope              map[string]any `json:"scope"`
	DelegationDepthMax int            `json:"delegation_depth_max"`
	TTLHours           int            `json:"ttl_hours"`
	HolderKeyHex       string         `json:"holder_key_hex"`
}

func handleIssue(privKey ed25519.PrivateKey, issuerPub ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Cap request size (review M5): no unbounded JSON bodies.
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

		var req issueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// ── Authenticated issuance (review C3) ─────────────────────────
		// Issuance requires a subject identity token signed by the Domain A
		// wallet key (the registered ct_issuer key). Without that key an
		// external caller cannot forge a valid subject token, so /cat/issue is
		// no longer an unauthenticated oracle. The CAT subject is bound to the
		// verified token, not to attacker-supplied input.
		if req.SubjectToken == "" {
			jsonError(w, "subject_token required: issuance is authenticated", http.StatusUnauthorized)
			return
		}
		subjClaims, err := verifySubjectToken(req.SubjectToken, issuerPub)
		if err != nil {
			jsonError(w, "subject token rejected: "+err.Error(), http.StatusUnauthorized)
			return
		}
		subject, _ := subjClaims["sub"].(string)
		if subject == "" {
			jsonError(w, "subject token missing sub", http.StatusUnauthorized)
			return
		}
		principal := req.PrincipalName
		if principal == "" {
			principal = subject
		}

		// Decode holder public key.
		holderKeyBytes, err := hex.DecodeString(req.HolderKeyHex)
		if err != nil || len(holderKeyBytes) != ed25519.PublicKeySize {
			jsonError(w, "holder_key_hex must be 64 hex chars (32-byte Ed25519 key)",
				http.StatusBadRequest)
			return
		}

		ttl := time.Duration(req.TTLHours) * time.Hour
		if ttl == 0 {
			ttl = 24 * time.Hour
		}

		cat, err := cattoken.Issue(cattoken.IssueRequest{
			Issuer:             req.Issuer,
			Subject:            subject,
			PrincipalName:      principal,
			Scope:              cattoken.CapabilityScope(req.Scope),
			DelegationDepthMax: req.DelegationDepthMax,
			TTL:                ttl,
			HolderPublicKey:    ed25519.PublicKey(holderKeyBytes),
		}, privKey)
		if err != nil {
			jsonError(w, "issue failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, map[string]any{
			"token":        cat.Token,
			"human_anchor": cat.HumanAnchor.String(),
			"issued_at":    cat.IssuedAt.UTC().Format(time.RFC3339),
			"expires_at":   cat.ExpiresAt.UTC().Format(time.RFC3339),
			"token_type":   "CAT",
		})
	}
}

// verifySubjectToken verifies the wallet-issued identity token that authorizes
// CAT issuance (review C3). It accepts a plain EdDSA JWT or an SD-JWT
// presentation (JWT~disclosures~); only the signed JWT core is verified, against
// the wallet/ct_issuer public key. Signature and expiry are checked.
func verifySubjectToken(token string, pub ed25519.PublicKey) (map[string]any, error) {
	if i := strings.IndexByte(token, '~'); i >= 0 {
		token = token[:i] // strip SD-JWT disclosures; verify the signed core
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed subject token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("signature does not verify against the wallet (ct_issuer) key")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("subject token missing exp")
	}
	if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("subject token expired")
	}
	return claims, nil
}

// ── Trust Registry HTTP client ─────────────────────────────────────────

type httpTrustRegistry struct{ baseURL string }

func (t *httpTrustRegistry) Lookup(ctx context.Context, iss string, role trustregistry.Role) (*trustregistry.Record, error) {
	url := fmt.Sprintf("%s/tr/lookup?iss=%s&role=%s", t.baseURL, iss, string(role))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, trustregistry.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust registry returned %d", resp.StatusCode)
	}
	var body struct {
		PublicKey string `json:"public_key"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(body.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	return &trustregistry.Record{
		Iss:       iss,
		Role:      role,
		PublicKey: pubBytes,
		Status:    trustregistry.RecordStatus(body.Status),
	}, nil
}

// ── Signify key loader ─────────────────────────────────────────────────

// loadSignifyKey reads an OpenBSD signify secret key file and extracts
// the raw Ed25519 private key (64 bytes: 32-byte seed + 32-byte public key).
//
// Signify secret key format (base64-decoded):
//   [0:2]   algorithm ("Ed")
//   [2:4]   KDF ("BK" = bcrypt | "none")
//   [4:8]   KDF rounds (big-endian uint32)
//   [8:24]  salt (16 bytes)
//   [24:32] checksum (8 bytes)
//   [32:40] fingerprint (8 bytes)
//   [40:104] Ed25519 private key (64 bytes: seed||public)
func loadSignifyKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Skip the "untrusted comment: ..." first line.
	lines := splitLines(data)
	var b64line string
	for _, l := range lines {
		if len(l) > 10 && l[0] != 'u' {
			b64line = l
			break
		}
	}
	if b64line == "" {
		return nil, nil, fmt.Errorf("no base64 line found in %s", path)
	}

	raw, err := base64.StdEncoding.DecodeString(b64line)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 104 {
		return nil, nil, fmt.Errorf("key too short: %d bytes", len(raw))
	}
	if string(raw[0:2]) != "Ed" {
		return nil, nil, fmt.Errorf("unexpected algorithm: %q", raw[0:2])
	}
	// H5: reject passphrase-encrypted keys. This service has no passphrase
	// handling; signify marks an unencrypted key with kdfrounds == 0. Slicing an
	// encrypted key would silently yield a wrong signing key.
	if rounds := binary.BigEndian.Uint32(raw[4:8]); rounds != 0 {
		return nil, nil, fmt.Errorf("signify key is passphrase-encrypted (kdfrounds=%d); only unencrypted keys are supported", rounds)
	}
	// H5: verify the embedded checksum — the first 8 bytes of SHA-512 over the
	// 64-byte secret key — so a corrupted or wrong key is rejected, not used.
	sum := sha512.Sum512(raw[40:104])
	if !bytes.Equal(sum[:8], raw[24:32]) {
		return nil, nil, fmt.Errorf("signify key checksum mismatch (corrupted or wrong key)")
	}

	privKey := ed25519.PrivateKey(raw[40:104])
	pubKey  := ed25519.PublicKey(raw[72:104])
	return privKey, pubKey, nil
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

// ── Helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
