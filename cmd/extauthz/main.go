// Command extauthz is the Envoy ext_authz (HTTP service mode) skin over the
// SPT-Txn decision core — docs/spec/GATEWAY-PROFILES.md §2.
//
// Envoy forwards each request to this server with the original method, path,
// and headers. The skin extracts the SPT-Txn token from x-spt-txn-token,
// derives the HTTP intent (tool = method, params = {"path": <path>}, target =
// the configured upstream identity), and asks the decision core.
//
//	200 → allow; the response instructs Envoy to strip the token header so
//	      the credential never reaches the upstream (no passthrough).
//	403 → deny; uniform body. The receipt records the failing check.
//
// A decision is ALWAYS 200 or 403 — never 5xx. Envoy deployments with
// failure_mode_allow would treat a 5xx as "authz broken" and may fail open;
// an SPT-Txn answer is always an authz answer (deny-by-default).
//
// The skin holds no decision logic. It can deny on its own (malformed
// input) but can never permit — only the engine returns a permit.
//
// Example Envoy wiring (http_filters):
//
//   - name: envoy.filters.http.ext_authz
//     typed_config:
//     "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
//     http_service:
//     server_uri: {uri: http://127.0.0.1:9191, cluster: spt_txn_authz, timeout: 0.050s}
//     authorization_request: {allowed_headers: {patterns: [{exact: x-spt-txn-token}]}}
//     failure_mode_allow: false
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
)

// TokenHeader carries the SPT-Txn token on the guarded request.
const TokenHeader = "x-spt-txn-token"

func main() {
	listen := flag.String("listen", "127.0.0.1:9191", "listen address")
	pepName := flag.String("pep", "extauthz.spt-txn", "PEP identity (trust registry name)")
	upstream := flag.String("upstream", "", "upstream service identity — the intent target (required)")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "extauthz-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	maxTTL := flag.Duration("max-token-ttl", 60*time.Second,
		"longest remaining token lifetime this PEP accepts. A gateway PEP does not walk "+
			"the chain, so this IS the revocation latency (GATEWAY-PROFILES.md 1.1). "+
			"txntoken.DefaultTTL is 30s; the default here allows one clock-skew margin over it.")
	flag.Parse()

	if *upstream == "" || *ttsPubHex == "" || *logKeyFile == "" || *policyHash == "" {
		flag.Usage()
		os.Exit(2)
	}
	ttsPub, err := parseHexKey(*ttsPubHex, ed25519.PublicKeySize)
	if err != nil {
		log.Fatalf("tts-pub: %v", err)
	}
	logKeyHex, err := os.ReadFile(*logKeyFile)
	if err != nil {
		log.Fatalf("log-key-file: %v", err)
	}
	logKey, err := parseHexKey(string(trimSpace(logKeyHex)), ed25519.PrivateKeySize)
	if err != nil {
		log.Fatalf("log key: %v", err)
	}

	auditLog, err := audit.Open(*auditPath)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()
	emitter, err := receiptlog.NewLogEmitter(auditLog, ed25519.PrivateKey(logKey))
	if err != nil {
		log.Fatalf("emitter: %v", err)
	}

	engine, err := decision.New(decision.Config{
		PEP:          *pepName,
		PolicyHash:   *policyHash,
		Jurisdiction: *jurisdiction,
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			return txntoken.Verify(token, ed25519.PublicKey(ttsPub))
		},
		Emit:        emitter.Emit,
		MaxTokenTTL: *maxTTL,
	})
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		d := engine.Decide(r.Context(), decision.Input{
			Token: r.Header.Get(TokenHeader),
			Intent: intent.Intent{
				Tool:   r.Method,
				Params: []byte(fmt.Sprintf(`{"path":%q}`, r.URL.Path)),
				Target: *upstream,
			},
		})
		if d.Permit() {
			// Strip the credential before it reaches the upstream.
			w.Header().Set("x-envoy-auth-headers-to-remove", TokenHeader)
			w.Header().Set("x-spt-txn-receipt", d.ReceiptHash())
			w.WriteHeader(http.StatusOK)
			return
		}
		// Uniform denial; coarse class only (outage vs violation is
		// operational metadata, the failing check stays in the receipt).
		w.Header().Set("x-spt-txn-class", d.Class())
		w.Header().Set("x-spt-txn-receipt", d.ReceiptHash())
		http.Error(w, "spt-txn: denied", http.StatusForbidden)
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second, // slowloris guard
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	log.Printf("spt-txn ext_authz skin listening on %s (upstream identity %s)", *listen, *upstream)
	log.Fatal(srv.ListenAndServe())
}

func parseHexKey(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d bytes, got %d", size, len(b))
	}
	return b, nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
