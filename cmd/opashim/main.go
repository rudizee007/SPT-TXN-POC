// Command opashim is the OPA-compatible decision API skin over the SPT-Txn
// decision core — docs/spec/GATEWAY-PROFILES.md §3.
//
// It accepts the request shape existing OPA integrations already send and
// answers in the shape they expect, so every OPA integration point becomes an
// SPT-Txn integration point without client changes:
//
//	POST /v1/data/spttxn/authz
//	{"input": {"token": "...", "tool": "...", "params": {...}, "target": "..."}}
//
//	→ {"result": {"allow": true|false, "class": "...", "receipt_ref": "..."}}
//
// The shim performs no Rego evaluation and holds no policy — it is a socket
// shape over the decision core, nothing more. Absent fields, wrong types, and
// unparseable input all yield {"allow": false} with a receipt (fail closed).
// Only the engine can produce allow=true.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// maxBody bounds the request body: parser DoS guard (THREAT-MODEL §4.5).
const maxBody = 1 << 20 // 1 MiB

type opaRequest struct {
	Input struct {
		Token  string          `json:"token"`
		Tool   string          `json:"tool"`
		Params json.RawMessage `json:"params"`
		Target string          `json:"target"`
	} `json:"input"`
}

type opaResult struct {
	Allow      bool   `json:"allow"`
	Class      string `json:"class"`
	ReceiptRef string `json:"receipt_ref,omitempty"`
}

type opaResponse struct {
	Result opaResult `json:"result"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9192", "listen address")
	pepName := flag.String("pep", "opashim.spt-txn", "PEP identity (trust registry name)")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "opashim-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	flag.Parse()

	if *ttsPubHex == "" || *logKeyFile == "" || *policyHash == "" {
		flag.Usage()
		os.Exit(2)
	}
	ttsPub, err := hexKey(*ttsPubHex, ed25519.PublicKeySize)
	if err != nil {
		log.Fatalf("tts-pub: %v", err)
	}
	keyRaw, err := os.ReadFile(*logKeyFile)
	if err != nil {
		log.Fatalf("log-key-file: %v", err)
	}
	logKey, err := hexKey(stringsTrim(string(keyRaw)), ed25519.PrivateKeySize)
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
		Emit: emitter.Emit,
	})
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/data/spttxn/authz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeResult(w, opaResult{Allow: false, Class: receipt.ClassViolation})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			d := engine.RecordDeny("opa.body-oversize", false, "")
			writeResult(w, opaResult{Allow: false, Class: d.Class(), ReceiptRef: d.ReceiptHash()})
			return
		}
		var req opaRequest
		if err := json.Unmarshal(body, &req); err != nil {
			d := engine.RecordDeny("opa.input-malformed", false, "")
			writeResult(w, opaResult{Allow: false, Class: d.Class(), ReceiptRef: d.ReceiptHash()})
			return
		}
		d := engine.Decide(r.Context(), decision.Input{
			Token: req.Input.Token,
			Intent: intent.Intent{
				Tool:   req.Input.Tool,
				Params: req.Input.Params,
				Target: req.Input.Target,
			},
		})
		writeResult(w, opaResult{Allow: d.Permit(), Class: d.Class(), ReceiptRef: d.ReceiptHash()})
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	log.Printf("spt-txn OPA-compatible shim listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}

func writeResult(w http.ResponseWriter, res opaResult) {
	w.Header().Set("Content-Type", "application/json")
	// OPA answers 200 with a result document; "allow": false IS the denial.
	_ = json.NewEncoder(w).Encode(opaResponse{Result: res})
}

func hexKey(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d bytes, got %d", size, len(b))
	}
	return b, nil
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
