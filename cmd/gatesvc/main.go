// Command gatesvc exposes the SPT-Txn x402 authorization gate as a small local
// HTTP service — the AUTHORITY in the x402 loop (P1 of the agentic-x402 demo).
//
// It provisions one agent with a standing capability (a spend ceiling) and, per
// request, decides whether a specific payment is authorized: mint the
// CAT -> CT -> SPT-Txn chain for that payment and run the eight-step verifier.
// It returns ALLOW (with the on-ledger stamp fields + attestation) or DENY.
// It never settles anything — that is clients/xrpl-pay, invoked by the agent
// only after ALLOW.
//
// Bind to loopback only; the gate holds the issuing authority.
//
//	go run ./cmd/gatesvc -ceiling 5000 -agent rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT
//
// Endpoints:
//
//	GET  /gate/health
//	POST /gate/authorize   {"price","currency","payto","sourcetag"} -> Decision JSON
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/gate"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8401", "loopback listen address (gate is the authority; do not expose)")
	chain := flag.String("chain", "xrpl", "ledger the gate binds to (xrpl, hedera, …)")
	agent := flag.String("agent", "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT", "payer agent address (chain-specific: XRPL r-address, Hedera 0.0.x, …)")
	ceiling := flag.String("ceiling", "5000", "agent capability ceiling as a decimal string (max spend under its CT)")
	currency := flag.String("currency", "XRP", "capability currency")
	flag.Parse()

	log.SetPrefix("gatesvc: ")
	g, err := gate.New(*chain, *agent, *ceiling, *currency)
	if err != nil {
		log.Fatalf("provision gate: %v", err)
	}
	log.Printf("gate ready: agent=%s ceiling=%s %s anchor=%s", *agent, *ceiling, *currency, g.Anchor())

	mux := http.NewServeMux()
	mux.HandleFunc("/gate/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "gatesvc"})
	})
	// Trusted channel: the merchant fetches the issuer public keys here at startup
	// so it can independently verify attestations. (Demo stand-in for the shared
	// Trust Registry; keys must NOT come from the untrusted agent.)
	mux.HandleFunc("/gate/registry", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"records": g.IssuerRecords()})
	})
	mux.HandleFunc("/gate/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		var req struct {
			Price     string `json:"price"`
			Currency  string `json:"currency"`
			PayTo     string `json:"payto"`
			SourceTag string `json:"sourcetag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		d, err := g.Authorize(gate.Request{Price: req.Price, Currency: req.Currency, PayTo: req.PayTo, SourceTag: req.SourceTag})
		if err != nil {
			log.Printf("authorize error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization error"})
			return
		}
		if d.Allow {
			log.Printf("ALLOW pay %s %s to %s", req.Price, req.Currency, req.PayTo)
		} else {
			log.Printf("DENY pay %s %s to %s: %s", req.Price, req.Currency, req.PayTo, d.Reason)
		}
		writeJSON(w, http.StatusOK, d)
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	log.Printf("listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
