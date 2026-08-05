// cmd/agentsvc — agentic authorization VERIFY service (Milestone 7).
//
// Verify role (this build): runs the SPT-Txn eight-step enforcement engine on a
// presented capability chain (CAT -> CT[…] -> SPT-Txn) against a LOCAL,
// read-only Trust Registry snapshot. It holds NO signing key and never writes to
// disk (pledge "stdio rpath inet" — no wpath/cpath), so it cannot mint or mutate
// anything; the worst a bug can do is mis-answer allow/deny.
//
// This is the offline enforcement engine exposed as a network convenience for
// platforms that do not embed the verifier library. Verification stays
// offline-first BY DESIGN: the library is the primary path, this endpoint never
// makes a synchronous issuer or chain call (it reads only the cached snapshot).
//
// Listens on 127.0.0.1:8087. Reachable externally via relayd (TLS termination).
// The issue/delegate role (which holds a ct_issuer key) is a separate, audited
// surface — see docs/AGENTSVC-AND-ZKCHAIN-SCOPING.md — and is not in this build.
//
// Endpoints:
//
//	POST /agent/verify  — run the eight-step engine on a presented chain
//	GET  /agent/health  — liveness check
//
// POST /agent/verify request body (JSON):
//
//	{
//	  "txn_token": "<compact SPT-Txn JWT>",
//	  "dpop_proof": "<DPoP proof JWT>",
//	  "htm": "POST",
//	  "htu": "https://…/agent/verify",
//	  "ct_chain": ["<CT_A compact>", "<CT_B compact>"],  // root→leaf (multi-hop)
//	  "ct": "<CT compact>",                              // single-hop alternative
//	  "cat": "<root CAT compact>",
//	  "audience": "domain-b.execorg",
//	  "txn": {"chain":"xrpl","originator":"r…","beneficiary":"r…",
//	          "amount":"5000","currency":"USD","timestamp":1750000000,
//	          "extra":{"DestinationTag":"42"}}
//	}
//
// Response (JSON): {"allow": true} on success, or on denial
// {"allow": false, "step": 6, "step_name": "chain", "reason": "…"}.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

const (
	defaultAddr     = "127.0.0.1:8087" // 8086 is tr-svc; keep agentsvc clear of it
	defaultRegistry = "/var/spt-txn/b/registry.snapshot"
)

func main() {
	addr := envOr("SPT_AGENTSVC_ADDR", defaultAddr)
	role := envOr("SPT_AGENT_ROLE", "verify")
	regPath := envOr("SPT_AGENT_REGISTRY", defaultRegistry)

	log.SetPrefix("agentsvc: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if role != "verify" {
		log.Fatalf("role %q not supported in this build (verify only); the issue/delegate role is a separate audited surface — see docs/AGENTSVC-AND-ZKCHAIN-SCOPING.md", role)
	}

	// ── Load the local Trust Registry snapshot ─────────────────────────
	// This is the cached trust anchor: issuer keys, roles, and active status.
	// The verifier reads it in-memory; no live issuer/chain call is ever made.
	reg, err := trustregistry.NewPersistentRegistry(regPath)
	if err != nil {
		log.Fatalf("open trust registry snapshot %s: %v", regPath, err)
	}
	eng := verifier.New(reg)
	log.Printf("loaded trust registry snapshot: %s", regPath)

	// ── HTTP mux ───────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/health", handleHealth)
	mux.HandleFunc("/agent/verify", handleVerify(eng))

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
	log.Printf("listening on %s (verify role)", addr)

	// ── unveil + pledge ────────────────────────────────────────────────
	// The snapshot is already loaded into memory and the listener is bound.
	// unveil restricts the filesystem view to the snapshot path read-only;
	// pledge "stdio rpath inet" omits wpath/cpath, so the verify role cannot
	// write to disk or mutate the registry — it is structurally read-only.
	unveil(regPath, "r")
	unveilLock()
	if err := pledge("stdio rpath inet"); err != nil {
		log.Fatalf("pledge: %v", err)
	}

	// ── Graceful shutdown ──────────────────────────────────────────────
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
	writeJSON(w, map[string]string{"status": "ok", "service": "agentsvc", "role": "verify"})
}

// txnBody mirrors ledger.TxnContext for JSON transport.
type txnBody struct {
	Chain       string            `json:"chain"`
	Originator  string            `json:"originator"`
	Beneficiary string            `json:"beneficiary"`
	Amount      string            `json:"amount"`
	Currency    string            `json:"currency"`
	Timestamp   int64             `json:"timestamp"`
	Extra       map[string]string `json:"extra"`
}

type verifyRequest struct {
	TxnToken  string   `json:"txn_token"`
	DPoPProof string   `json:"dpop_proof"`
	HTM       string   `json:"htm"`
	HTU       string   `json:"htu"`
	CTChain   []string `json:"ct_chain"` // root→leaf; multi-hop
	CT        string   `json:"ct"`       // single-hop alternative (legacy)
	CAT       string   `json:"cat"`
	Audience  string   `json:"audience"`
	Txn       txnBody  `json:"txn"`
}

func handleVerify(eng *verifier.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Cap request size: a chain plus tokens, but never unbounded.
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)

		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Don't echo decoder internals to the client; log server-side.
			log.Printf("verify: decode body: %v", err)
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		in := verifier.Input{
			TxnToken:  req.TxnToken,
			DPoPProof: req.DPoPProof,
			HTM:       req.HTM,
			HTU:       req.HTU,
			CT:        req.CT,
			CTChain:   req.CTChain,
			CAT:       req.CAT,
			Audience:  req.Audience,
			Txn: ledger.TxnContext{
				Chain:       req.Txn.Chain,
				Originator:  req.Txn.Originator,
				Beneficiary: req.Txn.Beneficiary,
				Amount:      req.Txn.Amount,
				Currency:    req.Txn.Currency,
				Timestamp:   req.Txn.Timestamp,
				Extra:       req.Txn.Extra,
			},
		}

		d := eng.Verify(r.Context(), in)

		// On allow, Step is 0 and Reason is empty by contract. On deny, surface
		// which step failed and why — these describe the CLIENT's presented
		// tokens (not any server secret) and the engine logic is open source, so
		// returning them aids integrators without leaking anything sensitive.
		resp := map[string]any{"allow": d.Allow}
		if !d.Allow {
			resp["step"] = d.Step
			resp["step_name"] = d.StepName
			resp["reason"] = d.Reason
		}
		writeJSON(w, resp)
	}
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
