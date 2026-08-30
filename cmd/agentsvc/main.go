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
	"crypto/ed25519"
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

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
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
	// An ABSENT snapshot is a legitimately fresh deploy to the registry writer,
	// and a silent outage to a verifier: NewPersistentRegistry returns an empty
	// registry with no error, the service reports healthy, and every verify
	// denies forever. Refuse to start instead — a service that answers /health
	// with "ok" while denying 100% of traffic is indistinguishable from a working
	// one, and that is worse than not starting.
	if err := snapshotPresent(regPath); err != nil {
		log.Fatalf("trust registry snapshot %s: %v", regPath, err)
	}
	// Presence is not authenticity. This service verifies tokens for a living,
	// so the file it resolves issuer keys from has to be the one the publisher
	// signed — otherwise anyone who can write it chooses which keys this service
	// trusts, and every verification below is theatre.
	pinned, err := pinnedPublicationKeys(os.Getenv("SPT_AGENT_SNAPSHOT_KEYS"))
	if err != nil {
		log.Fatalf("SPT_AGENT_SNAPSHOT_KEYS: %v\n"+
			"  set it to the publisher's ed25519 public key(s), hex, comma-separated;\n"+
			"  generate a keypair and sign a snapshot with: go run ./cmd/snapshot", err)
	}
	maxAge := 24 * time.Hour
	if v := os.Getenv("SPT_AGENT_SNAPSHOT_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("SPT_AGENT_SNAPSHOT_MAX_AGE: %v", err)
		}
		maxAge = d
	}
	allowStale := os.Getenv("SPT_AGENT_SNAPSHOT_ALLOW_STALE") == "1"
	if allowStale {
		log.Printf("WARNING: SPT_AGENT_SNAPSHOT_ALLOW_STALE=1 — a stale snapshot keeps authorizing, " +
			"including one restored from before a compromise. Deliberate degrade mode, and it is on.")
	}

	manifestPath := os.Getenv("SPT_AGENT_SNAPSHOT_MANIFEST")
	if manifestPath == "" {
		manifestPath = trustregistry.ManifestPathFor(regPath)
	}
	reg, err := trustregistry.OpenVerified(manifestPath, regPath, trustsnapshot.Options{
		PinnedKeys: pinned,
		MaxAge:     maxAge,
		AllowStale: allowStale,
	})
	if err != nil {
		log.Fatalf("trust registry snapshot %s: %v", regPath, err)
	}
	if err := issuerKeysPresent(reg); err != nil {
		log.Fatalf("trust registry snapshot %s: %v", regPath, err)
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

// snapshotPresent asserts the snapshot file is actually there and is a
// non-empty regular file. It deliberately does NOT parse or authenticate it:
// this is the presence guard, and authenticity is verify.FromSignedSnapshot's
// job. Keeping the two separate means neither can be mistaken for the other.
func snapshotPresent(path string) error {
	if path == "" {
		return fmt.Errorf("no path configured")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("not readable: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("is a directory")
	}
	if fi.Size() == 0 {
		return fmt.Errorf("is empty")
	}
	return nil
}

// issuerKeysPresent refuses a snapshot with no token-issuance authority in it.
// A zero-record snapshot is a valid fail-closed FIXTURE; it is not a
// configuration this service can do anything with, and starting on one produces
// exactly the healthy-but-denying state above.
func issuerKeysPresent(reg *trustregistry.PersistentRegistry) error {
	ctx := context.Background()
	for _, role := range []trustregistry.Role{trustregistry.RoleCTIssuer, trustregistry.RoleTTSIssuer} {
		recs, err := reg.List(ctx, role)
		if err != nil {
			return fmt.Errorf("list %s: %w", role, err)
		}
		if len(recs) > 0 {
			return nil
		}
	}
	return fmt.Errorf("contains no ct_issuer or tts_issuer records — every verification would deny")
}

// pinnedPublicationKeys parses the publication-key set: hex ed25519 public keys,
// comma-separated. A SET, so a rotation has an overlap window. Empty is refused
// rather than defaulted — "accept whatever key appears" is trust-on-first-use,
// which is the failure the verification path exists to close.
func pinnedPublicationKeys(raw string) ([]ed25519.PublicKey, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("no pinned publication key configured")
	}
	var out []ed25519.PublicKey
	for i, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		b, err := hex.DecodeString(field)
		if err != nil {
			return nil, fmt.Errorf("key %d is not hex: %w", i, err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %d is %d bytes, want %d", i, len(b), ed25519.PublicKeySize)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no pinned publication key configured")
	}
	return out, nil
}
