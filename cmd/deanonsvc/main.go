// cmd/deanonsvc — escrow deanonymization service for the SPT-Txn POC.
//
// This is the single most sensitive component in the system: it holds the
// escrow private key that can recover the real identity behind ANY humanAnchor.
// It is therefore served ONLY on a local, owner-only Unix socket — never a TCP
// port, never behind relayd. There is no network path to deanonymization by
// construction. Runs as its own user (_sptesc) so the escrow key is isolated
// from the issuers (see internal/escrow/vault.go).
//
// It exposes three endpoints on the socket:
//
//	GET  /escrow/health        liveness
//	POST /escrow/store         deposit a sealed envelope (issuer / CAT issuance)
//	POST /escrow/deanonymize   signed, lawful-basis request → recovered identity
//
// Deanonymization is gated by internal/escrow.Handler: the request must be
// signed by a key registered for the escrow_req role AND carry a lawful basis,
// and it is freshness- and replay-checked. Authorized escrow_req signers are
// loaded from the Trust Registry at startup.
//
// Env vars:
//
//	SPT_ESC_KEY     hybrid escrow private key file (hex, from escrowkeygen)
//	                default /var/spt-txn/escrow/escrow.key
//	SPT_ESC_SOCKET  admin Unix socket, mode 0600
//	                default /var/spt-txn/sockets/escrow.sock
//	SPT_TR_DB       Trust Registry file (read-only, for escrow_req signers)
//	                default /var/spt-txn/tr/registry.db
//
// POC boundaries (documented, not hidden): the vault is in-memory, so deposited
// envelopes do not survive a restart — a production deployment backs it with a
// persistent, encrypted store. escrow_req signers are loaded once at startup;
// rotating them requires a restart. The escrow key should be held in threshold
// / offline custody in production (see docs/PQ-ESCROW-HYBRID-KEM-SCOPE.md §5);
// loading a single on-disk key here is the POC custody model.
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/escrow"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
)

const (
	defaultKeyPath = "/var/spt-txn/escrow/escrow.key"
	defaultSocket  = "/var/spt-txn/sockets/escrow.sock"
	defaultDB      = "/var/spt-txn/tr/registry.db"
	maxBodyBytes   = 64 << 10
)

func main() {
	keyPath := envOr("SPT_ESC_KEY", defaultKeyPath)
	socket := envOr("SPT_ESC_SOCKET", defaultSocket)
	dbPath := envOr("SPT_TR_DB", defaultDB)

	log.SetPrefix("deanonsvc: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// ── Load the escrow private key (fail closed) ──────────────────────
	key, err := loadEscrowKey(keyPath)
	if err != nil {
		log.Fatalf("load escrow key %s: %v", keyPath, err)
	}
	log.Printf("escrow key loaded (hybrid X25519+ML-KEM-768)")

	// ── Build vault + handler, load escrow_req signers from the registry ──
	vault := escrow.NewVault()
	handler := escrow.NewHandler(vault, key)

	reg, err := trustregistry.NewPersistentRegistry(dbPath)
	if err != nil {
		log.Fatalf("open trust registry %s: %v", dbPath, err)
	}
	n, err := loadSigners(handler, reg)
	_ = reg.Close()
	if err != nil {
		log.Fatalf("load escrow_req signers: %v", err)
	}
	if n == 0 {
		// Not fatal: a service with no authorized signers simply refuses every
		// request (fail closed). Surface it loudly so an operator notices.
		log.Printf("WARNING: no active escrow_req signers in the registry — every deanonymization request will be refused")
	} else {
		log.Printf("loaded %d escrow_req signer(s)", n)
	}

	// ── Bind the owner-only Unix socket (never TCP) ────────────────────
	_ = os.Remove(socket)
	var ln net.Listener
	withTightUmask(func() {
		ln, err = net.Listen("unix", socket)
	})
	if err != nil {
		log.Fatalf("listen unix %s: %v", socket, err)
	}
	// Re-assert 0600 defensively; if we cannot guarantee owner-only, refuse to
	// serve rather than expose deanonymization under unknown permissions.
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(socket)
		log.Fatalf("chmod socket %s: %v — refusing to serve", socket, err)
	}
	log.Printf("deanon socket at %s (owner-only, no network path)", socket)

	// ── unveil + pledge ────────────────────────────────────────────────
	// The key and registry were read above; at serve time the only filesystem
	// need is the socket directory (create/unlink the node). No inet promise:
	// deanonymization is never network-reachable.
	unveil(filepath.Dir(socket), "rwc")
	unveilLock()
	if err := pledge("stdio rpath cpath unix"); err != nil {
		log.Fatalf("pledge: %v", err)
	}

	// ── Serve (socket only) ────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/escrow/health", handleHealth)
	mux.HandleFunc("/escrow/store", handleStore(vault))
	mux.HandleFunc("/escrow/deanonymize", handleDeanonymize(handler))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

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

// loadEscrowKey reads the hex-encoded hybrid escrow private key and parses it,
// zeroing the decoded buffer once the key object holds the material.
func loadEscrowKey(path string) (*escrow.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	key, err := escrow.ParseKey(raw)
	for i := range raw { // best-effort wipe of the serialized private bytes
		raw[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

// loadSigners registers every currently-valid escrow_req Ed25519 key from the
// registry as an authorized deanonymization requester.
func loadSigners(h *escrow.Handler, reg trustregistry.Registry) (int, error) {
	recs, err := reg.List(context.Background(), trustregistry.RoleEscrowReq)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := 0
	for _, rec := range recs {
		if !rec.IsCurrentlyValid(now) {
			continue
		}
		if rec.KeyType != trustregistry.KeyTypeEd25519 || len(rec.PublicKey) != ed25519.PublicKeySize {
			log.Printf("skipping escrow_req record %q: unexpected key type/length", rec.Iss)
			continue
		}
		h.AddSigner(rec.Iss, ed25519.PublicKey(rec.PublicKey))
		n++
	}
	return n, nil
}

// ── Handlers ─────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "service": "deanonsvc"})
}

// handleStore deposits a sealed envelope into the vault. Access is gated by the
// socket's filesystem permissions (local processes only); the depositor is not
// separately authenticated in the POC.
func handleStore(vault *escrow.Vault) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var env escrow.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			log.Printf("store: decode: %v", err)
			jsonError(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		if err := vault.Store(&env); err != nil {
			if errors.Is(err, escrow.ErrExists) {
				jsonError(w, "envelope already exists for humanAnchor", http.StatusConflict)
				return
			}
			jsonError(w, "cannot store envelope", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"stored": env.HumanAnchor, "scheme": env.Scheme})
	}
}

type deanonRequest struct {
	HumanAnchor string `json:"human_anchor"`
	Requester   string `json:"requester"`
	LawfulBasis string `json:"lawful_basis"`
	IssuedAt    int64  `json:"issued_at"`
	Sig         string `json:"sig"` // hex-encoded Ed25519 signature
}

// handleDeanonymize authorizes and executes a deanonymization request, returning
// the recovered identity on success. Every refusal maps to a distinct status so
// an audit log records exactly why.
func handleDeanonymize(h *escrow.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var body deanonRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Printf("deanon: decode: %v", err)
			jsonError(w, "invalid request", http.StatusBadRequest)
			return
		}
		sig, err := hex.DecodeString(body.Sig)
		if err != nil {
			jsonError(w, "invalid sig hex", http.StatusBadRequest)
			return
		}
		req := &escrow.Request{
			HumanAnchor: body.HumanAnchor,
			Requester:   body.Requester,
			LawfulBasis: body.LawfulBasis,
			IssuedAt:    body.IssuedAt,
			Sig:         sig,
		}
		identity, err := h.Deanonymize(req)
		if err != nil {
			// Audit the refusal (requester + anchor + reason), never the identity.
			log.Printf("deanon REFUSED requester=%q anchor=%q basis=%q: %v",
				body.Requester, body.HumanAnchor, body.LawfulBasis, err)
			jsonError(w, "deanonymization refused: "+err.Error(), deanonStatus(err))
			return
		}
		// Accountability: record that a successful recovery happened and under
		// what basis — but not the recovered identity itself.
		log.Printf("deanon GRANTED requester=%q anchor=%q basis=%q",
			body.Requester, body.HumanAnchor, body.LawfulBasis)
		writeJSON(w, map[string]any{
			"human_anchor": body.HumanAnchor,
			"identity_hex": hex.EncodeToString(identity),
		})
	}
}

func deanonStatus(err error) int {
	switch {
	case errors.Is(err, escrow.ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, escrow.ErrBadSignature), errors.Is(err, escrow.ErrNoLawfulBasis):
		return http.StatusBadRequest
	case errors.Is(err, escrow.ErrStaleRequest):
		return http.StatusRequestTimeout
	case errors.Is(err, escrow.ErrReplay):
		return http.StatusConflict
	case errors.Is(err, escrow.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("json encode: %v", err)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
