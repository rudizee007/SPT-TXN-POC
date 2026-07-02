// cmd/trsvc — Trust Registry HTTP service for the SPT-Txn POC.
//
// Listens on a local TCP port (default 127.0.0.1:8081) so relayd can
// forward /tr/* requests to it. Also creates a Unix socket for direct
// inter-process use by other SPT-Txn services on the same host.
// Applies pledge(2) and unveil(2) after binding both listeners.
//
// Endpoints:
//   GET /tr/health          — liveness check, returns 200 OK + JSON
//   GET /tr/lookup?iss=&role= — active record lookup
//   GET /tr/list?role=      — list records (empty role = all)
//
// Run as _spttr. Env vars:
//   SPT_TR_ADDR    TCP listen address (default 127.0.0.1:8081) — read-only,
//                  relayd-facing (lookup/list/health). NEVER serves register.
//   SPT_TR_SOCKET  Admin Unix socket  (default /var/spt-txn/sockets/tr-admin.sock)
//                  — serves /tr/register, mode 0600, owner-only. relayd MUST NOT
//                  forward to this socket; registration is local-admin only.
//   SPT_TR_DB      SQLite DB path     (default /var/spt-txn/tr/registry.db)
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"


	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
)

const (
	defaultAddr   = "127.0.0.1:8081"
	defaultSocket = "/var/spt-txn/sockets/tr-admin.sock"
	defaultDB     = "/var/spt-txn/tr/registry.db"
)

func main() {
	addr       := envOr("SPT_TR_ADDR",   defaultAddr)
	socketPath := envOr("SPT_TR_SOCKET", defaultSocket)
	dbPath     := envOr("SPT_TR_DB",     defaultDB)

	log.SetPrefix("trsvc: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// ── Open registry ──────────────────────────────────────────────
	// File-backed and durable: real issuer registrations survive a
	// restart, so seedIfEmpty (below) never silently re-revokes a live
	// issuer (security review M7 / Trust Registry persistence).
	reg, err := trustregistry.NewPersistentRegistry(dbPath)
	if err != nil {
		log.Fatalf("open registry: %v", err)
	}
	defer reg.Close()

	if err := seedIfEmpty(reg); err != nil {
		log.Fatalf("seed registry: %v", err)
	}

	// ── Bind TCP listener (for relayd) ─────────────────────────────
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen tcp %s: %v", addr, err)
	}
	log.Printf("TCP listening on %s", addr)

	// ── Bind Unix socket (for local inter-process) ─────────────────
	_ = os.Remove(socketPath)
	// Bind under a tight umask (0o177) so the socket node is *born* mode 0600.
	// Previously Listen created the node under the inherited umask and a
	// follow-up Chmod tightened it — leaving a TOCTOU window where the admin
	// socket (which carries /tr/register) was connectable under looser perms
	// (security review SVC-2).
	var unixLn net.Listener
	withTightUmask(func() {
		unixLn, err = net.Listen("unix", socketPath)
	})
	if err != nil {
		log.Printf("warn: listen unix %s: %v (continuing without unix socket)", socketPath, err)
		unixLn = nil
	} else {
		// 0600: owner-only. The admin socket carries /tr/register, so only the
		// service user (and root) may connect — never group/other, and never the
		// network. relayd must not be pointed at this path. The umask above
		// already makes the node 0600; this Chmod re-asserts it defensively. If
		// it fails we cannot guarantee the socket is owner-only, so we refuse to
		// serve admin rather than expose registration under unknown perms.
		if err := os.Chmod(socketPath, 0600); err != nil {
			log.Printf("warn: chmod admin socket %s: %v — refusing to serve admin", socketPath, err)
			_ = unixLn.Close()
			_ = os.Remove(socketPath)
			unixLn = nil
		} else {
			log.Printf("admin Unix socket at %s (register is local-admin only)", socketPath)
		}
	}

	// ── unveil + pledge ────────────────────────────────────────────
	// unveil (filesystem confinement, security review SVC-5): restrict the
	// visible filesystem to ONLY the two directories trsvc legitimately
	// touches at runtime — the registry DB dir (read the store at startup;
	// write temp + rename + dir-fsync on every registration) and the socket
	// dir (create/remove the admin socket node). "rwc" covers read, write, and
	// create for both. After unveilLock no other path on disk is reachable, so
	// a bug in the registrar cannot read or clobber anything else.
	unveil(filepath.Dir(dbPath), "rwc")
	unveil(filepath.Dir(socketPath), "rwc")
	unveilLock()

	// pledge (syscall confinement, security review C4). Promise set is a small
	// superset of what serving needs: stdio (runtime), rpath (read the registry
	// file at startup + fsync the parent dir after rename), wpath+cpath (atomic
	// registry persistence — write temp file, rename into place — plus Go
	// unlinks the unix socket on listener Close at shutdown), inet (TCP), unix
	// (admin socket).
	if err := pledge("stdio rpath wpath cpath inet unix"); err != nil {
		log.Fatalf("pledge: %v", err)
	}

	// ── HTTP muxes ─────────────────────────────────────────────────
	// Read-only endpoints are exposed on the TCP listener (relayd-facing).
	// The mutating /tr/register endpoint is served ONLY on the local Unix
	// socket, so it is reachable solely by local processes with filesystem
	// access to the socket — never via relayd/TCP (review C1). Registration is
	// thus gated by OpenBSD socket/file permissions, not exposed to the network.
	readMux := http.NewServeMux()
	readMux.HandleFunc("/tr/health", handleHealth)
	readMux.HandleFunc("/tr/lookup", handleLookup(reg))
	readMux.HandleFunc("/tr/list", handleList(reg))

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/tr/health", handleHealth)
	adminMux.HandleFunc("/tr/lookup", handleLookup(reg))
	adminMux.HandleFunc("/tr/list", handleList(reg))
	adminMux.HandleFunc("/tr/register", handleRegister(reg))

	newSrv := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:      h,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
	}
	publicSrv := newSrv(readMux)
	adminSrv := newSrv(adminMux)

	// ── Graceful shutdown ──────────────────────────────────────────
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = publicSrv.Shutdown(ctx)
		_ = adminSrv.Shutdown(ctx)
		close(done)
	}()

	// Admin endpoints (including /tr/register) are served ONLY on the local
	// Unix socket. Without the socket, registration is simply unavailable.
	if unixLn != nil {
		go func() {
			if err := adminSrv.Serve(unixLn); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Printf("unix serve: %v", err)
			}
		}()
	} else {
		log.Printf("warn: no unix socket — registration endpoint unavailable")
	}

	log.Printf("ready")
	if err := publicSrv.Serve(tcpLn); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("tcp serve: %v", err)
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
	writeJSON(w, map[string]string{"status": "ok", "service": "trsvc"})
}

func handleLookup(reg trustregistry.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		iss     := r.URL.Query().Get("iss")
		roleStr := r.URL.Query().Get("role")
		if iss == "" || roleStr == "" {
			jsonError(w, "missing required parameters: iss, role", http.StatusBadRequest)
			return
		}
		role := trustregistry.Role(roleStr)
		if !role.IsValid() {
			jsonError(w, "unknown role: "+roleStr, http.StatusBadRequest)
			return
		}
		rec, err := reg.Lookup(r.Context(), iss, role)
		if errors.Is(err, trustregistry.ErrNotFound) {
			jsonError(w, "record not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("lookup %s/%s: %v", iss, roleStr, err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, recordJSON(rec))
	}
}

func handleList(reg trustregistry.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		role := trustregistry.Role(r.URL.Query().Get("role"))
		recs, err := reg.List(r.Context(), role)
		if err != nil {
			log.Printf("list: %v", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := make([]map[string]any, 0, len(recs))
		for _, rec := range recs {
			out = append(out, recordJSON(rec))
		}
		writeJSON(w, map[string]any{"records": out, "count": len(out)})
	}
}

// ── Helpers ────────────────────────────────────────────────────────────

func recordJSON(rec *trustregistry.Record) map[string]any {
	m := map[string]any{
		"iss":         rec.Iss,
		"role":        string(rec.Role),
		"key_type":    rec.KeyType,
		"public_key":  hex.EncodeToString(rec.PublicKey),
		"valid_from":  rec.ValidFrom.UTC().Format(time.RFC3339),
		"valid_until": rec.ValidUntil.UTC().Format(time.RFC3339),
		"status":      string(rec.Status),
		"metadata":    rec.Metadata,
	}
	// Emit the ML-KEM-768 encapsulation key for hybrid escrow records so an
	// issuer can rebuild both escrow public halves (escrow.NewPublicKey).
	if len(rec.MlkemEncapKey) > 0 {
		m["mlkem_encap_key"] = hex.EncodeToString(rec.MlkemEncapKey)
	}
	return m
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func allZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ── Test seed data ─────────────────────────────────────────────────────

func seedIfEmpty(reg trustregistry.Mutable) error {
	ctx := context.Background()
	existing, err := reg.List(ctx, "")
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	zeroKey := make([]byte, 32)
	now     := time.Now().UTC()
	oneYear := now.Add(365 * 24 * time.Hour)
	note    := map[string]string{"note": "revoked placeholder — register a real signify key via regkey (socket)"}

	seeds := []*trustregistry.Record{
		{Iss: "domain-a.authorg", Role: trustregistry.RoleCTIssuer,
			PublicKey: zeroKey, KeyType: "Ed25519",
			ValidFrom: now, ValidUntil: oneYear,
			Status: trustregistry.StatusRevoked, Metadata: note},
		{Iss: "domain-a.authorg", Role: trustregistry.RoleEscrow,
			PublicKey: zeroKey, KeyType: "X25519",
			ValidFrom: now, ValidUntil: oneYear,
			Status: trustregistry.StatusRevoked, Metadata: note},
		{Iss: "domain-b.execorg", Role: trustregistry.RoleTTSIssuer,
			PublicKey: zeroKey, KeyType: "Ed25519",
			ValidFrom: now, ValidUntil: oneYear,
			Status: trustregistry.StatusRevoked, Metadata: note},
		{Iss: "domain-b.execorg", Role: trustregistry.RoleAudit,
			PublicKey: zeroKey, KeyType: "Ed25519",
			ValidFrom: now, ValidUntil: oneYear,
			Status: trustregistry.StatusRevoked, Metadata: note},
	}
	for _, rec := range seeds {
		if err := reg.Register(ctx, rec); err != nil {
			return err
		}
	}
	log.Printf("seeded %d test records", len(seeds))
	return nil
}

// handleRegister adds or updates a registry record via HTTP POST.
// Used by the regkey tool to replace zero-byte test keys with real keys.
// Body: {"iss":"...","role":"...","key_type":"...","public_key":"<hex>"}
func handleRegister(reg trustregistry.Mutable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10) // cap body (review M5)
		var body struct {
			Iss           string `json:"iss"`
			Role          string `json:"role"`
			KeyType       string `json:"key_type"`
			PublicKey     string `json:"public_key"`
			MlkemEncapKey string `json:"mlkem_encap_key"` // hybrid escrow only
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			// Don't echo the decoder error to the client — it can leak parser
			// internals/offsets. Log server-side, return a generic message
			// (security review SVC-7). This endpoint is admin-only, but we keep
			// it consistent with the network-facing handlers.
			log.Printf("register: decode body: %v", err)
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		pubBytes, err := hex.DecodeString(body.PublicKey)
		if err != nil {
			jsonError(w, "invalid public_key hex", http.StatusBadRequest)
			return
		}
		role := trustregistry.Role(body.Role)
		if !role.IsValid() {
			jsonError(w, "unknown role", http.StatusBadRequest)
			return
		}
		// Reject malformed or degenerate keys at the registrar (review C1/C2).
		// The X25519 half is always 32 bytes and must never be all-zero. The
		// registry's validateRecord re-checks lengths per KeyType; this gate is
		// the network-facing first line (SVC-6).
		if len(pubBytes) != 32 {
			jsonError(w, "public_key must be 32 bytes", http.StatusBadRequest)
			return
		}
		if allZeroBytes(pubBytes) {
			jsonError(w, "refusing degenerate all-zero key", http.StatusBadRequest)
			return
		}
		// Hybrid escrow (KeyTypeX25519MLKEM768) additionally carries a
		// 1184-byte ML-KEM-768 encapsulation key; it is permitted only for the
		// escrow role. Classical key types must not supply one.
		var mlkemBytes []byte
		if body.MlkemEncapKey != "" {
			mlkemBytes, err = hex.DecodeString(body.MlkemEncapKey)
			if err != nil {
				jsonError(w, "invalid mlkem_encap_key hex", http.StatusBadRequest)
				return
			}
		}
		if body.KeyType == trustregistry.KeyTypeX25519MLKEM768 {
			if role != trustregistry.RoleEscrow {
				jsonError(w, "hybrid key type is escrow-only", http.StatusBadRequest)
				return
			}
			if len(mlkemBytes) != trustregistry.MlkemEncapKeySize {
				jsonError(w, "mlkem_encap_key must be 1184 bytes for hybrid escrow", http.StatusBadRequest)
				return
			}
			if allZeroBytes(mlkemBytes) {
				jsonError(w, "refusing degenerate all-zero mlkem_encap_key", http.StatusBadRequest)
				return
			}
		} else if len(mlkemBytes) != 0 {
			jsonError(w, "mlkem_encap_key allowed only with key_type "+trustregistry.KeyTypeX25519MLKEM768, http.StatusBadRequest)
			return
		}
		if body.Iss == "" {
			jsonError(w, "iss required", http.StatusBadRequest)
			return
		}
		now    := time.Now().UTC()
		oneYear := now.Add(365 * 24 * time.Hour)
		rec := &trustregistry.Record{
			Iss:           body.Iss,
			Role:          role,
			KeyType:       body.KeyType,
			PublicKey:     pubBytes,
			MlkemEncapKey: mlkemBytes,
			ValidFrom:     now, ValidUntil: oneYear,
			Status:   trustregistry.StatusActive,
			Metadata: map[string]string{"note": "registered via regkey tool (socket)"},
		}
		// Atomically supersede any existing active record and install the new
		// one. Replace does the revoke-old + append-new under a single lock and
		// a single persisted save with rollback-on-failure, so a crash can never
		// leave this issuer with no active key (security review SVC-1). The old
		// Revoke-then-Register pair was two separate saves with a gap between
		// them — and it swallowed the Revoke error with `_ =`.
		ctx := r.Context()
		if err := reg.Replace(ctx, rec); err != nil {
			// Don't echo the registry error to the client (SVC-7).
			log.Printf("register %s/%s: %v", body.Iss, body.Role, err)
			jsonError(w, "registration failed", http.StatusBadRequest)
			return
		}
		log.Printf("registered %s / %s key=%s", body.Iss, body.Role, body.PublicKey[:16]+"...")
		writeJSON(w, map[string]string{"status": "registered"})
	}
}
