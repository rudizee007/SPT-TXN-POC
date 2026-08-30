// cmd/workload-bridge — RFC 8693 Token Exchange: attested WORKLOAD identity ->
// SPT-Txn CAT. The workload analog of cmd/idp-bridge (SPT-Txn P4, NHI attested
// issuance; spec docs/spec/NHI-ATTESTED-ISSUANCE.md).
//
// A workload presents an attested identity — SPIFFE JWT-SVID / X.509-SVID, a
// Kubernetes projected ServiceAccount token, or a cloud workload-identity OIDC
// assertion (AWS IRSA / GCP WIF / Azure FC) — and receives a transaction-scoped
// CAT whose spt_attestation claim seals the evidence digest. A downstream
// verifier then checks not only WHO acted but ON WHAT ATTESTED SUBSTRATE.
//
// Trust material is PINNED (the correct posture for SPIFFE bundles):
//
//	SPT_WL_JWKS_FILE     JWKS JSON for the JWT trust domain (RSA + Ed25519 keys)
//	SPT_WL_X509_ROOTS    PEM roots for spiffe-x509-svid (optional)
//	SPT_WL_ISSUER        expected `iss` for k8s/cloud methods (not SPIFFE JWT-SVID)
//	SPT_WL_AUDIENCE      required audience this exchange endpoint expects
//	SPT_WL_CAT_ISSUER    CAT issuer identity (default domain-a.authorg)
//	SPT_WL_CAT_SEED_HEX  pinned Ed25519 CAT signing seed (else ephemeral)
//	SPT_WL_ADDR          listen address (default 127.0.0.1:8091)
//
// POST /token params (form-encoded or JSON):
//
//	grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
//	subject_token       = <attested assertion>  (JWT methods)
//	subject_token_cert  = <base64 DER leaf>      (spiffe-x509-svid; PEM also ok)
//	subject_token_type  = urn:violetsky:token-type:{spiffe-jwt-svid|k8s-sa|gcp-wif|...}
//	holder_key_hex      = <64-hex Ed25519 public key of the workload/agent>
//	audience            = <this endpoint's identifier>   (required)
//	scope               = <JSON object>   (optional; intersected with the policy ceiling)
//	requested_max_age_s = <int>           (optional freshness predicate)
//	dry_run             = "true"          (optional; run the full evaluation and
//	                                       return the decision it WOULD make —
//	                                       would_issue + granted scope, or the
//	                                       denial reason — WITHOUT issuing a token)
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
const catTokenType = "urn:violetsky:token-type:spt-cat"

// maxDelegationDepth bounds the delegation fan-out a single exchange may request
// (fail-closed: a caller can never request an unbounded chain). The attestation
// proves identity, not entitlement; scope entitlement is decided here by the
// issuer as intersect(requested, permitted) and independently re-checked on the
// full chain by the PEP at execution.
const maxDelegationDepth = 8

func main() {
	addr := envOr("SPT_WL_ADDR", "127.0.0.1:8091")
	catIssuer := envOr("SPT_WL_CAT_ISSUER", "domain-a.authorg")
	expectedIssuer := os.Getenv("SPT_WL_ISSUER")
	audience := os.Getenv("SPT_WL_AUDIENCE")

	log.SetPrefix("workload-bridge: ")
	log.SetFlags(log.Ltime)

	if audience == "" {
		log.Fatal("SPT_WL_AUDIENCE is required (binds assertions to this endpoint)")
	}

	// CAT signing key.
	var priv ed25519.PrivateKey
	if seedHex := os.Getenv("SPT_WL_CAT_SEED_HEX"); seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("SPT_WL_CAT_SEED_HEX must be %d hex bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		priv = p
		// The seed is NOT printed. It signs every CAT this process issues, and a
		// log line is the widest possible distribution channel for it: stdout,
		// journald, the container runtime, and whatever aggregator ships them
		// onward, all of which are read by people who are not trusted with a
		// signing key. Write it where the operator asked for it, or say nothing.
		// (cmd/idp-bridge was fixed first; this is its twin and had the same bug.)
		if out := os.Getenv("SPT_WL_CAT_SEED_OUT"); out != "" {
			if err := os.WriteFile(out, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
				log.Fatalf("SPT_WL_CAT_SEED_OUT %s: %v", out, err)
			}
			log.Printf("generated an ephemeral CAT issuer key and wrote its seed to %s (0600)", out)
		} else {
			log.Printf("generated an ephemeral CAT issuer key; it is discarded on exit. " +
				"To pin it across restarts set SPT_WL_CAT_SEED_HEX, or set SPT_WL_CAT_SEED_OUT " +
				"to a path and this process will write the seed there with mode 0600.")
		}
	}
	pub := priv.Public().(ed25519.PublicKey)
	log.Printf("CAT issuer %q public key: %s", catIssuer, hex.EncodeToString(pub))

	// Pinned JWT trust bundle.
	var ks attest.KeySource
	if f := os.Getenv("SPT_WL_JWKS_FILE"); f != "" {
		keys, err := loadJWKS(f)
		if err != nil {
			log.Fatalf("JWKS %s: %v", f, err)
		}
		ks = attest.NewStaticKeySource(keys)
		log.Printf("loaded %d JWT trust key(s) from %s", len(keys), f)
	}

	// Optional X.509 SVID roots.
	var x509Bundle attest.X509Bundle
	if f := os.Getenv("SPT_WL_X509_ROOTS"); f != "" {
		pool, err := loadPEMRoots(f)
		if err != nil {
			log.Fatalf("X.509 roots %s: %v", f, err)
		}
		x509Bundle = attest.X509Bundle{Roots: pool}
		log.Printf("loaded X.509 SVID trust roots from %s", f)
	}

	h := &handler{
		ks: ks, x509: x509Bundle, priv: priv, catIssuer: catIssuer,
		expectedIssuer: expectedIssuer, audience: audience,
		permitted: loadPermittedScope("SPT_WL_PERMITTED_SCOPE"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "workload-bridge"})
	})
	mux.HandleFunc("/issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": catIssuer, "public_key_hex": hex.EncodeToString(pub)})
	})
	mux.HandleFunc("/token", h.exchange)

	log.Printf("listening on %s  (POST /token, GET /issuer, GET /health)", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

type handler struct {
	ks             attest.KeySource
	x509           attest.X509Bundle
	priv           ed25519.PrivateKey
	catIssuer      string
	expectedIssuer string
	audience       string
	permitted      tbac.Scope
}

// exchangeDecision is the outcome of evaluating an exchange, computed
// identically for the live and dry-run paths. On allow it carries what WOULD be
// minted; on deny it carries the exact response the live path returns. It never
// carries a token — minting happens only in the live branch of exchange(),
// after this decision, so a dry-run is structurally incapable of producing
// authority.
type exchangeDecision struct {
	wouldIssue bool

	// allow
	scope  tbac.Scope
	depth  int
	ttl    time.Duration
	id     attest.Identity
	holder []byte

	// deny (mirrors the live oauthErr call)
	httpStatus    int
	oauthError    string
	description   string
	decisionClass string // "ok" | "violation" | "invalid_request"
}

func (h *handler) exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	p := parseParams(r)
	dryRun := p["dry_run"] == "true"

	dec := h.decide(r.Context(), p)

	if !dec.wouldIssue {
		if dryRun {
			writeJSON(w, http.StatusOK, map[string]any{
				"dry_run":           true,
				"would_issue":       false,
				"decision_class":    dec.decisionClass,
				"error":             dec.oauthError,
				"error_description": dec.description,
			})
			return
		}
		oauthErr(w, dec.httpStatus, dec.oauthError, dec.description)
		return
	}

	if dryRun {
		// Preview only: report the decision, mint nothing.
		writeJSON(w, http.StatusOK, map[string]any{
			"dry_run":              true,
			"would_issue":          true,
			"decision_class":       "ok",
			"granted_scope":        map[string]any(dec.scope),
			"delegation_depth_max": dec.depth,
			"expires_in":           int(dec.ttl.Seconds()),
			"attested_subject":     dec.id.Subject,
			"attestation_method":   string(dec.id.Method),
		})
		return
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             h.catIssuer,
		Subject:            "workload:" + dec.id.Subject,
		PrincipalName:      dec.id.Subject,
		Scope:              cattoken.CapabilityScope(dec.scope),
		DelegationDepthMax: dec.depth,
		TTL:                dec.ttl,
		HolderPublicKey:    ed25519.PublicKey(dec.holder),
		Attestation:        dec.id.SealClaim(),
	}, h.priv)
	if err != nil {
		log.Printf("cattoken.Issue: %v", err)
		oauthErr(w, http.StatusBadRequest, "invalid_request", "issuance failed")
		return
	}
	log.Printf("exchanged %s attestation (sub=%s) -> attested CAT", dec.id.Method, dec.id.Subject)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       cat.Token,
		"issued_token_type":  catTokenType,
		"token_type":         "N_A",
		"expires_in":         int(time.Until(cat.ExpiresAt).Seconds()),
		"attested_subject":   dec.id.Subject,
		"attestation_method": string(dec.id.Method),
	})
}

// decide runs the full evaluation pipeline and returns a decision. It performs
// no I/O beyond attestation verification and mints nothing. Live and dry-run
// call this identically; only exchange() decides whether to act on the result.
func (h *handler) decide(ctx context.Context, p map[string]string) exchangeDecision {
	deny := func(status int, oauthError, desc, class string) exchangeDecision {
		return exchangeDecision{httpStatus: status, oauthError: oauthError, description: desc, decisionClass: class}
	}

	if p["grant_type"] != grantTokenExchange {
		return deny(http.StatusBadRequest, "unsupported_grant_type", "expected "+grantTokenExchange, "invalid_request")
	}
	// Audience must match this endpoint (defeats cross-service replay).
	if p["audience"] != h.audience {
		return deny(http.StatusBadRequest, "invalid_request", "audience must equal this exchange endpoint", "invalid_request")
	}
	holder, err := hex.DecodeString(p["holder_key_hex"])
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return deny(http.StatusBadRequest, "invalid_request", "holder_key_hex must be 64 hex chars", "invalid_request")
	}
	method, err := attest.MethodFromTokenType(p["subject_token_type"])
	if err != nil {
		return deny(http.StatusBadRequest, "invalid_request", "unsupported subject_token_type", "invalid_request")
	}

	id, err := h.verify(ctx, method, p)
	if err != nil {
		log.Printf("attestation rejected (%s): %v", method, err)
		return deny(http.StatusUnauthorized, "invalid_grant", "attestation rejected", "violation")
	}

	// Optional freshness predicate.
	if s := p["requested_max_age_s"]; s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			if err := (attest.Freshness{MaxAge: time.Duration(secs) * time.Second}).Check(id, time.Now()); err != nil {
				log.Printf("freshness rejected: %v", err)
				return deny(http.StatusForbidden, "invalid_grant", "attestation not fresh enough", "violation")
			}
		}
	}

	// Issuer-side scope decision (spec §Attested-Issuance, draft §3): the issuer
	// grants intersect(requested, permitted). An omitted request yields the full
	// permitted ceiling; a request is narrowed to it and can never widen it. The
	// PEP re-checks the chain at execution — this is defense in depth, not a
	// substitute for it.
	var scope tbac.Scope
	requested, err := parseScope(p["scope"])
	if err != nil {
		log.Printf("scope rejected: %v", err)
		return deny(http.StatusBadRequest, "invalid_scope", "requested scope is not a usable JSON object", "violation")
	}
	if requested == nil {
		scope = h.permitted
	} else {
		g, err := tbac.Intersect(h.permitted, tbac.Scope(requested))
		if err != nil {
			log.Printf("scope rejected: %v", err)
			return deny(http.StatusForbidden, "invalid_scope", "requested scope exceeds the policy-permitted ceiling", "violation")
		}
		scope = g
	}
	depth := 3
	if d, err := strconv.Atoi(p["delegation_depth_max"]); err == nil && d >= 1 {
		depth = d
	}
	if depth > maxDelegationDepth {
		depth = maxDelegationDepth
	}

	// CAT lifetime bounded by the attestation lifetime (spec §4). Default 15
	// min, clamped so the CAT never outlives the proof.
	ttl := 15 * time.Minute
	if id.ExpiresAt.IsZero() {
		// No expiry on the attestation means no lifetime to inherit and nothing
		// to clamp against. Refuse rather than mint the full default.
		log.Printf("attestation rejected: no expiry, nothing to bound the CAT lifetime against")
		return deny(http.StatusForbidden, "invalid_grant", "attestation rejected", "violation")
	}
	// Clamp the CAT to the remaining life of the attestation it was minted on.
	// The previous guard was `rem > 0 && rem < ttl`, which SKIPPED the clamp when
	// rem <= 0 -- handing an already-expired attestation the full 15-minute
	// capability, the longest-lived grant to the least-alive proof. Same defect
	// cmd/idp-bridge was fixed for; this is its twin.
	rem := time.Until(id.ExpiresAt)
	if rem <= 0 {
		log.Printf("attestation rejected: past exp by %s", -rem)
		return deny(http.StatusForbidden, "invalid_grant", "attestation rejected", "violation")
	}
	if rem < ttl {
		ttl = rem
	}

	return exchangeDecision{wouldIssue: true, scope: scope, depth: depth, ttl: ttl, id: id, holder: holder}
}

func (h *handler) verify(ctx context.Context, method attest.Method, p map[string]string) (attest.Identity, error) {
	switch method {
	case attest.MethodSPIFFEX509SVID:
		der, err := decodeCert(p["subject_token_cert"])
		if err != nil {
			return attest.Identity{}, err
		}
		return attest.VerifyX509SVID([][]byte{der}, h.x509, time.Now())
	case attest.MethodSPIFFEJWTSVID:
		return attest.VerifySPIFFEJWTSVID(ctx, p["subject_token"], []string{h.audience}, h.ks)
	case attest.MethodK8sSA:
		return attest.VerifyK8sSAToken(ctx, p["subject_token"], h.expectedIssuer, []string{h.audience}, h.ks)
	default: // cloud OIDC federation
		return attest.VerifyCloudWorkload(ctx, p["subject_token"], method, h.expectedIssuer, []string{h.audience}, h.ks)
	}
}

// ── trust-material loading ──────────────────────────────────────────────

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
	} `json:"keys"`
}

func loadJWKS(path string) (map[string]crypto.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		switch k.Kty {
		case "RSA":
			nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
			if err != nil {
				return nil, err
			}
			eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
			if err != nil {
				return nil, err
			}
			e := 0
			for _, b := range eb {
				e = e<<8 | int(b)
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
			if err != nil {
				return nil, err
			}
			if len(xb) != ed25519.PublicKeySize {
				return nil, os.ErrInvalid
			}
			out[k.Kid] = ed25519.PublicKey(xb)
		}
	}
	return out, nil
}

func loadPEMRoots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, os.ErrInvalid
	}
	return pool, nil
}

func decodeCert(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, os.ErrInvalid
		}
		return block.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// ── HTTP helpers ────────────────────────────────────────────────────────

func parseParams(r *http.Request) map[string]string {
	out := map[string]string{}
	ct := r.Header.Get("Content-Type")
	if len(ct) >= 16 && ct[:16] == "application/json" {
		var m map[string]any
		if json.NewDecoder(r.Body).Decode(&m) == nil {
			for k, v := range m {
				switch t := v.(type) {
				case string:
					out[k] = t
				default:
					b, _ := json.Marshal(t)
					out[k] = string(b)
				}
			}
		}
		return out
	}
	_ = r.ParseForm()
	// PostForm, not Form: Form merges the URL query string into the body, so a
	// credential could arrive in a URL -- where it lands in access logs, proxy
	// logs, browser history and Referer headers. RFC 6749 s3.2 requires the token
	// endpoint to take parameters in the body. (cmd/idp-bridge was fixed first.)
	for k := range r.PostForm {
		out[k] = r.PostForm.Get(k)
	}
	return out
}

// parseScope parses the requested-scope parameter. It reports THREE outcomes and
// callers must not collapse them:
//
//	(nil, nil)  no scope was requested — the caller may grant the full ceiling
//	(nil, err)  a scope was present but unusable — the caller MUST deny
//	(m,   nil)  a usable scope object to intersect with the ceiling
//
// The two nil-map cases used to be indistinguishable, which turned a truncated
// body or a wrong content encoding into a grant at the deployment's MAXIMUM
// permitted ceiling: the one place in this service where a parse FAILURE
// produced a WIDER grant. A present-but-unusable scope is a client error, never
// an omission.
func parseScope(s string) (map[string]any, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(s))
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("scope is not a JSON object: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("scope has trailing content after the JSON object")
	}
	// `null` decodes into a nil map with no error, and would otherwise be
	// indistinguishable from an absent parameter.
	if m == nil {
		return nil, fmt.Errorf("scope must be a JSON object, not null")
	}
	return m, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, err, desc string) {
	writeJSON(w, code, map[string]string{"error": err, "error_description": desc})
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// loadPermittedScope reads the policy-permitted scope ceiling this issuer will
// grant, from env as a JSON object. It is REQUIRED and fails closed at startup:
// the issuer will not run without an explicit ceiling, so no authority is ever
// granted by omission (a default ceiling would silently hand out real authority
// on an unconfigured deployment). A malformed value likewise refuses to start.
// Per-principal entitlement policy — a different ceiling per attested subject —
// is a jurisdictional-TBAC (policy-pack) concern layered above this.
func loadPermittedScope(env string) tbac.Scope {
	raw := os.Getenv(env)
	if raw == "" {
		log.Fatalf("%s is required: the issuer must be told the policy-permitted scope ceiling it may grant (a JSON object). It will not start without one, so no authority is granted by omission.", env)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || len(m) == 0 {
		log.Fatalf("%s must be a non-empty JSON object: %v", env, err)
	}
	// A ceiling this issuer cannot legally seal into a token is a configuration
	// error, and it must fail the DEPLOY rather than the first request that
	// happens to hit it. The commonest case: a monetary ceiling with no currency
	// beside it, which bounds the amount in every currency at once.
	if err := tbac.ValidateIssuance(tbac.Scope(m)); err != nil {
		log.Fatalf("%s is not a usable ceiling: %v", env, err)
	}
	log.Printf("permitted scope ceiling loaded from %s", env)
	return tbac.Scope(m)
}
