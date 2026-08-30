// Package trp is an OpenVASP Travel Rule Protocol (TRP) transport for SPT-Txn.
//
// TRP is the REST/JSON inter-VASP Travel Rule protocol (HTTPS POST, IVMS101,
// Api-Version + Request-Identifier headers, Travel Address discovery). Its one
// privacy gap: standard TRP carries the originator/beneficiary IVMS101 identity
// in cleartext to the counterparty and relies solely on transport-level crypto
// (mTLS). TRISA closes that gap with sealed Secure Envelopes; plain TRP does
// not.
//
// SPT-Txn closes it differently and more strongly: instead of shipping the PII,
// the originator ships a payload-level zero-knowledge attestation (a
// selectively-disclosable SD-JWT plus Groth16 proofs of identity-commitment,
// amount-over-threshold, and beneficiary-VASP registration). The beneficiary
// verifies that the transfer is reportable, between registered counterparties,
// with an authenticated identity — without receiving the amount or the identity
// fields it is not entitled to. This package carries that attestation in the TRP
// `extensions` object and lets a VASP refuse cleartext-only transfers.
//
// Scope (POC): mTLS and the bech32m Travel Address are the standard TRP
// transport/addressing; here transport security is delegated to relayd/TLS and
// the Travel Address is a documented base64url encoding of the inbound endpoint.
// The compliance semantics carried in the extension are the real contribution.
package trp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/travelrule"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
)

const (
	// APIVersion is the TRP API version this implementation speaks; sent in the
	// Api-Version header on every request and response.
	APIVersion = "3.2.0"

	// HeaderAPIVersion and HeaderRequestIdentifier are the two headers TRP
	// requires on every message. The responder MUST echo Request-Identifier.
	HeaderAPIVersion        = "Api-Version"
	HeaderRequestIdentifier = "Request-Identifier"

	// ExtensionVersion identifies the SPT-Txn privacy extension that replaces the
	// cleartext IVMS101 originator/beneficiary blocks in a TRP transfer.
	ExtensionVersion = "spt-txn/1"

	travelAddressPrefix = "ta_"
)

// Asset identifies the virtual asset (TRP `asset` object).
type Asset struct {
	SLIP0044 uint32 `json:"slip0044,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
}

// TransferRequest is a TRP transfer initiation (the HTTPS POST body). In
// standard TRP the originator/beneficiary IVMS101 identity travels in cleartext
// alongside these fields; SPT-Txn carries it instead as a payload-level
// zero-knowledge attestation in Extensions.SPTTxn.
type TransferRequest struct {
	Asset Asset `json:"asset"`
	// Amount is a decimal string (never a float) so it canonicalizes
	// byte-exactly across languages and carries no float rounding (TR-4).
	Amount     string     `json:"amount"`
	Callback   string     `json:"callback,omitempty"`
	Extensions Extensions `json:"extensions"`
}

// Extensions is the TRP extension envelope.
type Extensions struct {
	SPTTxn *SPTTxn `json:"spt-txn,omitempty"`
}

// SPTTxn is the SPT-Txn payload-level privacy extension to TRP.
type SPTTxn struct {
	Version     string                 `json:"version"`
	Attestation travelrule.Attestation `json:"attestation"`
	// TxnContextHash is the SPT-Txn payment the attestation is bound to. The
	// beneficiary SHOULD compare this against the on-chain transaction it
	// independently observes rather than trusting it from the request.
	TxnContextHash string   `json:"txn_context_hash"`
	Disclose       []string `json:"disclose"`
}

// TransferResponse is the beneficiary's TRP reply.
type TransferResponse struct {
	Approved *Approval `json:"approved,omitempty"`
	Rejected string    `json:"rejected,omitempty"`
	// Disclosed is the SPT-Txn extension result: the IVMS101 claims the
	// beneficiary was entitled to see (bound claims + requested disclosures).
	Disclosed map[string]any `json:"disclosed,omitempty"`
}

// Approval is the TRP accept body.
type Approval struct {
	Address  string `json:"address,omitempty"`
	Callback string `json:"callback,omitempty"`
}

// ── Travel Address (discovery) ───────────────────────────────────────────────

// EncodeTravelAddress encodes a beneficiary inbound endpoint URL as an opaque,
// URL-safe Travel Address. Standard TRP uses a bech32m `ta` address; this POC
// uses a documented base64url encoding so discovery works without a registry.
func EncodeTravelAddress(endpoint string) string {
	return travelAddressPrefix + base64.RawURLEncoding.EncodeToString([]byte(endpoint))
}

// DecodeTravelAddress recovers the inbound endpoint URL from a Travel Address.
func DecodeTravelAddress(addr string) (string, error) {
	if !strings.HasPrefix(addr, travelAddressPrefix) {
		return "", fmt.Errorf("trp: not a travel address: %q", addr)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(addr, travelAddressPrefix))
	if err != nil {
		return "", fmt.Errorf("trp: bad travel address: %w", err)
	}
	return string(raw), nil
}

// ── originator client ────────────────────────────────────────────────────────

// Client sends outbound TRP transfers (the originator VASP side).
type Client struct {
	HTTP *http.Client
	// AllowInsecureTarget, when true, disables the production target guard that
	// requires https and rejects loopback/private/link-local destinations
	// (TR-2). It exists ONLY so tests can target httptest servers on 127.0.0.1.
	// It MUST stay false in production; the zero value is secure.
	AllowInsecureTarget bool
}

// NewClient returns a TRP client; a nil http.Client gets a 60s-timeout default.
// The target guard is on by default (AllowInsecureTarget is false).
func NewClient(h *http.Client) *Client {
	if h == nil {
		h = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{HTTP: h}
}

// Send initiates a TRP transfer to the beneficiary addressed by travelAddress,
// returning the beneficiary's response and the HTTP status. It sets the
// Api-Version and a fresh Request-Identifier, and verifies the beneficiary
// echoed that identifier as the spec requires.
func (c *Client) Send(ctx context.Context, travelAddress string, req *TransferRequest) (*TransferResponse, int, error) {
	endpoint, err := DecodeTravelAddress(travelAddress)
	if err != nil {
		return nil, 0, err
	}
	if err := c.validateTarget(endpoint); err != nil {
		return nil, 0, err
	}
	if err := ValidAmount(req.Amount); err != nil {
		return nil, 0, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, err
	}
	reqID := newRequestIdentifier()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HeaderAPIVersion, APIVersion)
	httpReq.Header.Set(HeaderRequestIdentifier, reqID)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if echo := resp.Header.Get(HeaderRequestIdentifier); echo != reqID {
		return nil, resp.StatusCode, fmt.Errorf("trp: response request-identifier %q != sent %q", echo, reqID)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	var tr TransferResponse
	if len(data) > 0 {
		if err := json.Unmarshal(data, &tr); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("trp: bad response body: %w", err)
		}
	}
	return &tr, resp.StatusCode, nil
}

// ── beneficiary handler ──────────────────────────────────────────────────────

// VerifyFunc verifies the SPT-Txn attestation in a TRP transfer and returns the
// disclosed IVMS101 claims. (*travelrule.Verifier).Verify satisfies it.
type VerifyFunc func(att *travelrule.Attestation, expectedTxnContextHash string, disclose []string) (map[string]any, error)

// Handler is the beneficiary's inbound TRP endpoint. It validates the TRP
// envelope (method, headers, Api-Version compatibility), then verifies the
// SPT-Txn attestation and replies approved/rejected. This VASP requires the
// payload-level extension: a cleartext-only TRP transfer is rejected.
//
// expectedHash supplies the txn-context hash the beneficiary INDEPENDENTLY
// expects — in production, derived from the on-chain transaction it observes,
// not read back from the request. It MUST be non-nil: a nil expectedHash would
// reduce the payment binding to the request asserting its own hash (a
// self-referential, fail-open check). Handler therefore fails closed when
// expectedHash is nil, rejecting every request with 422 (TR-3).
//
// Replay note (TR-5): seen Request-Identifiers are recorded in an in-process,
// TTL-bounded set and duplicates are rejected with 409. This assumes a single
// service instance; a multi-instance deployment needs a shared store.
func Handler(verify VerifyFunc, expectedHash func(*TransferRequest) string) http.Handler {
	seen := newReplayGuard(10 * time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderAPIVersion, APIVersion)
		reqID := r.Header.Get(HeaderRequestIdentifier)
		if reqID != "" {
			w.Header().Set(HeaderRequestIdentifier, reqID) // echo per spec
		}
		if r.Method != http.MethodPost {
			reject(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if reqID == "" {
			reject(w, http.StatusBadRequest, "missing Request-Identifier header")
			return
		}
		if v := r.Header.Get(HeaderAPIVersion); v != "" && !compatible(v) {
			reject(w, http.StatusBadRequest, "unsupported Api-Version "+v)
			return
		}
		// Fail closed: without an independent transaction-context source the
		// payment binding is meaningless, so refuse to serve at all (TR-3).
		if expectedHash == nil {
			reject(w, http.StatusUnprocessableEntity,
				"server misconfigured: no independent transaction-context source")
			return
		}
		// Inbound replay protection: a Request-Identifier seen recently is a
		// replay (TR-5).
		if !seen.observe(reqID) {
			reject(w, http.StatusConflict, "duplicate Request-Identifier (replay)")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		var req TransferRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reject(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		ext := req.Extensions.SPTTxn
		if ext == nil {
			reject(w, http.StatusUnprocessableEntity,
				"missing spt-txn extension: this VASP requires a payload-level ZK attestation and does not accept cleartext-only TRP transfers")
			return
		}
		if err := ValidAmount(req.Amount); err != nil {
			reject(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		expected := expectedHash(&req)
		disclosed, err := verify(&ext.Attestation, expected, ext.Disclose)
		if err != nil {
			reject(w, http.StatusUnprocessableEntity, "attestation rejected: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, &TransferResponse{Approved: &Approval{}, Disclosed: disclosed})
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// compatible reports whether a peer Api-Version shares our major version.
func compatible(v string) bool {
	maj := func(s string) string { return strings.SplitN(s, ".", 2)[0] }
	return maj(v) == maj(APIVersion)
}

func reject(w http.ResponseWriter, code int, reason string) {
	writeJSON(w, code, &TransferResponse{Rejected: reason})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// validateTarget enforces that an outbound TRP endpoint is safe to dial (TR-2):
// it must be an absolute https URL, and — unless AllowInsecureTarget is set for
// tests — its host must not be a loopback, private, link-local, or unspecified
// address. This blocks a malicious Travel Address from steering the request at
// an internal service (SSRF) or downgrading to plaintext http.
func (c *Client) validateTarget(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("trp: bad target endpoint: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("trp: target endpoint has no host")
	}
	// Tests targeting an httptest server opt out of the https + private-host
	// guards entirely; production keeps the zero value and both apply.
	if c.AllowInsecureTarget {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("trp: target endpoint must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("trp: target endpoint resolves to a forbidden (loopback) host")
	}
	// Resolve and reject any address that is loopback/private/link-local/
	// unspecified. A literal IP resolves to itself.
	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("trp: cannot resolve target host %q: %w", host, err)
	}
	for _, ip := range addrs {
		if forbiddenIP(ip) {
			return fmt.Errorf("trp: target endpoint resolves to a forbidden (loopback/private/link-local) address %s", ip)
		}
	}
	return nil
}

// forbiddenIP reports whether ip is in a range a public inter-VASP target must
// never be: loopback, unspecified, link-local, or RFC1918/ULA private space.
func forbiddenIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return ip.IsPrivate() // 10/8, 172.16/12, 192.168/16, fc00::/7
}

// ValidAmount reports whether a TRP transfer amount is a well-formed, positive
// decimal string (TR-4).
//
// It delegates to ledger.ParseAmount rather than parsing here. This used to call
// big.Rat.SetString directly, which accepts a great deal more than a decimal
// string — "0x2710" as 10000, "1/3", "1e6", "+5", "017" — so this VASP would
// accept an amount that a counterparty applying the ledger grammar reads
// differently or rejects, while the TxnContextHash travelling in the same
// envelope binds an unrelated number. One grammar, one reading, or the wire is
// not interoperable.
func ValidAmount(s string) error {
	if _, err := ledger.ParseAmount(s); err != nil {
		return fmt.Errorf("trp: %w", err)
	}
	return nil
}

// replayGuard is an in-process, TTL-bounded set of seen Request-Identifiers
// (TR-5). It assumes a single service instance; a multi-instance deployment
// would need a shared store. Expired entries are pruned lazily on observe.
type replayGuard struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func newReplayGuard(ttl time.Duration) *replayGuard {
	return &replayGuard{ttl: ttl, seen: make(map[string]time.Time)}
}

// observe records id and returns true if it is new, false if it is a live
// (non-expired) duplicate — i.e. a replay.
func (g *replayGuard) observe(id string) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	// Lazy prune.
	for k, t := range g.seen {
		if now.Sub(t) > g.ttl {
			delete(g.seen, k)
		}
	}
	if t, ok := g.seen[id]; ok && now.Sub(t) <= g.ttl {
		return false
	}
	g.seen[id] = now
	return true
}

// newRequestIdentifier returns a RFC-4122 v4 UUID for the Request-Identifier
// header without pulling in an external dependency.
func newRequestIdentifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
