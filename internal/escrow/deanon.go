package escrow

// deanon.go — the deanonymization request flow (Section 9.6.5). Opening an
// escrow envelope requires a request that is (a) signed by a key authorized for
// the escrow-request role and (b) accompanied by a stated lawful basis. Only
// then does the handler decrypt the envelope and return the recovered identity.
// This keeps anonymity accountable: pseudonymous by default, recoverable only
// under due process.
//
// The lawful-basis check here is a structural stub (non-empty reference); a real
// deployment would validate the basis against an external authority and likely
// require a threshold of escrow-request signers.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultRequestMaxAge bounds how long a signed deanonymization request remains
// actionable, limiting the replay window (review M3).
const DefaultRequestMaxAge = 5 * time.Minute

var (
	// ErrUnauthorized indicates the requester is not an authorized escrow-
	// request signer.
	ErrUnauthorized = errors.New("escrow: requester not authorized")
	// ErrBadSignature indicates the request signature did not verify.
	ErrBadSignature = errors.New("escrow: request signature invalid")
	// ErrNoLawfulBasis indicates the request stated no lawful basis.
	ErrNoLawfulBasis = errors.New("escrow: no lawful basis stated")
	// ErrStaleRequest indicates the request is outside the freshness window.
	ErrStaleRequest = errors.New("escrow: request expired or timestamp invalid")
	// ErrReplay indicates the request was already processed.
	ErrReplay = errors.New("escrow: request already processed (replay)")
)

// Request is a deanonymization request for a single humanAnchor.
type Request struct {
	HumanAnchor string // the envelope to open
	Requester   string // identifier of the requesting authority
	LawfulBasis string // e.g. a court-order / warrant reference
	IssuedAt    int64
	Sig         []byte // Ed25519 over signingBytes()
}

func (r *Request) signingBytes() []byte {
	return []byte(fmt.Sprintf("spt-txn-deanon-v1|%s|%s|%s|%d",
		r.HumanAnchor, r.Requester, r.LawfulBasis, r.IssuedAt))
}

// Sign fills in the request signature with an escrow-request key.
func (r *Request) Sign(key ed25519.PrivateKey) {
	r.Sig = ed25519.Sign(key, r.signingBytes())
}

// Handler authorizes and executes deanonymization requests against a vault. It
// holds the escrow private key — in production a separate, hardened service
// (ideally a FROST threshold group) — and the set of authorized escrow-request
// signers, which in production come from the Trust Registry's escrow_req role.
type Handler struct {
	vault      *Vault
	escrowPriv *Key
	signers    map[string]ed25519.PublicKey
	maxAge     time.Duration

	mu   sync.Mutex
	seen map[string]time.Time // request fingerprint -> expiry (replay guard)
}

// NewHandler creates a deanonymization handler over a vault and the hybrid
// escrow key.
func NewHandler(vault *Vault, escrowPriv *Key) *Handler {
	return &Handler{
		vault:      vault,
		escrowPriv: escrowPriv,
		signers:    make(map[string]ed25519.PublicKey),
		maxAge:     DefaultRequestMaxAge,
		seen:       make(map[string]time.Time),
	}
}

// AddSigner authorizes an escrow-request signer.
func (h *Handler) AddSigner(requester string, pub ed25519.PublicKey) {
	h.signers[requester] = pub
}

// Deanonymize verifies authorization, signature, and lawful basis, then opens
// the envelope and returns the recovered identity material. Each guard maps to
// a distinct error so callers and audit logs can record exactly why a request
// was refused.
func (h *Handler) Deanonymize(r *Request) ([]byte, error) {
	pub, ok := h.signers[r.Requester]
	if !ok {
		return nil, ErrUnauthorized
	}
	if r.Sig == nil || !ed25519.Verify(pub, r.signingBytes(), r.Sig) {
		return nil, ErrBadSignature
	}
	if r.LawfulBasis == "" {
		return nil, ErrNoLawfulBasis
	}
	// Freshness + replay guard (review M3): IssuedAt is signed, so enforce it is
	// recent and reject a request fingerprint already seen within the window.
	now := time.Now()
	age := now.Sub(time.Unix(r.IssuedAt, 0))
	if age < -1*time.Minute || age > h.maxAge {
		return nil, ErrStaleRequest
	}
	fp := fingerprint(r)
	h.mu.Lock()
	for k, exp := range h.seen {
		if now.After(exp) {
			delete(h.seen, k)
		}
	}
	if exp, ok := h.seen[fp]; ok && now.Before(exp) {
		h.mu.Unlock()
		return nil, ErrReplay
	}
	h.seen[fp] = now.Add(h.maxAge)
	h.mu.Unlock()

	env, err := h.vault.Get(r.HumanAnchor)
	if err != nil {
		return nil, err
	}
	return env.Open(h.escrowPriv)
}

// fingerprint uniquely identifies a signed request (by its signature) for the
// replay guard.
func fingerprint(r *Request) string {
	sum := sha256.Sum256(r.Sig)
	return hex.EncodeToString(sum[:])
}
