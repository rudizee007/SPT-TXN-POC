// Package disclosure is the SPT-Txn scoped-disclosure SDK: a small
// request → consent → response protocol for time-limited, scope-selected
// selective disclosure over an SD-JWT credential.
//
// A requester (a counterparty, auditor, or institution) issues a Request naming
// exactly the fields it needs, why (purpose), and for how long (expiry). The
// holder decides — via a Grant — which of those fields to release; Respond
// discloses only the intersection (requested ∩ consented), so the holder never
// over-shares and the requester never receives more than it asked for. Verify
// binds the response to the request, enforces the time window, authenticates the
// SD-JWT, and guarantees no out-of-scope field was disclosed.
//
// This is the selective-disclosure half of the SPT-Txn "auditable privacy"
// primitive (the ESP ZK wishlist item). Predicates that must be proven while the
// value stays fully hidden — amount-over-threshold, VASP membership, identity
// commitment — are carried as zero-knowledge proofs via internal/zkproof and
// internal/travelrule; Request.Predicates names them so a response can attach
// them out of band. The schema is language-agnostic (see docs/DISCLOSURE-SCHEMA.md);
// this is the Go reference implementation.
//
// Holder-binding/replay: like the underlying SD-JWT, a Response is only safe
// inside a holder-/transaction-bound outer envelope (the SPT-Txn token). The
// Request ID acts as a per-exchange nonce and the expiry bounds the window; full
// key-binding is provided by the outer token, not here.
package disclosure

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/sdjwt"
)

// Request is what a requester asks a holder to disclose.
type Request struct {
	ID         string   `json:"id"`                   // unique per-exchange id / nonce
	Audience   string   `json:"audience,omitempty"`   // who is asking (requester identifier)
	Purpose    string   `json:"purpose,omitempty"`    // human-readable reason (consent context)
	Fields     []string `json:"fields"`               // requested disclosable claim names
	Predicates []string `json:"predicates,omitempty"` // optional ZK predicates to also prove (e.g. "amount_over_threshold")
	ExpiresAt  int64    `json:"expires_at"`           // unix seconds; request invalid at/after this
}

// Grant is the holder's consent decision: the subset of the request's fields the
// holder is willing to release. Fields not listed are withheld.
type Grant struct {
	Allow []string `json:"allow"`
}

// Response is the holder's scoped disclosure for a Request.
type Response struct {
	RequestID    string   `json:"request_id"`
	Presentation string   `json:"presentation"` // SD-JWT presentation carrying only the granted fields
	Disclosed    []string `json:"disclosed"`    // field names actually released
	IssuedAt     int64    `json:"issued_at"`
}

// NewRequest builds a Request with a fresh random id and an expiry ttl from now.
func NewRequest(audience, purpose string, fields []string, ttl time.Duration) (Request, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Request{}, err
	}
	return Request{
		ID:        hex.EncodeToString(b[:]),
		Audience:  audience,
		Purpose:   purpose,
		Fields:    fields,
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}, nil
}

// Respond is the holder's side. It discloses only the fields that are BOTH
// requested AND consented to (req.Fields ∩ grant.Allow) — enforcing scope
// selection and consent — and refuses an expired request. credential is the
// holder's SD-JWT (combined serialization from sdjwt.Issue).
func Respond(req Request, credential string, grant Grant, now time.Time) (Response, error) {
	if req.ExpiresAt != 0 && now.Unix() >= req.ExpiresAt {
		return Response{}, fmt.Errorf("disclosure request %q has expired", req.ID)
	}
	allow := toSet(grant.Allow)
	disclosed := make([]string, 0, len(req.Fields))
	for _, f := range req.Fields {
		if allow[f] {
			disclosed = append(disclosed, f)
		}
	}
	pres, err := sdjwt.Present(credential, disclosed)
	if err != nil {
		return Response{}, fmt.Errorf("build presentation: %w", err)
	}
	return Response{
		RequestID:    req.ID,
		Presentation: pres,
		Disclosed:    disclosed,
		IssuedAt:     now.Unix(),
	}, nil
}

// Verify is the requester's side. It binds the response to the request, enforces
// the time window, authenticates the SD-JWT against the issuer key, and rejects
// any field the holder disclosed that was not requested (scope enforcement). It
// returns the disclosed claims and the requested fields the holder withheld.
//
// The credential must carry its scoped data as DISCLOSABLE claims (sdjwt.Issue);
// any returned claim outside req.Fields is treated as a scope violation.
func Verify(req Request, resp Response, issuerPub ed25519.PublicKey, now time.Time) (disclosed map[string]any, withheld []string, err error) {
	if resp.RequestID != req.ID {
		return nil, nil, fmt.Errorf("response references request %q, expected %q", resp.RequestID, req.ID)
	}
	if req.ExpiresAt != 0 && now.Unix() >= req.ExpiresAt {
		return nil, nil, fmt.Errorf("disclosure request %q has expired", req.ID)
	}
	claims, err := sdjwt.Verify(resp.Presentation, issuerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("verify presentation: %w", err)
	}
	reqSet := toSet(req.Fields)
	for name := range claims {
		if !reqSet[name] {
			return nil, nil, fmt.Errorf("holder disclosed unrequested field %q (scope violation)", name)
		}
	}
	for _, f := range req.Fields {
		if _, ok := claims[f]; !ok {
			withheld = append(withheld, f)
		}
	}
	return claims, withheld, nil
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
