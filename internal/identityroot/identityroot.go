// Package identityroot defines the SPT-Txn identity-root seam.
//
// SPT-Txn does not itself establish that a delegating principal is a genuine,
// unique human — it consumes that assertion from an identity/personhood root and
// carries it, as the humanAnchor, unchanged through every downstream capability
// and transaction token. This package is the single interface that root fills.
//
// An identity root supplies three things, in a fixed shape, per (subject,
// context):
//
//   - a fresh human Anchor (a zkDID commitment) that the issuer seals as the CAT
//     humanAnchor (cattoken.IssueRequest.IdentityAnchor);
//   - a context-specific Nullifier — stable per (subject, context) for
//     per-context Sybil detection, unlinkable across contexts so relying parties
//     cannot correlate the same person;
//   - a Proof that a trusted root vouched for the above.
//
// Two providers implement Provider:
//
//   - internal/zkdidmock — a clearly-labelled MOCK that ASSERTS personhood with a
//     mock authority signature (stands in for Toby Bolton's .zkdid™ initiative,
//     https://zkd.id, which is a proposed integration, not implemented here).
//   - internal/civicpass — a real, VERIFYING adapter over a shipping identity
//     root: Civic Pass / the Solana Attestation Service. It mints no personhood;
//     it verifies an externally-issued attestation and maps it onto this seam.
//
// Issuance code depends only on this interface, so the identity root can be
// swapped — mock for Civic/SAS for a future .zkdid — without changing cattoken
// issuance. That decoupling is the point: SPT-Txn is not blocked on any one
// identity provider's timeline.
package identityroot

import (
	"context"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
)

// Assertion is what an identity root returns for a subject acting in a context.
// It carries NO subject identifier — only the anchor, the context nullifier, a
// context label, and a proof — so it is privacy-preserving by shape. The Proof's
// meaning is provider-specific (a mock authority signature; an adapter signature
// over a verified Civic/SAS attestation); each provider ships its own verifier.
type Assertion struct {
	Method    string           `json:"method"`    // provider tag, e.g. "zkdid-mock" or "civic-pass"
	Anchor    zkdid.Commitment `json:"anchor"`    // fresh per issuance; sealed as the CAT humanAnchor
	Nullifier [32]byte         `json:"nullifier"` // context-specific; stable per (subject, context)
	Context   string           `json:"context"`
	Proof     []byte           `json:"proof"` // root/adapter proof that personhood was vouched for
	IssuedAt  time.Time        `json:"issued_at"`
}

// Provider is the integration seam an identity/personhood root fills. Every
// provider — mock or real — implements exactly this, so SPT-Txn issuance code
// never changes when one root is swapped for another.
type Provider interface {
	// Resolve returns, for subjectRef acting in contextLabel, a fresh
	// personhood-backed anchor plus the context-specific nullifier, or fails
	// closed if the subject cannot be vouched for.
	Resolve(ctx context.Context, subjectRef, contextLabel string) (*Assertion, error)
}
