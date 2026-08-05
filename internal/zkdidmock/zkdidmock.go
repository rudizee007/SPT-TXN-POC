// Package zkdidmock is a MOCK .zkdid™ adapter.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ THIS IS NOT THE .zkdid™ PROTOCOL. NOT PRODUCTION. NOT ENDORSED.           │
// │ It SIMULATES the personhood/uniqueness/root that Toby Bolton's .zkdid™    │
// │ initiative (https://zkd.id) is designed to provide, so that SPT-Txn's     │
// │ issuance seam can be exercised against the SHAPE of a real .zkdid provider │
// │ instead of a bare deterministic test principal. It proves NOTHING          │
// │ cryptographically about personhood or global uniqueness — it ASSERTS them  │
// │ with a trusted mock authority signature, which is exactly the centralised  │
// │ trust the real .zkdid protocol removes. Replace this with the real         │
// │ protocol, governance, and security model before any production claim.      │
// └──────────────────────────────────────────────────────────────────────────┘
//
// What it models (the properties that matter for the SPT-Txn integration):
//
//   - Personhood assertion: "this anchor belongs to one genuine, unique human."
//     Mocked as a mock-authority Ed25519 signature. Real .zkdid: a zero-knowledge
//     proof over a biometric-committed personhood + decentralised-root membership,
//     with no trusted authority.
//   - Context-specific nullifier: a value that is STABLE per (subject, context)
//     — so a service can detect the same human enrolling twice in ITS context
//     (Sybil resistance) — yet UNLINKABLE across contexts, so two services cannot
//     correlate the same person. Modelled exactly (HMAC of a per-subject secret).
//   - Fresh human anchor per issuance: the anchor sealed into each SPT-Txn CAT is
//     freshly randomised, so tokens are unlinkable across issuances even for the
//     same human — the property SPT-Txn already requires of its humanAnchor.
//
// The seam: SPT-Txn's issuer calls Provider.Resolve, seals the returned Anchor as
// the CAT humanAnchor (cattoken.IssueRequest.IdentityAnchor), and a policy layer
// MAY enforce the Nullifier for per-context Sybil resistance. The seam itself
// lives in internal/identityroot; the real .zkdid — and the real, verifying
// Civic/SAS adapter in internal/civicpass — implement the same Provider interface.
package zkdidmock

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/identityroot"
	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
)

// Assertion and Provider are the shared identity-root seam (internal/
// identityroot). Aliased here so existing callers keep using zkdidmock.Assertion
// / zkdidmock.Provider while the real civicpass adapter implements the same
// interface and returns the same Assertion shape.
type (
	// Assertion is the identity-root assertion shape (see identityroot.Assertion).
	Assertion = identityroot.Assertion
	// Provider is the identity-root seam (see identityroot.Provider).
	Provider = identityroot.Provider
)

// Method labels an assertion's origin. Deliberately names itself a mock so a
// downstream verifier or auditor can never mistake it for the real protocol.
const Method = "zkdid-mock"

const (
	nullifierTag = "zkdid-mock-nullifier-v1"
	proofTag     = "zkdid-mock-personhood-v1"
)

var (
	// ErrNotEnrolled means the subject has not been enrolled as a unique human.
	ErrNotEnrolled = errors.New("zkdidmock: subject not enrolled")
	// ErrContext means an empty context label was supplied.
	ErrContext = errors.New("zkdidmock: context label required")
	// ErrProof means the personhood proof failed verification.
	ErrProof = errors.New("zkdidmock: personhood proof invalid")
)

// MockProvider is a stand-in .zkdid root. It holds a per-subject personhood
// secret (a real .zkdid derives this from a unique biometric it proves in zero
// knowledge; the mock simply remembers enrolled subjects) and an authority
// signing key (a real .zkdid replaces this with a decentralised, capture-
// resistant root). Not safe for concurrent Enroll/Resolve; serialize them.
type MockProvider struct {
	authorityPriv ed25519.PrivateKey
	authorityPub  ed25519.PublicKey
	secrets       map[string][]byte // subjectRef -> personhood secret
}

// NewMockProvider creates a mock provider and returns it together with the mock
// authority's public key (the key a relying party uses to verify personhood
// proofs — the centralised trust the real protocol removes).
func NewMockProvider() (*MockProvider, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &MockProvider{authorityPriv: priv, authorityPub: pub, secrets: map[string][]byte{}}, pub, nil
}

// AuthorityPublic returns the mock authority's verification key.
func (m *MockProvider) AuthorityPublic() ed25519.PublicKey { return m.authorityPub }

// Enroll registers subjectRef as one unique human under the mock root, assigning
// a stable personhood secret. It is idempotent: enrolling the same subjectRef
// twice keeps the same secret (the mock's model of "one human, one identity").
// A real .zkdid enforces this via biometric deduplication; the mock does NOT —
// distinct subjectRefs are simply assumed to be distinct humans.
func (m *MockProvider) Enroll(subjectRef string) error {
	if subjectRef == "" {
		return errors.New("zkdidmock: subjectRef required")
	}
	if _, ok := m.secrets[subjectRef]; ok {
		return nil
	}
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		return err
	}
	m.secrets[subjectRef] = s
	return nil
}

// Resolve implements Provider.
func (m *MockProvider) Resolve(_ context.Context, subjectRef, contextLabel string) (*Assertion, error) {
	secret, ok := m.secrets[subjectRef]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotEnrolled, subjectRef)
	}
	if contextLabel == "" {
		return nil, ErrContext
	}

	// Context-specific nullifier: HMAC(secret, tag||context). Stable per
	// (subject, context) → duplicate enrolment in one context is detectable;
	// different across contexts → services cannot correlate the same human.
	null := nullifier(secret, contextLabel)

	// Fresh anchor per issuance → tokens unlinkable across issuances. The anchor
	// is a zkDID commitment over the subject's personhood material, so it is the
	// exact value SPT-Txn seals and a real .zkdid would prove knowledge of.
	r, err := zkdid.NewRandomness()
	if err != nil {
		return nil, err
	}
	anchor := zkdid.Compute(secret, r[:])

	iat := time.Now().UTC()
	proof := ed25519.Sign(m.authorityPriv, personhoodMessage(anchor, null, contextLabel, iat))

	return &Assertion{
		Method:    Method,
		Anchor:    anchor,
		Nullifier: null,
		Context:   contextLabel,
		Proof:     proof,
		IssuedAt:  iat,
	}, nil
}

// VerifyAssertion checks the mock personhood proof against the mock authority
// key. A relying party runs this before trusting that an anchor belongs to one
// unique human in the given context. (In the real protocol this verification is
// a zero-knowledge proof check, not a trusted-authority signature check.)
func VerifyAssertion(a *Assertion, authorityPub ed25519.PublicKey) error {
	if a == nil || a.Method != Method {
		return fmt.Errorf("%w: not a %s assertion", ErrProof, Method)
	}
	if len(authorityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad authority key", ErrProof)
	}
	if len(a.Proof) != ed25519.SignatureSize ||
		!ed25519.Verify(authorityPub, personhoodMessage(a.Anchor, a.Nullifier, a.Context, a.IssuedAt), a.Proof) {
		return ErrProof
	}
	return nil
}

// nullifier = HMAC-SHA256(secret, tag || 0x00 || context).
func nullifier(secret []byte, contextLabel string) [32]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(nullifierTag))
	mac.Write([]byte{0x00})
	mac.Write([]byte(contextLabel))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// personhoodMessage is the domain-separated preimage the mock authority signs:
// it binds the anchor, the context nullifier, the context, and the issuance time,
// so a proof cannot be lifted onto a different anchor, context, or nullifier.
func personhoodMessage(anchor zkdid.Commitment, null [32]byte, contextLabel string, iat time.Time) []byte {
	var b []byte
	// Length-prefix every variable-length field so a contextLabel containing 0x00
	// cannot be shifted across the field boundary into the trailing timestamp.
	put := func(p []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		b = append(b, n[:]...)
		b = append(b, p...)
	}
	put([]byte(proofTag))
	put(anchor.Bytes())
	put(null[:])
	put([]byte(contextLabel))
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(iat.Unix()))
	b = append(b, t[:]...)
	return b
}
