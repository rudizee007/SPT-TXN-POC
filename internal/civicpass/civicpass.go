// Package civicpass is a real, VERIFYING identity-root adapter for SPT-Txn.
//
// Unlike internal/zkdidmock — which ASSERTS (invents) personhood with a mock
// authority — this adapter CONSUMES a personhood/uniqueness attestation that a
// shipping identity root already issued, and maps it onto the SPT-Txn identity
// seam (internal/identityroot.Provider). It mints no personhood of its own; the
// trust anchor is Civic / the Solana Attestation Service attester, not this code.
//
// Supported roots (same code path, distinguished by Scheme):
//
//   - Civic Pass / Civic Proof of Personhood — an on-chain pass asserting a
//     wallet belongs to one unique, live human (Solana-native).
//   - Solana Attestation Service (SAS) — a wallet-linked, issuer-signed,
//     reusable credential (KYC / uniqueness / eligibility), Solana-native.
//
// What this adapter does, and does NOT do:
//
//   - It VERIFIES an attestation: known Scheme, a TRUSTED attester's signature
//     over the canonical attestation bytes, an allow-listed Claim, and temporal
//     validity. Any failure => no assertion (fail-closed). This is the real
//     security boundary — trust in the Civic gatekeeper network / SAS attester.
//   - It derives a context Nullifier (per-context Sybil detection, cross-context
//     unlinkability for relying parties) and a FRESH Anchor per Resolve, then
//     emits an adapter-signed identityroot.Assertion so downstream verification
//     has the same shape as the mock's.
//   - It does NOT read Solana directly. Real Civic/SAS state lives on-chain (a
//     gateway token / an SAS attestation PDA); a production deployment reads that
//     account and checks pass status against the gatekeeper network, then
//     constructs the Attestation below. That on-chain read slots in behind
//     Present() unchanged — this tree stays offline and unit-testable, verifying
//     the attester signature exactly as the on-chain check would gate trust.
//
// Trust/linkability model (stated honestly): the identity root (Civic/SAS) and
// this adapter CAN link a subject across contexts — they hold the subject
// reference. The nullifier only prevents *relying parties* from correlating the
// same person across their respective contexts. That is precisely Civic's and
// World ID's real model (the provider knows you; the apps do not). The most
// private path — a native, provider-computed per-context nullifier — is
// preferred when the attestation carries one (NativeNullifier), in which case
// this adapter never needs subject linkage at all.
package civicpass

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/identityroot"
	"github.com/rudizee007/spt-txn-poc/internal/zkdid"
)

// Scheme identifiers for the supported shipping roots.
const (
	SchemeCivicPass = "civic-pass"
	SchemeSAS       = "solana-attestation-service"
)

const (
	attestationTag = "spt-txn-civicpass-attestation-v1" // attester signs this domain
	assertionTag   = "spt-txn-civicpass-assertion-v1"   // adapter signs this domain
	nullifierTag   = "spt-txn-civicpass-nullifier-v1"
	anchorTag      = "spt-txn-civicpass-anchor"
	leeway         = 60 * time.Second
)

var (
	// ErrScheme means the attestation Scheme is not a supported identity root.
	ErrScheme = errors.New("civicpass: unsupported scheme")
	// ErrUntrustedAttester means the attester is not in the trusted set.
	ErrUntrustedAttester = errors.New("civicpass: untrusted attester")
	// ErrClaim means the attestation's claim is not allow-listed.
	ErrClaim = errors.New("civicpass: claim not allowed")
	// ErrAttestationSig means the attester signature failed verification.
	ErrAttestationSig = errors.New("civicpass: attestation signature invalid")
	// ErrExpired means the attestation is outside its validity window.
	ErrExpired = errors.New("civicpass: attestation expired or not yet valid")
	// ErrNoAttestation means no verified attestation is held for the subject.
	ErrNoAttestation = errors.New("civicpass: no verified attestation for subject")
	// ErrContext means an empty context label was supplied.
	ErrContext = errors.New("civicpass: context label required")
	// ErrNativeNullifierContext means a native nullifier was presented for a
	// different context than the one being resolved.
	ErrNativeNullifierContext = errors.New("civicpass: native nullifier bound to a different context")
	// ErrProof means an adapter assertion proof failed verification.
	ErrProof = errors.New("civicpass: assertion proof invalid")
	// ErrMalformed means a required attestation field is missing.
	ErrMalformed = errors.New("civicpass: malformed attestation")
)

// Attestation is a verifiable credential issued by a shipping identity root
// (Civic Pass or the Solana Attestation Service) and consumed by SPT-Txn as its
// identity root. In production the fields are read from the on-chain pass /
// attestation account; here they are supplied directly so the seam is offline-
// testable. The attester signature covers every field via canonicalBytes.
type Attestation struct {
	Scheme    string    `json:"scheme"`   // SchemeCivicPass | SchemeSAS
	Attester  string    `json:"attester"` // trusted issuer id (gatekeeper network / SAS credential)
	Subject   string    `json:"subject"`  // stable subject ref (wallet / pass id); NEVER exposed downstream
	Claim     string    `json:"claim"`    // e.g. "proof-of-personhood", "uniqueness", "kyc"
	IssuedAt  time.Time `json:"issued_at"`
	NotBefore time.Time `json:"not_before"` // zero => no lower bound beyond IssuedAt
	ExpiresAt time.Time `json:"expires_at"`

	// NativeNullifier, when non-empty, is a per-context nullifier the identity
	// root computed itself (Civic / World ID do this natively). NullifierContext
	// is the context it is bound to. Preferred over adapter derivation because
	// the adapter then needs no linkage to the subject. Both are covered by the
	// attester signature.
	NativeNullifier  []byte `json:"native_nullifier,omitempty"`
	NullifierContext string `json:"nullifier_context,omitempty"`

	// Signature is the attester's Ed25519 signature over canonicalBytes().
	Signature []byte `json:"signature"`
}

// canonicalBytes is the domain-separated preimage the attester signs. Field
// order and 0x00 separators are fixed so the signature binds every field and a
// value cannot be shifted between fields.
func (a *Attestation) canonicalBytes() []byte {
	var b []byte
	// Every variable-length field is length-prefixed (8-byte big-endian length)
	// so no value — including a NativeNullifier that contains 0x00 — can be
	// shifted across a field boundary and still reproduce the same preimage.
	put := func(p []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		b = append(b, n[:]...)
		b = append(b, p...)
	}
	putS := func(s string) { put([]byte(s)) }
	putI64 := func(v int64) {
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], uint64(v)) // fixed 8-byte width, unambiguous
		b = append(b, t[:]...)
	}
	putS(attestationTag)
	putS(a.Scheme)
	putS(a.Attester)
	putS(a.Subject)
	putS(a.Claim)
	putI64(a.IssuedAt.Unix())
	putI64(a.NotBefore.Unix())
	putI64(a.ExpiresAt.Unix())
	putS(a.NullifierContext)
	put(a.NativeNullifier)
	return b
}

// Sign sets att.Signature to the attester's Ed25519 signature over the canonical
// bytes. This is the ISSUER side (a Civic gatekeeper / SAS attester); in the demo
// and tests a harness standing in for that issuer calls it. A production adapter
// never signs — it only verifies signatures produced on-chain by the real root.
func (a *Attestation) Sign(attesterPriv ed25519.PrivateKey) {
	a.Signature = ed25519.Sign(attesterPriv, a.canonicalBytes())
}

// Verifier consumes verified attestations and implements identityroot.Provider.
// It is the local trust bridge: it verifies the UPSTREAM Civic/SAS attester
// signature, then emits DOWNSTREAM adapter-signed assertions, mirroring the
// mock's structure so both providers verify identically at the seam. Not safe
// for concurrent Present/Resolve; serialize them.
type Verifier struct {
	attesters map[string]ed25519.PublicKey // trusted attester id -> verification key
	claims    map[string]bool              // allow-listed claims
	nullKey   []byte                       // adapter secret keying derived nullifiers
	signPriv  ed25519.PrivateKey           // adapter's downstream assertion key
	signPub   ed25519.PublicKey
	verified  map[string]*Attestation // subjectRef -> last verified attestation
}

// NewVerifier creates a Verifier. nullifierKey keys the derivation of context
// nullifiers (when a native one is not supplied); it MUST be a high-entropy
// secret held only by the adapter/root, and MUST NOT be shared with relying
// parties (sharing it would let them recompute and correlate nullifiers). It
// returns the adapter's public key, which relying parties use in VerifyAssertion.
func NewVerifier(nullifierKey []byte) (*Verifier, ed25519.PublicKey, error) {
	if len(nullifierKey) < 32 {
		return nil, nil, errors.New("civicpass: nullifier key must be >= 32 bytes")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	k := append([]byte(nil), nullifierKey...)
	return &Verifier{
		attesters: map[string]ed25519.PublicKey{},
		claims:    map[string]bool{},
		nullKey:   k,
		signPriv:  priv,
		signPub:   pub,
		verified:  map[string]*Attestation{},
	}, pub, nil
}

// TrustAttester registers a Civic gatekeeper-network / SAS attester public key
// under its identifier. Only attestations signed by a trusted attester verify.
func (v *Verifier) TrustAttester(attesterID string, pub ed25519.PublicKey) error {
	if attesterID == "" || len(pub) != ed25519.PublicKeySize {
		return errors.New("civicpass: attester id and 32-byte key required")
	}
	v.attesters[attesterID] = append(ed25519.PublicKey(nil), pub...)
	return nil
}

// UntrustAttester removes an attester from the trusted set. Because Resolve
// re-checks attester membership, any attestation already Presented under this
// attester immediately stops producing anchors — the operator's revocation lever,
// with no cache to flush.
func (v *Verifier) UntrustAttester(attesterID string) { delete(v.attesters, attesterID) }

// AllowClaim adds a claim value the adapter will accept (e.g.
// "proof-of-personhood", "uniqueness", "kyc"). An attestation whose Claim is not
// allow-listed is rejected — an operator opts in to exactly the assurance level
// its jurisdiction requires.
func (v *Verifier) AllowClaim(claim string) { v.claims[claim] = true }

// AuthorityPublic returns the adapter's downstream assertion verification key.
func (v *Verifier) AuthorityPublic() ed25519.PublicKey { return v.signPub }

// Present verifies an attestation and, on success, stores it for later Resolve.
// This is the fail-closed gate: unknown scheme, untrusted attester, disallowed
// claim, bad signature, or an expired window all reject and store nothing.
func (v *Verifier) Present(att *Attestation) error {
	if att == nil || att.Subject == "" || att.Attester == "" || att.Claim == "" {
		return ErrMalformed
	}
	if att.Scheme != SchemeCivicPass && att.Scheme != SchemeSAS {
		return fmt.Errorf("%w: %q", ErrScheme, att.Scheme)
	}
	pub, ok := v.attesters[att.Attester]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUntrustedAttester, att.Attester)
	}
	if !v.claims[att.Claim] {
		return fmt.Errorf("%w: %q", ErrClaim, att.Claim)
	}
	if len(att.NativeNullifier) != 0 && att.NullifierContext == "" {
		return fmt.Errorf("%w: native nullifier without a context", ErrMalformed)
	}
	// A personhood/uniqueness credential MUST expire: a zero ExpiresAt would make
	// withinValidity skip the upper bound and (with no revocation of cached
	// entries) resolve forever. Require a bounded expiry up front.
	if att.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: attestation must carry a non-zero expiry", ErrMalformed)
	}
	if len(att.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, att.canonicalBytes(), att.Signature) {
		return ErrAttestationSig
	}
	if err := withinValidity(att, time.Now()); err != nil {
		return err
	}
	// Store a copy so a caller mutating att after Present cannot affect state.
	cp := *att
	cp.NativeNullifier = append([]byte(nil), att.NativeNullifier...)
	cp.Signature = append([]byte(nil), att.Signature...)
	v.verified[att.Subject] = &cp
	return nil
}

// Resolve implements identityroot.Provider. It looks up a previously verified
// attestation for subjectRef, re-checks validity at resolve time (an attestation
// can expire after Present), and returns a fresh anchor plus a context nullifier
// in an adapter-signed assertion. Fails closed if no verified attestation is held.
func (v *Verifier) Resolve(_ context.Context, subjectRef, contextLabel string) (*identityroot.Assertion, error) {
	if contextLabel == "" {
		return nil, ErrContext
	}
	att, ok := v.verified[subjectRef]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoAttestation, subjectRef)
	}
	// Re-run the full trust gate at resolve time, not just the temporal check, so
	// that un-trusting a (compromised) attester, removing a claim from the
	// allow-list, or a now-invalid signature immediately stops producing anchors.
	// Present-time caching must not become a revocation bypass.
	pub, ok := v.attesters[att.Attester]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUntrustedAttester, att.Attester)
	}
	if !v.claims[att.Claim] {
		return nil, fmt.Errorf("%w: %q", ErrClaim, att.Claim)
	}
	if len(att.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, att.canonicalBytes(), att.Signature) {
		return nil, ErrAttestationSig
	}
	if err := withinValidity(att, time.Now()); err != nil {
		return nil, err
	}

	// Context nullifier: prefer the identity root's own per-context nullifier
	// (most private — no subject linkage needed here); otherwise derive one keyed
	// by the adapter secret so relying parties cannot correlate across contexts.
	var null [32]byte
	if len(att.NativeNullifier) != 0 {
		if att.NullifierContext != contextLabel {
			return nil, fmt.Errorf("%w: have %q, want %q", ErrNativeNullifierContext, att.NullifierContext, contextLabel)
		}
		null = sha256.Sum256(append([]byte("civicpass-native\x00"), att.NativeNullifier...))
	} else {
		null = v.deriveNullifier(att.Scheme, att.Subject, contextLabel)
	}

	// Fresh anchor per Resolve → tokens unlinkable across issuances. The anchor
	// is a zkDID commitment over the verified subject material, i.e. the exact
	// value SPT-Txn seals as the CAT humanAnchor.
	r, err := zkdid.NewRandomness()
	if err != nil {
		return nil, err
	}
	material := subjectMaterial(att.Scheme, att.Subject)
	anchor := zkdid.Compute(material, r[:])

	iat := time.Now().UTC()
	proof := ed25519.Sign(v.signPriv, assertionMessage(att.Scheme, anchor, null, contextLabel, iat))

	return &identityroot.Assertion{
		Method:    att.Scheme,
		Anchor:    anchor,
		Nullifier: null,
		Context:   contextLabel,
		Proof:     proof,
		IssuedAt:  iat,
	}, nil
}

// VerifyAssertion checks the adapter's downstream signature on an assertion
// produced by a Verifier holding authorityPub. A relying party runs this before
// sealing the anchor. (The UPSTREAM personhood guarantee was verified in
// Present; this confirms the adapter vouched for exactly this anchor, nullifier,
// and context.)
func VerifyAssertion(a *identityroot.Assertion, authorityPub ed25519.PublicKey) error {
	if a == nil || (a.Method != SchemeCivicPass && a.Method != SchemeSAS) {
		return fmt.Errorf("%w: not a civicpass assertion", ErrProof)
	}
	if len(authorityPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad authority key", ErrProof)
	}
	if len(a.Proof) != ed25519.SignatureSize ||
		!ed25519.Verify(authorityPub, assertionMessage(a.Method, a.Anchor, a.Nullifier, a.Context, a.IssuedAt), a.Proof) {
		return ErrProof
	}
	return nil
}

// deriveNullifier = HMAC(nullKey, tag || scheme || 0x00 || subject || 0x00 || context).
// Stable per (subject, context); different across contexts; not recomputable
// without nullKey, so relying parties cannot correlate the same person.
func (v *Verifier) deriveNullifier(scheme, subject, contextLabel string) [32]byte {
	mac := hmac.New(sha256.New, v.nullKey)
	put := func(p []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		mac.Write(n[:])
		mac.Write(p)
	}
	put([]byte(nullifierTag))
	put([]byte(scheme))
	put([]byte(subject))
	put([]byte(contextLabel))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// subjectMaterial derives the personhood material hashed into the anchor from
// the verified subject reference, domain-separated by scheme. The raw subject
// reference never leaves the adapter.
func subjectMaterial(scheme, subject string) []byte {
	h := sha512.Sum512([]byte(anchorTag + ":" + scheme + ":" + subject))
	return h[:]
}

// assertionMessage is the domain-separated preimage the adapter signs, binding
// the scheme, anchor, context nullifier, context, and issuance time so a proof
// cannot be lifted onto a different anchor, context, or nullifier.
func assertionMessage(scheme string, anchor zkdid.Commitment, null [32]byte, contextLabel string, iat time.Time) []byte {
	var b []byte
	put := func(p []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		b = append(b, n[:]...)
		b = append(b, p...)
	}
	put([]byte(assertionTag))
	put([]byte(scheme))
	put(anchor.Bytes())
	put(null[:])
	put([]byte(contextLabel))
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(iat.Unix()))
	b = append(b, t[:]...)
	return b
}

// withinValidity checks IssuedAt/NotBefore/ExpiresAt with bounded leeway.
func withinValidity(att *Attestation, now time.Time) error {
	if !att.ExpiresAt.IsZero() && now.After(att.ExpiresAt.Add(leeway)) {
		return ErrExpired
	}
	lower := att.IssuedAt
	if !att.NotBefore.IsZero() && att.NotBefore.After(lower) {
		lower = att.NotBefore
	}
	if !lower.IsZero() && now.Add(leeway).Before(lower) {
		return ErrExpired
	}
	return nil
}
