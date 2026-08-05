// Package suite implements SPT-Txn crypto-agility: algorithm suites as a
// first-class, signed property of every envelope. Spec:
// docs/spec/CRYPTO-AGILITY.md. Threat model: docs/THREAT-MODEL.md §4.3.
//
// The suite identifier is INSIDE the signed bytes — a downgrade requires
// forging the very signature it is trying to weaken. Unknown suites are
// rejected by allowlist. An implemented-but-unavailable suite (hybrid PQC on
// a build without the backend) fails closed with ErrSuiteUnavailable, which
// callers map to decision class `unavailable` — never silent fallback.
//
// Verification modes are verifier CONFIGURATION, never inferred from the
// token: ModeVerifyEither for migration windows, ModeVerifyBoth for strict
// (CNSA 2.0) posture. Jurisdiction floors are checked before signature
// dispatch, so a valid classical signature cannot argue its way past a
// profile that demands hybrid.
//
// No custom cryptography: Ed25519 from the standard library; ML-DSA-65 from
// an audited pure-Go implementation behind the `mldsa` build tag (until
// crypto/mldsa lands in the Go standard library).
package suite

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

// Registered suite identifiers.
const (
	SuiteEdDSA  = "EdDSA"                  // Ed25519, current default
	SuiteHybrid = "HYBRID-Ed25519-MLDSA65" // Ed25519 AND ML-DSA-65 (FIPS 204)
)

// signingTag domain-separates envelope signatures system-wide.
const signingTag = "spt-txn-env-v1"

// Mode selects hybrid acceptance semantics. The zero value is invalid so a
// forgotten configuration cannot silently mean "either".
type Mode int

const (
	// ModeVerifyEither (transition): a hybrid envelope is valid if either
	// constituent signature verifies. Both signatures must still be PRESENT.
	ModeVerifyEither Mode = iota + 1
	// ModeVerifyBoth (strict): every constituent signature must verify.
	ModeVerifyBoth
)

var (
	ErrUnknownSuite     = errors.New("suite: unknown or unregistered suite (allowlist)")
	ErrSuiteUnavailable = errors.New("suite: suite not available in this build")
	ErrBelowFloor       = errors.New("suite: suite below the jurisdiction profile floor")
	ErrBadEnvelope      = errors.New("suite: malformed envelope")
	ErrVerify           = errors.New("suite: signature verification failed")
	ErrBadMode          = errors.New("suite: verification mode not configured")
)

// Envelope is a suite-tagged signed message. The outer Suite field exists
// for dispatch only; verification reconstructs the signing input from it, so
// any disagreement with what the signer committed to invalidates the
// signatures. Sigs order is defined per suite (hybrid: [Ed25519, ML-DSA-65]).
type Envelope struct {
	Suite   string   `json:"suite"`
	Payload []byte   `json:"payload"`
	Sigs    [][]byte `json:"sigs"`
}

// PrivateKeySet carries signing material. A suite uses the members it needs
// and errors if a required member is absent.
type PrivateKeySet struct {
	Ed25519 ed25519.PrivateKey
	// PQ is the post-quantum signer (ML-DSA-65). Typed as crypto.Signer so
	// builds without the backend still compile; the hybrid suite checks the
	// concrete type.
	PQ crypto.Signer
}

// PublicKeySet mirrors PrivateKeySet for verification.
type PublicKeySet struct {
	Ed25519 ed25519.PublicKey
	PQ      crypto.PublicKey
}

// Impl is a registered signature suite.
type Impl interface {
	ID() string
	Sign(keys PrivateKeySet, signingInput []byte) ([][]byte, error)
	Verify(keys PublicKeySet, signingInput []byte, sigs [][]byte, mode Mode) error
}

var (
	regMu    sync.RWMutex
	registry = map[string]Impl{}
)

// Register adds a suite implementation. Later registrations for the same ID
// replace earlier ones — the mldsa build tag uses this to upgrade the hybrid
// stub to the real backend at init time.
func Register(impl Impl) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[impl.ID()] = impl
}

func lookup(id string) (Impl, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	impl, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownSuite, id)
	}
	return impl, nil
}

// SigningInput builds the bytes that are signed:
// tag || 0x00 || suite || 0x00 || payload. The suite identifier is covered.
func SigningInput(suiteID string, payload []byte) []byte {
	out := make([]byte, 0, len(signingTag)+2+len(suiteID)+len(payload))
	out = append(out, signingTag...)
	out = append(out, 0x00)
	out = append(out, suiteID...)
	out = append(out, 0x00)
	out = append(out, payload...)
	return out
}

// Seal signs payload under the given suite.
func Seal(suiteID string, payload []byte, keys PrivateKeySet) (*Envelope, error) {
	impl, err := lookup(suiteID)
	if err != nil {
		return nil, err
	}
	sigs, err := impl.Sign(keys, SigningInput(suiteID, payload))
	if err != nil {
		return nil, err
	}
	return &Envelope{Suite: suiteID, Payload: payload, Sigs: sigs}, nil
}

// Floors pins minimum suites per jurisdiction profile. Nil means "no floor
// policy configured" (all registered suites acceptable). A NON-nil Floors is
// strict: an unknown profile or an unlisted suite is below the floor — fail
// closed, no default profile fallback.
type Floors map[string][]string

// Check reports nil when suiteID satisfies the floor for profile.
func (f Floors) Check(profile, suiteID string) error {
	if f == nil {
		return nil
	}
	allowed, ok := f[profile]
	if !ok {
		return fmt.Errorf("%w: unknown jurisdiction profile %q", ErrBelowFloor, profile)
	}
	for _, s := range allowed {
		if s == suiteID {
			return nil
		}
	}
	return fmt.Errorf("%w: profile %q does not accept suite %q", ErrBelowFloor, profile, suiteID)
}

// Verify checks an envelope: allowlisted suite, jurisdiction floor (BEFORE
// any signature work — a valid signature under a banned suite is still a
// violation), then suite-specific signature verification under the
// configured mode.
func Verify(env *Envelope, keys PublicKeySet, mode Mode, floors Floors, profile string) error {
	if env == nil || env.Suite == "" || len(env.Sigs) == 0 {
		return ErrBadEnvelope
	}
	if mode != ModeVerifyEither && mode != ModeVerifyBoth {
		return ErrBadMode
	}
	if err := floors.Check(profile, env.Suite); err != nil {
		return err
	}
	impl, err := lookup(env.Suite)
	if err != nil {
		return err
	}
	return impl.Verify(keys, SigningInput(env.Suite, env.Payload), env.Sigs, mode)
}

// ── Ed25519 suite (standard library) ────────────────────────────────────

type edSuite struct{}

func (edSuite) ID() string { return SuiteEdDSA }

func (edSuite) Sign(keys PrivateKeySet, input []byte) ([][]byte, error) {
	if len(keys.Ed25519) != ed25519.PrivateKeySize {
		return nil, errors.New("suite: EdDSA: missing or malformed Ed25519 private key")
	}
	return [][]byte{ed25519.Sign(keys.Ed25519, input)}, nil
}

func (edSuite) Verify(keys PublicKeySet, input []byte, sigs [][]byte, _ Mode) error {
	if len(sigs) != 1 {
		return fmt.Errorf("%w: EdDSA expects exactly 1 signature, got %d", ErrBadEnvelope, len(sigs))
	}
	if len(keys.Ed25519) != ed25519.PublicKeySize {
		return errors.New("suite: EdDSA: missing or malformed Ed25519 public key")
	}
	if len(sigs[0]) != ed25519.SignatureSize || !ed25519.Verify(keys.Ed25519, input, sigs[0]) {
		return ErrVerify
	}
	return nil
}

func init() { Register(edSuite{}) }
