package suite

// hybrid.go — the dual-signature envelope suites and the pure ML-DSA suite.
// The classical half and all agility plumbing (signature counting, mode
// semantics, envelope shape) are always compiled and tested; only the
// post-quantum primitive itself is swapped by build tag:
//
//	go build            → mldsa_stub.go: PQ operations fail closed
//	go build -tags mldsa → mldsa_backend.go: filippo.io/mldsa
//
// Sigs order for a hybrid is fixed: [0] Ed25519, [1] ML-DSA. Both signatures
// are always PRESENT in a hybrid envelope; the verification Mode only governs
// acceptance, never shape.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// pqParamSet selects an ML-DSA parameter set without naming the library, so the
// selection is expressible in builds that do not compile the backend.
type pqParamSet int

const (
	pqMLDSA65 pqParamSet = iota + 1
	pqMLDSA87
)

func (p pqParamSet) String() string {
	switch p {
	case pqMLDSA65:
		return "ML-DSA-65"
	case pqMLDSA87:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}

// checkMode validates the caller's verification mode.
//
// Called BEFORE the availability check, deliberately. Mode is a caller-side
// configuration fact and availability is a build fact; if availability is tested
// first, a build without the PQ backend reports ErrSuiteUnavailable for a call
// that was ALSO missing its mode, and the caller fixes the build tag without
// ever learning their mode was unset. Mode's zero value is invalid precisely so
// that a forgotten configuration cannot silently mean anything — that invariant
// should not depend on which build is running.
func checkMode(m Mode) error {
	switch m {
	case ModeVerifyEither, ModeVerifyBoth:
		return nil
	default:
		return ErrBadMode
	}
}

// pqBackend is the tag-selected ML-DSA implementation, bound to one parameter
// set and one domain-separation context.
type pqBackend interface {
	// Available reports whether real PQ operations exist in this build.
	Available() bool
	Sign(signer any, input []byte) ([]byte, error)
	Verify(pub any, input []byte, sig []byte) error
}

// ── hybrid: Ed25519 + ML-DSA, both signatures present ───────────────────────

type hybridSuite struct {
	id string
	pq pqBackend
}

func (h hybridSuite) ID() string { return h.id }

func (h hybridSuite) Sign(keys PrivateKeySet, input []byte) ([][]byte, error) {
	if !h.pq.Available() {
		return nil, fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, h.id)
	}
	if len(keys.Ed25519) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("suite: %s: missing or malformed Ed25519 private key", h.id)
	}
	if keys.PQ == nil {
		return nil, fmt.Errorf("suite: %s: missing ML-DSA private key", h.id)
	}
	edSig := ed25519.Sign(keys.Ed25519, input)
	pqSig, err := h.pq.Sign(keys.PQ, input)
	if err != nil {
		return nil, fmt.Errorf("suite: %s: ML-DSA sign: %w", h.id, err)
	}
	return [][]byte{edSig, pqSig}, nil
}

func (h hybridSuite) Verify(keys PublicKeySet, input []byte, sigs [][]byte, mode Mode) error {
	// Shape first: a hybrid envelope ALWAYS carries both signatures. An
	// envelope missing one is malformed regardless of mode — otherwise
	// "either" mode would let an attacker simply omit the half they cannot
	// forge, which is a downgrade by subtraction.
	if len(sigs) != 2 {
		return fmt.Errorf("%w: %s expects exactly 2 signatures, got %d", ErrBadEnvelope, h.id, len(sigs))
	}
	if len(sigs[0]) == 0 || len(sigs[1]) == 0 {
		return fmt.Errorf("%w: %s signature missing", ErrBadEnvelope, h.id)
	}
	if err := checkMode(mode); err != nil {
		return err
	}
	if !h.pq.Available() {
		return fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, h.id)
	}

	classicalOK := len(keys.Ed25519) == ed25519.PublicKeySize &&
		len(sigs[0]) == ed25519.SignatureSize &&
		ed25519.Verify(keys.Ed25519, input, sigs[0])
	pqErr := h.pq.Verify(keys.PQ, input, sigs[1])

	switch mode {
	case ModeVerifyBoth:
		if !classicalOK || pqErr != nil {
			return ErrVerify
		}
		return nil
	case ModeVerifyEither:
		if classicalOK || pqErr == nil {
			return nil
		}
		return ErrVerify
	default:
		return ErrBadMode
	}
}

// ── pure ML-DSA: the CNSA 2.0 end state ─────────────────────────────────────

// mldsaSuite carries a single ML-DSA signature and no classical component.
//
// CNSA 2.0 contains no classical signature algorithm, so an NSS deployment
// eventually runs this rather than a hybrid. A registry offering only classical
// and hybrid cannot express where the standard lands, which is why this exists
// before anyone has asked for it.
type mldsaSuite struct {
	id string
	pq pqBackend
}

func (m mldsaSuite) ID() string { return m.id }

func (m mldsaSuite) Sign(keys PrivateKeySet, input []byte) ([][]byte, error) {
	if !m.pq.Available() {
		return nil, fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, m.id)
	}
	if keys.PQ == nil {
		return nil, fmt.Errorf("suite: %s: missing ML-DSA private key", m.id)
	}
	// An Ed25519 key MAY be present in the key set — a deployment mid-migration
	// holds both. It is deliberately NOT signed with: this suite asserts a
	// single post-quantum signature, and quietly adding a classical one would
	// make the envelope shape depend on what happened to be in the key set.
	sig, err := m.pq.Sign(keys.PQ, input)
	if err != nil {
		return nil, fmt.Errorf("suite: %s: ML-DSA sign: %w", m.id, err)
	}
	return [][]byte{sig}, nil
}

func (m mldsaSuite) Verify(keys PublicKeySet, input []byte, sigs [][]byte, mode Mode) error {
	if len(sigs) != 1 {
		return fmt.Errorf("%w: %s expects exactly 1 signature, got %d", ErrBadEnvelope, m.id, len(sigs))
	}
	if len(sigs[0]) == 0 {
		return fmt.Errorf("%w: %s signature missing", ErrBadEnvelope, m.id)
	}
	// Mode has no meaning for a single-signature suite — "either" and "both"
	// describe the same check. The ZERO VALUE is still rejected: a forgotten
	// configuration must not silently mean anything, and that invariant should
	// not weaken just because this particular suite would not have been affected
	// by the choice.
	if err := checkMode(mode); err != nil {
		return err
	}
	if !m.pq.Available() {
		return fmt.Errorf("%w: %s (build without -tags mldsa)", ErrSuiteUnavailable, m.id)
	}
	if err := m.pq.Verify(keys.PQ, input, sigs[0]); err != nil {
		return ErrVerify
	}
	return nil
}

var errNoPQBackend = errors.New("ml-dsa backend not compiled in")
