// Package receipt implements the SPT-Txn Transaction Receipt: a compact
// signed record emitted at decision time, appended to the transparency log
// (internal/audit). Spec: docs/spec/RECEIPT-FORMAT.md.
//
// The receipt is the artifact that lets an auditor VERIFY a chain instead of
// sampling controls: "this control was enforced at the moment of this
// specific transaction, and here is a cryptographic proof."
//
// Signing key discipline: receipts are signed with the LOG/AUDIT key, which
// is separate from the token issuance key and rotates on its own schedule
// (docs/THREAT-MODEL.md §3.5). No payloads, no PII, ever — hashes and
// references only.
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/jcs"
)

// Version is the receipt format version string.
const Version = "spt-receipt-v1"

// signingTag domain-separates receipt signatures from every other Ed25519
// use in the system.
const signingTag = "spt-txn-receipt-v1"

// Decision values. Nothing else is valid — there is no "maybe".
const (
	DecisionPermit = "PERMIT"
	DecisionDeny   = "DENY"
)

// Decision classes. Operators MUST be able to tell an outage from an attack.
const (
	ClassOK          = "ok"          // permits
	ClassViolation   = "violation"   // denied: a check failed
	ClassUnavailable = "unavailable" // denied: a dependency was unreachable/degraded
)

// Receipt is a single decision record. All fields participate in the
// signature except Sig itself.
type Receipt struct {
	V            string `json:"v"`
	PEP          string `json:"pep"`
	Decision     string `json:"decision"`
	Class        string `json:"class"`
	RulePath     string `json:"rule_path"`
	TokenHash    string `json:"token_hash"`  // base64url SHA-256 of the presented compact token; "" if none
	PolicyHash   string `json:"policy_hash"` // base64url SHA-256 of the policy bundle evaluated
	IntentDigest string `json:"intent_digest,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	TS           int64  `json:"ts"`
	Nonce        string `json:"nonce"`
	Sig          string `json:"sig,omitempty"`
}

// TokenHash hashes a presented compact token for inclusion in a receipt.
func TokenHash(token string) string {
	if token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// New builds an unsigned receipt with version, timestamp, and fresh nonce
// populated. It validates the decision/class pairing: PERMIT must be ClassOK
// and DENY must be violation or unavailable — a mislabeled receipt is a
// defect in the evidence chain, so it is rejected at construction.
func New(pep, decision, class, rulePath, tokenHash, policyHash string) (*Receipt, error) {
	if pep == "" {
		return nil, errors.New("receipt: empty PEP identity")
	}
	switch decision {
	case DecisionPermit:
		if class != ClassOK {
			return nil, fmt.Errorf("receipt: PERMIT requires class %q, got %q", ClassOK, class)
		}
	case DecisionDeny:
		if class != ClassViolation && class != ClassUnavailable {
			return nil, fmt.Errorf("receipt: DENY requires class %q or %q, got %q", ClassViolation, ClassUnavailable, class)
		}
	default:
		return nil, fmt.Errorf("receipt: invalid decision %q", decision)
	}
	if rulePath == "" {
		return nil, errors.New("receipt: empty rule path")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("receipt: nonce: %w", err)
	}
	return &Receipt{
		V:          Version,
		PEP:        pep,
		Decision:   decision,
		Class:      class,
		RulePath:   rulePath,
		TokenHash:  tokenHash,
		PolicyHash: policyHash,
		TS:         time.Now().UTC().Unix(),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce[:]),
	}, nil
}

// signingInput is the deterministic byte string that is signed: the JCS
// canonical form of every field except sig, under a domain-separation tag.
// SigningInput exposes the exact bytes that are signed and verified, so an
// independent implementation can reproduce them and produce interoperable
// signatures. It is the published conformance surface for receipts
// (docs/conformance). The bytes are domain-tag || 0x00 || JCS(receipt-without-sig).
func (r *Receipt) SigningInput() ([]byte, error) { return r.signingInput() }

// One canonicalizer for the whole system (internal/jcs).
func (r *Receipt) signingInput() ([]byte, error) {
	m := map[string]any{
		"v":           r.V,
		"pep":         r.PEP,
		"decision":    r.Decision,
		"class":       r.Class,
		"rule_path":   r.RulePath,
		"token_hash":  r.TokenHash,
		"policy_hash": r.PolicyHash,
		"ts":          r.TS,
		"nonce":       r.Nonce,
	}
	if r.IntentDigest != "" {
		m["intent_digest"] = r.IntentDigest
	}
	if r.Jurisdiction != "" {
		m["jurisdiction"] = r.Jurisdiction
	}
	canonical, err := jcs.Canonicalize(m)
	if err != nil {
		return nil, fmt.Errorf("receipt: canonicalize: %w", err)
	}
	out := make([]byte, 0, len(signingTag)+1+len(canonical))
	out = append(out, signingTag...)
	out = append(out, 0x00)
	out = append(out, canonical...)
	return out, nil
}

// Sign signs the receipt with the log key and stores the signature.
func (r *Receipt) Sign(logKey ed25519.PrivateKey) error {
	if len(logKey) != ed25519.PrivateKeySize {
		return errors.New("receipt: bad log key size")
	}
	in, err := r.signingInput()
	if err != nil {
		return err
	}
	r.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(logKey, in))
	return nil
}

// Verify checks the receipt signature against the log public key. It also
// re-validates the decision/class pairing so a forged-but-signed-elsewhere
// mislabeled record cannot pass by shape.
func (r *Receipt) Verify(logPub ed25519.PublicKey) error {
	if len(logPub) != ed25519.PublicKeySize {
		return errors.New("receipt: bad log public key size")
	}
	if r.V != Version {
		return fmt.Errorf("receipt: unsupported version %q", r.V)
	}
	switch {
	case r.Decision == DecisionPermit && r.Class == ClassOK:
	case r.Decision == DecisionDeny && (r.Class == ClassViolation || r.Class == ClassUnavailable):
	default:
		return fmt.Errorf("receipt: invalid decision/class pair %q/%q", r.Decision, r.Class)
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("receipt: malformed signature")
	}
	in, err := r.signingInput()
	if err != nil {
		return err
	}
	if !ed25519.Verify(logPub, in, sig) {
		return errors.New("receipt: signature verification failed")
	}
	return nil
}

// Hash returns the base64url SHA-256 of the signed receipt's signing input
// plus signature — the leaf value a transparency-log entry commits to.
func (r *Receipt) Hash() (string, error) {
	if r.Sig == "" {
		return "", errors.New("receipt: hash of unsigned receipt")
	}
	in, err := r.signingInput()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(in)
	h.Write([]byte{0x00})
	h.Write([]byte(r.Sig))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// AuditDetail renders the receipt as a flat detail map for the transparency
// log (internal/audit.Log.Append). Hashes and enums only — the audit
// package's no-PII gate stays intact.
func (r *Receipt) AuditDetail() (map[string]string, error) {
	rh, err := r.Hash()
	if err != nil {
		return nil, err
	}
	d := map[string]string{
		"receipt_v":    r.V,
		"receipt_hash": rh,
		"pep":          r.PEP,
		"decision":     r.Decision,
		"class":        r.Class,
		"rule_path":    r.RulePath,
		"token_hash":   r.TokenHash,
		"policy_hash":  r.PolicyHash,
	}
	if r.IntentDigest != "" {
		d["intent_digest"] = r.IntentDigest
	}
	if r.Jurisdiction != "" {
		d["jurisdiction"] = r.Jurisdiction
	}
	return d, nil
}
