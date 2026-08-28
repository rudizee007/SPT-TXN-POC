package trustsnapshot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/jcs"
)

// The ways a snapshot can be refused. Separate sentinels because they are
// separate diagnoses, and because a caller that cannot tell "the signature is
// wrong" from "the body does not match the signature" cannot tell an attack from
// a distribution bug.
var (
	// ErrNoPinnedKeys: the verifier was given no publication key to check
	// against. Per spec §6 an empty pin set fails closed — accepting a snapshot
	// without one is trust-on-first-use, which §6 forbids.
	ErrNoPinnedKeys = errors.New("no pinned publication key")
	// ErrUnregisteredAlg: an `alg` outside the registered set.
	ErrUnregisteredAlg = errors.New("unregistered signature suite")
	// ErrAlgNotAccepted: a registered `alg` outside this deployment's accept-set.
	ErrAlgNotAccepted = errors.New("signature suite not accepted by this verifier")
	// ErrAlgUnsupported: a registered, accepted `alg` this build cannot verify.
	// Refusing is the only safe answer — the alternative is trial-verifying under
	// a suite the manifest did not name.
	ErrAlgUnsupported = errors.New("signature suite not implemented by this verifier")
	// ErrBadSignature: the detached signature does not verify under any pinned key.
	ErrBadSignature = errors.New("snapshot signature does not verify under any pinned publication key")
	// ErrDigestMismatch: the body is not the body the manifest was signed over.
	ErrDigestMismatch = errors.New("body digest does not match the signed manifest")
	// ErrStale: the snapshot is older than the configured max_age (spec §7).
	ErrStale = errors.New("snapshot is stale")
	// ErrMalformed: the manifest or body could not be parsed as its own format.
	ErrMalformed = errors.New("snapshot is malformed")
)

// Manifest is the signed head of a trust-registry snapshot: the small object a
// verifier checks a signature over, which in turn commits to the body through
// DigestHex.
//
// PrevSnapshotID is a pointer because the field is ALWAYS present in the SIGNING
// INPUT (null when there is no predecessor) while the wire form may omit it.
// See SigningInput — mirroring the wire form here fails to verify every
// first-ever snapshot.
type Manifest struct {
	ID             string   `json:"id"`
	IssuedMs       uint64   `json:"issued_ms"`
	IssuerIDs      []string `json:"issuer_ids"`
	DigestHex      string   `json:"digest_hex"`
	PrevSnapshotID *string  `json:"prev_snapshot_id,omitempty"`
	Alg            string   `json:"alg"`
	SigDomain      string   `json:"sig_domain"`
	SignatureHex   string   `json:"signature_hex"`
}

// Options configures verification. There is no usable zero value on purpose:
// PinnedKeys is required, and so is a staleness policy.
type Options struct {
	// PinnedKeys is the publication-key set (spec §6). A set, not a single key,
	// so rotation has an overlap window. Empty fails closed.
	PinnedKeys []ed25519.PublicKey

	// AcceptAlgs narrows the registered suites this deployment will accept.
	// Empty means {EdDSA} — the only suite this verifier implements.
	AcceptAlgs []string

	// MaxAge is the staleness bound (spec §7). Zero with AllowStale false is an
	// error: "no bound" is not a policy, it is an unset field.
	MaxAge time.Duration

	// AllowStale is the explicit, logged operator choice for a disconnected or
	// air-gapped segment (spec §7's hold-last-known-good). Never a silent
	// default: the caller has to write it down.
	AllowStale bool

	// Now overrides the clock for tests. Zero means time.Now().
	Now time.Time
}

// Verify implements the normative verifier flow of spec §4, in order, failing
// closed at every step.
//
// It returns the parsed manifest only when: the manifest parses; its `alg` is
// registered and accepted and this build implements it; the detached signature
// verifies against a PINNED publication key under exactly that suite; the body's
// digest equals the signed DigestHex; and the snapshot is within max_age.
//
// The order matters and is the spec's. Recomputing the digest before checking
// the signature would let an unsigned body steer the work; checking staleness
// first would leak whether a given id exists.
func Verify(manifestJSON, body []byte, opts Options) (*Manifest, error) {
	if len(opts.PinnedKeys) == 0 {
		return nil, ErrNoPinnedKeys
	}
	if opts.MaxAge <= 0 && !opts.AllowStale {
		return nil, fmt.Errorf("%w: no max_age configured and stale snapshots are not allowed; "+
			"set MaxAge, or set AllowStale explicitly for a disconnected segment", ErrStale)
	}

	// 1. Parse the manifest.
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrMalformed, err)
	}
	if m.SigDomain != "" && m.SigDomain != SnapshotSigDomain {
		return nil, fmt.Errorf("%w: sig_domain %q is not %q — a signature over another artifact type",
			ErrMalformed, m.SigDomain, SnapshotSigDomain)
	}

	// 2. Suite selection, before any signature work. Never trial-verify: the
	//    manifest names one suite and that is the one it is checked under.
	if !RegisteredAlgs[m.Alg] {
		return nil, fmt.Errorf("%w: %q", ErrUnregisteredAlg, m.Alg)
	}
	if !algAccepted(m.Alg, opts.AcceptAlgs) {
		return nil, fmt.Errorf("%w: %q", ErrAlgNotAccepted, m.Alg)
	}
	if m.Alg != AlgEdDSA {
		return nil, fmt.Errorf("%w: %q", ErrAlgUnsupported, m.Alg)
	}

	sig, err := hex.DecodeString(m.SignatureHex)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not hex: %v", ErrMalformed, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(sig), ed25519.SignatureSize)
	}

	si := SigningInput(m.Alg, m.ID, m.IssuedMs, m.IssuerIDs, m.DigestHex, m.PrevSnapshotID)
	verified := false
	for _, k := range opts.PinnedKeys {
		if len(k) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(k, si, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrBadSignature
	}

	// 3. The body is only now worth looking at.
	digest, err := BodyDigest(body)
	if err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrMalformed, err)
	}
	if digest != m.DigestHex {
		return nil, fmt.Errorf("%w: computed %s, signed %s", ErrDigestMismatch, digest, m.DigestHex)
	}

	// 4. Staleness.
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	issued := time.UnixMilli(int64(m.IssuedMs))
	age := now.Sub(issued)
	if !opts.AllowStale && age > opts.MaxAge {
		return nil, fmt.Errorf("%w: issued %s ago, max_age %s", ErrStale, age.Truncate(time.Second), opts.MaxAge)
	}

	return &m, nil
}

func algAccepted(alg string, accept []string) bool {
	if len(accept) == 0 {
		return alg == AlgEdDSA
	}
	for _, a := range accept {
		if a == alg {
			return true
		}
	}
	return false
}

// BodyDigest computes the snapshot body's digest per spec §5:
//
//	digest_hex = hex(SHA-256(JCS(canonical_body)))
//
// The canonical body is NOT the on-disk body. The on-disk form is
// human-readable — pretty-printed, base64 key bytes, RFC 3339 timestamps — and
// is a separate artifact. The digest input is a normalised projection of it:
// public keys HEX-encoded, timestamps integer milliseconds, and the body's
// `version` inside the digested bytes.
//
// Why each of those is load-bearing:
//
//   - Key material must be inside the digest, or the signature proves only WHICH
//     ids and WHEN, never what key material those ids map to. An attacker then
//     serves a body with the same ids and different public keys: the signature is
//     valid, the digest matches, and the keys are theirs.
//   - `version` must be inside it, because a format version protects against
//     mis-parsing and authenticates nothing. Outside the digest, an attacker
//     flips it and the same bytes are reinterpreted under different parsing
//     rules while the digest still matches.
//   - JCS (RFC 8785) rather than a bespoke scheme, and the same canonicalizer
//     already used for receipts and intents. A novel canonical scheme is exactly
//     how a cross-language canonicalization bug gets in.
//
// Array order is preserved: JCS sorts object keys, not arrays, so the record
// SEQUENCE is part of what is digested. Producers must emit a deterministic
// order (see ExportBody).
func BodyDigest(body []byte) (string, error) {
	canonical, err := canonicalBody(body)
	if err != nil {
		return "", err
	}
	encoded, err := jcs.Canonicalize(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalize body: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// bodyRecord mirrors the on-disk record shape deliberately rather than reusing
// the registry's Go type. The digest is defined over the FORMAT — the bytes a
// producer in any language emits — not over one implementation's in-memory
// struct, and a shared type would let a field added for Go's convenience
// silently change what every other implementation has to digest.
type bodyRecord struct {
	Iss           string            `json:"Iss"`
	Role          string            `json:"Role"`
	PublicKey     []byte            `json:"PublicKey"`
	MlkemEncapKey []byte            `json:"MlkemEncapKey,omitempty"`
	KeyType       string            `json:"KeyType"`
	ValidFrom     time.Time         `json:"ValidFrom"`
	ValidUntil    time.Time         `json:"ValidUntil"`
	Status        string            `json:"Status"`
	Metadata      map[string]string `json:"Metadata,omitempty"`
}

type bodyFormat struct {
	Version int           `json:"version"`
	Records []*bodyRecord `json:"records"`
}

func canonicalBody(body []byte) (any, error) {
	var b bodyFormat
	dec := json.NewDecoder(newTrimReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("parse body: %w", err)
	}
	if dec.More() {
		return nil, errors.New("body has trailing content after the JSON object")
	}

	records := make([]any, 0, len(b.Records))
	for i, r := range b.Records {
		if r == nil {
			return nil, fmt.Errorf("record %d is null", i)
		}
		rec := map[string]any{
			"iss":            r.Iss,
			"role":           r.Role,
			"public_key":     hex.EncodeToString(r.PublicKey),
			"key_type":       r.KeyType,
			"valid_from_ms":  r.ValidFrom.UTC().UnixMilli(),
			"valid_until_ms": r.ValidUntil.UTC().UnixMilli(),
			"status":         r.Status,
		}
		if len(r.MlkemEncapKey) > 0 {
			rec["mlkem_encap_key"] = hex.EncodeToString(r.MlkemEncapKey)
		}
		if len(r.Metadata) > 0 {
			md := make(map[string]any, len(r.Metadata))
			for k, v := range r.Metadata {
				md[k] = v
			}
			rec["metadata"] = md
		}
		records = append(records, rec)
	}
	return map[string]any{
		"version": int64(b.Version),
		"records": records,
	}, nil
}

// canonicalBodyBytes returns the exact JCS bytes the digest is taken over. It
// exists so the known-answer vectors can pin the canonical form itself, not just
// its hash — a digest mismatch tells you something moved, the canonical bytes
// tell you what.
func canonicalBodyBytes(body []byte) ([]byte, error) {
	canonical, err := canonicalBody(body)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(canonical)
}
