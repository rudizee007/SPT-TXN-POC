// Package sdjwt implements a minimal SD-JWT (Selective Disclosure JWT, per
// draft-ietf-oauth-selective-disclosure-jwt) for the SPT-Txn Travel Rule layer.
//
// The originator VASP issues an SD-JWT over the IVMS101 originator/beneficiary
// fields: each field becomes a salted Disclosure, and the signed JWT carries
// only the SHA-256 digests of those disclosures in its _sd array. The holder
// then presents the JWT plus only the disclosures a given counterparty or
// regulator is entitled to see; the rest stay hidden. The verifier confirms
// each presented disclosure's digest is in the signed _sd set, so disclosed
// values are authenticated and undisclosed values leak nothing.
//
// This is hash-and-salt selective disclosure — real today, no ZK required. The
// ZK predicates (internal/zkproof) cover the facts that must be proven while the
// underlying value stays hidden entirely. Standard library only.
//
// HOLDER-BINDING / REPLAY (CR-2 — enforced invariant, not implemented here).
// This package deliberately implements NO key-binding JWT (KB-JWT) and reads no
// `cnf` claim: an SD-JWT produced or verified here carries selective-disclosure
// integrity ONLY. It does not, on its own, prove who is presenting it or bind the
// presentation to a particular transaction, and therefore offers NO replay
// protection in isolation.
//
// The system's security relies on the invariant that an SD-JWT is ALWAYS carried
// inside an already holder-bound, transaction-bound OUTER token and never trusted
// standalone:
//
//   - The outer CAT / SPT-Txn token is holder-bound via `cnf.jkt` and proof of
//     possession (DPoP), so only the legitimate holder can present it; and
//   - The travel-rule attestation that transports these disclosures binds a
//     `txn_context_hash`, tying the presentation to one specific transaction.
//
// Replay protection and holder authentication are thus provided by that outer
// transport. CALLERS MUST NOT accept or trust a bare SD-JWT presentation that
// arrives outside such a bound outer token; doing so would allow a captured
// presentation to be replayed. If this package is ever used in a context without
// a holder-/transaction-bound outer envelope, a KB-JWT (cnf + signed nonce/aud)
// MUST be added before it can be trusted.
package sdjwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const sdAlg = "sha-256"

// Disclosure is a single selectively-disclosable claim: salt, name, value.
type Disclosure struct {
	Salt    string
	Name    string
	Value   any
	Encoded string // base64url(JSON([salt, name, value]))
}

// NewDisclosure builds a disclosure for a claim with fresh 128-bit salt.
func NewDisclosure(name string, value any) (Disclosure, error) {
	var s [16]byte
	if _, err := rand.Read(s[:]); err != nil {
		return Disclosure{}, err
	}
	salt := b64(s[:])
	raw, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		return Disclosure{}, err
	}
	return Disclosure{Salt: salt, Name: name, Value: value, Encoded: b64(raw)}, nil
}

func digest(encoded string) string {
	h := sha256.Sum256([]byte(encoded))
	return b64(h[:])
}

var reserved = map[string]bool{"iss": true, "iat": true, "exp": true, "_sd": true, "_sd_alg": true}

// Issue creates an SD-JWT over claims (every claim selectively disclosable),
// signed by the issuer, and returns the combined serialization:
//
//	<JWT>~<Disclosure1>~<Disclosure2>~...~
func Issue(issuer string, claims map[string]any, signer crypto.Signer, ttl time.Duration) (string, error) {
	return IssueBound(issuer, claims, nil, signer, ttl)
}

// IssueBound is Issue with additional bound claims that are signed into the JWT
// payload directly (always present, never hidden). Use it to bind the SD-JWT to
// external values — e.g. the SPT-Txn payment context hash and the humanAnchor —
// so the disclosable IVMS101 data cannot be lifted onto a different transaction.
// bound claim names must not be reserved or collide with disclosable names.
func IssueBound(issuer string, disclosable, bound map[string]any, signer crypto.Signer, ttl time.Duration) (string, error) {
	names := make([]string, 0, len(disclosable))
	for n := range disclosable {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic output

	discs := make([]Disclosure, 0, len(names))
	digests := make([]string, 0, len(names))
	for _, n := range names {
		d, err := NewDisclosure(n, disclosable[n])
		if err != nil {
			return "", err
		}
		discs = append(discs, d)
		digests = append(digests, digest(d.Encoded))
	}

	now := time.Now().UTC()
	payload := map[string]any{
		"iss":     issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
		"_sd":     digests,
		"_sd_alg": sdAlg,
	}
	for k, v := range bound {
		if reserved[k] {
			return "", fmt.Errorf("bound claim %q is reserved", k)
		}
		if _, dup := disclosable[k]; dup {
			return "", fmt.Errorf("claim %q cannot be both bound and disclosable", k)
		}
		payload[k] = v
	}
	jwt, err := signJWT(payload, signer)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(jwt)
	for _, d := range discs {
		b.WriteByte('~')
		b.WriteString(d.Encoded)
	}
	b.WriteByte('~')
	return b.String(), nil
}

// Present returns a presentation that includes only the named disclosures,
// dropping the rest. The JWT itself is unchanged.
func Present(combined string, disclose []string) (string, error) {
	jwt, encs, err := split(combined)
	if err != nil {
		return "", err
	}
	want := make(map[string]bool, len(disclose))
	for _, n := range disclose {
		want[n] = true
	}
	var b strings.Builder
	b.WriteString(jwt)
	for _, enc := range encs {
		name, err := disclosureName(enc)
		if err != nil {
			return "", err
		}
		if want[name] {
			b.WriteByte('~')
			b.WriteString(enc)
		}
	}
	b.WriteByte('~')
	return b.String(), nil
}

// Verify checks the issuer signature and expiry, confirms every presented
// disclosure's digest is in the signed _sd set, and returns the disclosed
// claims. A presented disclosure whose digest is absent from _sd is rejected
// (it was not part of what the issuer signed).
func Verify(presentation string, issuerPub ed25519.PublicKey) (map[string]any, error) {
	jwt, encs, err := split(presentation)
	if err != nil {
		return nil, err
	}
	payload, err := verifyJWT(jwt, issuerPub)
	if err != nil {
		return nil, err
	}
	if exp, ok := payload["exp"].(float64); !ok {
		return nil, fmt.Errorf("missing exp")
	} else if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("SD-JWT expired")
	}

	sdRaw, ok := payload["_sd"].([]any)
	if !ok {
		return nil, fmt.Errorf("missing _sd")
	}
	sdSet := make(map[string]bool, len(sdRaw))
	for _, d := range sdRaw {
		if s, ok := d.(string); ok {
			sdSet[s] = true
		}
	}

	result := make(map[string]any, len(encs))
	// Bound claims (signed directly into the payload) are always returned.
	for k, v := range payload {
		if !reserved[k] {
			result[k] = v
		}
	}
	// Disclosed claims, each authenticated against the signed _sd set.
	for _, enc := range encs {
		if !sdSet[digest(enc)] {
			return nil, fmt.Errorf("disclosure not present in signed _sd set (tampered or forged)")
		}
		_, name, value, err := decodeDisclosure(enc)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	return result, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func split(combined string) (jwt string, disclosures []string, err error) {
	parts := strings.Split(combined, "~")
	if len(parts) < 1 || parts[0] == "" {
		return "", nil, fmt.Errorf("malformed SD-JWT")
	}
	jwt = parts[0]
	for _, p := range parts[1:] {
		if p != "" { // drop trailing empty from the final '~'
			disclosures = append(disclosures, p)
		}
	}
	return jwt, disclosures, nil
}

func decodeDisclosure(enc string) (salt, name string, value any, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", "", nil, fmt.Errorf("decode disclosure: %w", err)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", "", nil, fmt.Errorf("parse disclosure: %w", err)
	}
	if len(arr) != 3 {
		return "", "", nil, fmt.Errorf("disclosure must be [salt, name, value]")
	}
	salt, _ = arr[0].(string)
	name, _ = arr[1].(string)
	return salt, name, arr[2], nil
}

func disclosureName(enc string) (string, error) {
	_, name, _, err := decodeDisclosure(enc)
	return name, err
}

func signJWT(payload map[string]any, key crypto.Signer) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "sd-jwt"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(body)
	sig, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

func verifyJWT(jwt string, pub ed25519.PublicKey) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT")
	}
	if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	} else {
		var h struct {
			Alg string `json:"alg"`
		}
		_ = json.Unmarshal(hb, &h)
		if h.Alg != "EdDSA" {
			return nil, fmt.Errorf("unexpected JWT alg %q, want EdDSA", h.Alg)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("SD-JWT signature verification failed")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return payload, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
