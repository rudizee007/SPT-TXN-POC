// Package intent implements SPT-Txn intent binding: a token carries a digest
// of the DECLARED action, and the PEP verifies the ACTUAL call against it.
// An agent whose reasoning is hijacked mid-task holds a token that is
// cryptographically useless for the hijacked action (OWASP ASI01; NIST RFI
// "cross-system calls without proper authorization chains").
//
// Spec: docs/spec/DELEGATION-INTENT-MCP.md §2. Canonicalization is the single
// shared implementation in internal/jcs — do not canonicalize anywhere else.
package intent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rudizee007/spt-txn-poc/pkg/jcs"
)

// Claim is the token claim carrying the bound intent digest.
const Claim = "spt_intent_digest"

// domainTag domain-separates intent digests from every other SHA-256 use in
// the system. Covered fields: tool, params, target (docs/spec §2.1).
const domainTag = "spt-txn-intent-v1"

// ErrMismatch is the uniform external result for a failed intent check. The
// receipt records which internal check failed; the caller learns only this.
var ErrMismatch = errors.New("intent: declared intent does not match actual call")

// Intent is a declared (or observed) action: one tool, one parameter object,
// one target resource.
type Intent struct {
	// Tool is the tool/method identifier (e.g. an MCP tool name, an HTTP
	// method+route identifier, an ISO 20022 message type).
	Tool string
	// Params is the parameter object as raw JSON. It must be a JSON object
	// within the jcs accepted subset; anything else is rejected.
	Params json.RawMessage
	// Target is the target resource / service identity the action executes
	// against (e.g. the PEP's configured server identity). Binding the target
	// means a token minted for one server cannot verify at another.
	Target string
}

// Digest computes base64url(SHA-256(domainTag || 0x00 || JCS(intent))).
// Rejection anywhere (empty fields, params not an object, out-of-subset
// JSON) is an error — never a best-effort digest.
func (in Intent) Digest() (string, error) {
	if in.Tool == "" {
		return "", errors.New("intent: empty tool")
	}
	if in.Target == "" {
		return "", errors.New("intent: empty target")
	}
	params, err := parseParams(in.Params)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Canonicalize(map[string]any{
		"tool":   in.Tool,
		"params": params,
		"target": in.Target,
	})
	if err != nil {
		return "", fmt.Errorf("intent: canonicalize: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(domainTag))
	h.Write([]byte{0x00})
	h.Write(canonical)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// parseParams strictly parses the raw params and requires a JSON object.
func parseParams(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		// Absent params bind as the empty object — but only via this single
		// documented rule, applied identically at declaration and at
		// verification, so it cannot create an issuer/verifier divergence.
		return map[string]any{}, nil
	}
	v, err := jcs.ParseStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("intent: params: %w", err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("intent: params must be a JSON object")
	}
	return v, nil
}

// Match verifies the actual call against the digest bound in the token.
// Comparison is constant-time. Any failure — recomputation error or digest
// inequality — returns ErrMismatch; the wrapped detail is for the receipt,
// not for the wire.
func Match(boundDigest string, actual Intent) error {
	if boundDigest == "" {
		// A token without an intent digest presented to an intent-enforcing
		// PEP is a violation; absence never downgrades enforcement.
		return fmt.Errorf("%w: token carries no intent digest", ErrMismatch)
	}
	got, err := actual.Digest()
	if err != nil {
		return fmt.Errorf("%w: recompute: %v", ErrMismatch, err)
	}
	// Compare fixed-length decoded digests in constant time.
	a, err1 := base64.RawURLEncoding.DecodeString(boundDigest)
	b, err2 := base64.RawURLEncoding.DecodeString(got)
	if err1 != nil || err2 != nil || len(a) != sha256.Size || len(b) != sha256.Size {
		return fmt.Errorf("%w: malformed digest encoding", ErrMismatch)
	}
	if subtle.ConstantTimeCompare(a, b) != 1 {
		return ErrMismatch
	}
	return nil
}

// BoundDigestFromClaims extracts the intent digest claim from token claims.
// Missing or non-string claims return "", which Match treats as a violation.
func BoundDigestFromClaims(claims map[string]any) string {
	s, _ := claims[Claim].(string)
	return s
}
