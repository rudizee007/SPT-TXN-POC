package trustsnapshot

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Sign produces the signed manifest for a snapshot body.
//
// The generator belongs here, in the open verifier, and not in the commercial
// control plane: spec §8 puts verification, pinning, the format and the
// generator on the free side, because a verifier that cannot check its own root
// of trust — or an operator who cannot produce one to check — is not a security
// product. Hosting and distributing snapshots at fleet scale is the separate,
// paid concern.
//
// A self-hosted operator therefore has a complete path: export the registry body,
// Sign it with their own publication key, pin that key in every PEP.
//
// issuerIDs order is fixed by the producer and bound by the signature (spec
// §3.1 rule 7). ExportBody emits records in a deterministic order; pass the
// issuer ids in the same order for a reproducible manifest.
func Sign(body []byte, id string, issuedAt time.Time, issuerIDs []string, prevSnapshotID *string, key ed25519.PrivateKey) (*Manifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("publication key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	if err := checkCharset("id", id); err != nil {
		return nil, err
	}
	for _, iid := range issuerIDs {
		if err := checkCharset("issuer_ids[]", iid); err != nil {
			return nil, err
		}
	}
	if prevSnapshotID != nil {
		if err := checkCharset("prev_snapshot_id", *prevSnapshotID); err != nil {
			return nil, err
		}
	}

	digest, err := BodyDigest(body)
	if err != nil {
		return nil, fmt.Errorf("body digest: %w", err)
	}
	issuedMs := uint64(issuedAt.UTC().UnixMilli())
	si := SigningInput(AlgEdDSA, id, issuedMs, issuerIDs, digest, prevSnapshotID)

	return &Manifest{
		ID:             id,
		IssuedMs:       issuedMs,
		IssuerIDs:      append([]string(nil), issuerIDs...),
		DigestHex:      digest,
		PrevSnapshotID: prevSnapshotID,
		Alg:            AlgEdDSA,
		SigDomain:      SnapshotSigDomain,
		SignatureHex:   hexEncode(ed25519.Sign(key, si)),
	}, nil
}

// MarshalManifest renders a manifest in its wire form.
func MarshalManifest(m *Manifest) ([]byte, error) { return json.MarshalIndent(m, "", "  ") }

// checkCharset enforces spec §3.2: identifiers are ASCII and traversal-free
// (alphanumerics plus -_.:, enough for did:web:). Producers reject out-of-charset
// values so no residual JSON-escaping divergence can reach the signed bytes.
func checkCharset(field, s string) error {
	if s == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return fmt.Errorf("%s %q contains %q, outside the permitted charset (alphanumerics and -_.:)", field, s, string(c))
		}
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("%s %q contains a traversal sequence", field, s)
	}
	return nil
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
