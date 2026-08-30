// Package dpop implements a POC subset of DPoP (RFC 9449) for SPT-Txn M4.
//
// DPoP provides the sender constraint: an SPT-Txn Token is bound to a specific
// holder key via a confirmation claim cnf.jkt (the JWK SHA-256 Thumbprint,
// RFC 7638). To present the token, the holder signs a DPoP proof JWT with the
// matching private key; the verifier recomputes the thumbprint from the proof's
// embedded JWK and checks it equals the token's cnf.jkt. This stops a stolen
// bearer token from being replayed by anyone who lacks the holder key.
//
// Scope of the POC implementation:
//   - Keys are Ed25519 (OKP / EdDSA), consistent with the rest of the POC.
//   - Proof carries jti, htm (HTTP method), htu (HTTP URI), iat.
//   - Verify checks signature, htm/htu match, and freshness, then returns the
//     thumbprint for the caller to compare against cnf.jkt.
//
// Not in the POC: ath (access-token hash) binding, nonce/replay server state,
// and key types other than Ed25519. Those are mechanical additions for v2.
package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// DefaultMaxAge is the freshness window for a DPoP proof's iat.
const DefaultMaxAge = 60 * time.Second

// Thumbprint returns the RFC 7638 JWK SHA-256 Thumbprint of an Ed25519 public
// key, base64url-encoded. This is the value placed in cnf.jkt and recomputed at
// verification. The canonical JWK members for an OKP key are crv, kty, x, in
// lexicographic order with no whitespace.
func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ATH is the RFC 9449 access-token hash: base64url(SHA-256(token)). Binding a
// DPoP proof to a specific token via ath stops a proof captured for one token
// being presented with another.
func ATH(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Proof creates a DPoP proof JWT for an HTTP method (htm) and URI (htu), signed
// by the holder's private key, optionally bound to a token via ath (pass "" to
// omit). The corresponding public key is embedded in the header JWK so the
// verifier can check possession.
func Proof(priv ed25519.PrivateKey, htm, htu, ath string) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("private key is not Ed25519")
	}
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "EdDSA",
		"jwk": map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		},
	}
	jti, err := randID()
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"jti": jti,
		"htm": htm,
		"htu": htu,
		"iat": time.Now().UTC().Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64(sig), nil
}

// Verify checks a DPoP proof against the expected htm/htu, the expected access-
// token hash (ath; pass "" to skip), and the freshness window, verifying the
// signature with the proof's own embedded JWK. On success it returns the JWK
// thumbprint (compare to the token's cnf.jkt) and the proof's jti (the caller
// MUST reject a jti it has already seen — single-use replay protection). maxAge
// of zero uses DefaultMaxAge.
func Verify(proof, htm, htu, ath string, maxAge time.Duration) (jkt, jti string, err error) {
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("malformed DPoP proof: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("decode header: %w", err)
	}
	var hdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return "", "", fmt.Errorf("parse header: %w", err)
	}
	if hdr.Typ != "dpop+jwt" {
		return "", "", fmt.Errorf("unexpected typ %q, want dpop+jwt", hdr.Typ)
	}
	if hdr.Alg != "EdDSA" || hdr.JWK.Kty != "OKP" || hdr.JWK.Crv != "Ed25519" {
		return "", "", fmt.Errorf("unsupported DPoP key: alg=%s kty=%s crv=%s", hdr.Alg, hdr.JWK.Kty, hdr.JWK.Crv)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "", "", fmt.Errorf("invalid embedded JWK public key")
	}
	pub := ed25519.PublicKey(pubBytes)

	// Verify the signature against the embedded key.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return "", "", fmt.Errorf("DPoP signature verification failed")
	}

	// Check claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode claims: %w", err)
	}
	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		ATH string `json:"ath"`
		IAT int64  `json:"iat"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", "", fmt.Errorf("parse claims: %w", err)
	}
	if claims.JTI == "" {
		return "", "", fmt.Errorf("DPoP proof missing jti")
	}
	// An EMPTY expected binding is not a weak binding, it is no binding: the
	// comparisons below are equality, so "" == "" passes and the proof authorizes
	// any request. A caller that does not know the method and URI being
	// authorized cannot be given a proof-of-possession answer about them, and
	// this function will not pretend otherwise.
	//
	// Callers are supposed to refuse before reaching here — the gateway does —
	// but "the caller checks" is a property of today's callers, not of this
	// function, and this is the one that compares the values.
	if htm == "" || htu == "" {
		return "", "", fmt.Errorf("DPoP verification requires a non-empty htm and htu to bind to")
	}
	if claims.HTM != htm {
		return "", "", fmt.Errorf("htm mismatch: proof %q, expected %q", claims.HTM, htm)
	}
	// Normalize both htu values before comparison per RFC 9449 §4.3: the scheme
	// and host are case-insensitive and the query and fragment are not part of
	// the binding, so an equivalent-but-differently-spelled URI must still match.
	if normalizeHTU(claims.HTU) != normalizeHTU(htu) {
		return "", "", fmt.Errorf("htu mismatch: proof %q, expected %q", claims.HTU, htu)
	}
	// ath binds the proof to ONE token, and is checked only when the caller
	// supplies one. That is RFC 9449's own rule — ath is required when the proof
	// accompanies an access token, and this package is also used for flows where
	// there is none — so it is NOT tightened here.
	//
	// It does mean a caller that passes "" gets no token binding, and a proof
	// minted for token A would satisfy a check for token B. Callers that present
	// a token MUST pass dpop.ATH(token); the eight-step engine does, and asserts
	// it rather than assuming it (see step5DPoP). Do not move that assertion into
	// this function: it would break the flows the RFC allows.
	if ath != "" && claims.ATH != ath {
		return "", "", fmt.Errorf("ath mismatch: proof is not bound to this token")
	}
	// Compare real durations, not truncated whole seconds, so sub-second
	// maxAge values behave correctly. iat is whole seconds (RFC 9449), so
	// time.Unix(iat,0) is the start of the issuing second; age is therefore a
	// slight over-estimate, which is the safe direction for an expiry check.
	age := time.Since(time.Unix(claims.IAT, 0))
	if age < -5*time.Second { // small forward-skew tolerance
		return "", "", fmt.Errorf("DPoP proof iat is in the future")
	}
	if age > maxAge {
		return "", "", fmt.Errorf("DPoP proof expired (older than %s)", maxAge)
	}

	return Thumbprint(pub), claims.JTI, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// normalizeHTU canonicalizes a DPoP htu value for comparison per RFC 9449 §4.3:
// the scheme and host are lowercased and the query and fragment are stripped
// (they are not part of the htu binding). The path is left untouched so it
// remains a meaningful security boundary. If the input does not parse as a URL
// it is returned unchanged, so a malformed proof htu simply fails the exact
// compare rather than being silently accepted.
func normalizeHTU(htu string) string {
	u, err := url.Parse(htu)
	if err != nil {
		return htu
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
