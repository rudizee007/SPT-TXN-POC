// Package oidc is a small, dependency-light OpenID Connect / OAuth 2.0 token
// verifier used to accept an external identity provider's token (e.g. Keycloak,
// Okta, Auth0) as the subject_token of an RFC 8693 Token Exchange. It performs
// OIDC discovery, fetches and caches the JWKS, and verifies an RS256-signed JWT
// (issuer, expiry, and optionally audience). RS256 is Keycloak's default; this
// is deliberately stdlib-only (crypto/rsa) to match the project's minimal-deps
// posture. ES256 support is a small, marked extension point.
//
// Verification is issuance-time only — the JWKS is cached, so this never sits in
// the SPT-Txn hot path.
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Claims is a decoded JWT claim set.
type Claims map[string]any

// Str returns a string claim (empty if absent or not a string).
func (c Claims) Str(k string) string { s, _ := c[k].(string); return s }

// Verifier verifies OIDC ID/access tokens from a single issuer.
type Verifier struct {
	issuer    string
	audiences map[string]bool
	leeway    time.Duration
	hc        *http.Client

	insecureScheme bool
	issuerURL      *url.URL

	jwksURI string
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey // kid -> RSA public key
	// fetchedAt is when keys was last successfully loaded, and attemptedAt when
	// a load was last tried (success or not). maxAge bounds how long a cached
	// key set is honoured; minInterval bounds how often a fetch may be
	// attempted. Both exist for reasons the other cannot cover: without maxAge
	// a key set is cached until the process dies, so a key revoked at the
	// provider is honoured indefinitely whenever the presented kid still hits
	// the cache. Without minInterval, the cache MISS path is an unauthenticated
	// outbound fetch driven by a field of the caller's token.
	fetchedAt   time.Time
	attemptedAt time.Time
	maxAge      time.Duration
	minInterval time.Duration
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithAudience requires the token's `aud` to match one of these values.
//
// `azp` is deliberately NOT accepted as a substitute. azp is the authorized
// party — the client that requested the token — so it is present on every token
// that client obtains, for every resource. Matching on it turns a restriction on
// WHICH RESOURCE may consume the token into a restriction on WHICH CLIENT asked
// for it, which are different properties, and the second one does not bound
// replay across relying parties.
//
// If never set, the audience check is skipped. Callers that require the bound
// must set it; cmd/idp-bridge refuses to start without it.
func WithAudience(aud ...string) Option {
	return func(v *Verifier) {
		for _, a := range aud {
			if a != "" {
				v.audiences[a] = true
			}
		}
	}
}

// WithHTTPClient overrides the HTTP client (e.g. timeouts, a pinned CA pool).
func WithHTTPClient(hc *http.Client) Option { return func(v *Verifier) { v.hc = hc } }

// WithLeeway sets the clock-skew tolerance for exp/nbf (default 60s).
func WithLeeway(d time.Duration) Option { return func(v *Verifier) { v.leeway = d } }

// WithJWKSMaxAge bounds how long a cached key set is honoured before it must be
// re-fetched (default 15 minutes). This IS the propagation delay for a key
// revoked at the provider, so set it to what the deployment can tolerate.
func WithJWKSMaxAge(d time.Duration) Option {
	return func(v *Verifier) {
		if d > 0 {
			v.maxAge = d
		}
	}
}

// WithJWKSMinRefreshInterval bounds how often a key-set fetch may be attempted
// (default 30 seconds). The cache-miss path is reachable by an unauthenticated
// caller — the kid is a field of the token being presented, read before the
// signature is checked — so without a floor here each junk token becomes one
// outbound request to the identity provider.
func WithJWKSMinRefreshInterval(d time.Duration) Option {
	return func(v *Verifier) {
		if d > 0 {
			v.minInterval = d
		}
	}
}

// WithInsecureIssuerScheme permits a plaintext http:// issuer. Discovery decides
// which keys this verifier will trust for the life of the process, so over
// plaintext anything on the path chooses them. Loopback does not need this
// option; everything else does, and it should exist only in a demo.
func WithInsecureIssuerScheme() Option {
	return func(v *Verifier) { v.insecureScheme = true }
}

// NewVerifier runs OIDC discovery against issuer and loads its JWKS.
func NewVerifier(ctx context.Context, issuer string, opts ...Option) (*Verifier, error) {
	v := &Verifier{
		issuer:      strings.TrimRight(issuer, "/"),
		audiences:   map[string]bool{},
		leeway:      60 * time.Second,
		hc:          &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect},
		keys:        map[string]*rsa.PublicKey{},
		maxAge:      15 * time.Minute,
		minInterval: 30 * time.Second,
	}
	for _, o := range opts {
		o(v)
	}
	iss, err := parseIssuer(v.issuer, v.insecureScheme)
	if err != nil {
		return nil, err
	}
	v.issuerURL = iss
	if err := v.discover(ctx); err != nil {
		return nil, err
	}
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) discover(ctx context.Context) error {
	url := v.issuer + "/.well-known/openid-configuration"
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, url, &d); err != nil {
		return fmt.Errorf("oidc: discovery %s: %w", url, err)
	}
	// The issuer member is REQUIRED, not "checked if present". Treating an
	// absent member as nothing to check makes the one anti-substitution test in
	// this function optional at the discretion of whoever answered the request.
	if d.Issuer == "" {
		return errors.New("oidc: discovery document declares no issuer")
	}
	if strings.TrimRight(d.Issuer, "/") != v.issuer {
		return fmt.Errorf("oidc: discovery issuer %q != configured %q", d.Issuer, v.issuer)
	}
	if d.JWKSURI == "" {
		return errors.New("oidc: discovery document has no jwks_uri")
	}
	// jwks_uri decides which keys this verifier trusts for the life of the
	// process, and it arrives inside the document being validated. Requiring it
	// to share an origin with the configured issuer keeps that choice inside the
	// authority the operator already named, rather than wherever the document
	// points.
	if err := sameOrigin(v.issuerURL, d.JWKSURI); err != nil {
		return fmt.Errorf("oidc: discovery jwks_uri: %w", err)
	}
	v.jwksURI = d.JWKSURI
	return nil
}

// parseIssuer validates the configured issuer URL and returns it parsed.
func parseIssuer(issuer string, allowPlaintext bool) (*url.URL, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: issuer %q is not a URL: %w", issuer, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("oidc: issuer %q has no host", issuer)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if allowPlaintext || isLoopback(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("oidc: issuer %q is plaintext http; discovery over http lets "+
			"anything on the path choose the signing keys this verifier will trust. Use https, "+
			"or pass WithInsecureIssuerScheme for a demo", issuer)
	default:
		return nil, fmt.Errorf("oidc: issuer %q has unsupported scheme %q", issuer, u.Scheme)
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// sameOrigin reports whether raw shares scheme, host and port with base.
func sameOrigin(base *url.URL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("%q is not on the issuer's origin %s://%s", raw, base.Scheme, base.Host)
	}
	return nil
}

// noRedirect refuses every redirect on discovery and JWKS fetches. A redirect is
// the server choosing where the next request goes, and both of these requests
// decide which keys are trusted — including a downgrade from https to http.
func noRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("oidc: refusing redirect to %s (discovery and jwks are fetched without following redirects)", req.URL)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Verifier) refreshJWKS(ctx context.Context) error {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := v.getJSON(ctx, v.jwksURI, &set); err != nil {
		return fmt.Errorf("oidc: fetch jwks %s: %w", v.jwksURI, err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue // ES256 keys (kty=EC) are a marked extension point
		}
		pub, err := rsaFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("oidc: no usable RSA signing keys in JWKS")
	}
	now := time.Now()
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = now
	v.mu.Unlock()
	return nil
}

// tryRefresh attempts a key-set fetch subject to the minimum interval, and
// reports whether a fetch was actually made. A refusal is not an error: the
// caller still has whatever key set it had, and the decision to accept or
// reject the token is made on that, not on whether a fetch happened.
func (v *Verifier) tryRefresh(ctx context.Context) (bool, error) {
	now := time.Now()
	v.mu.Lock()
	if !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < v.minInterval {
		v.mu.Unlock()
		return false, nil
	}
	v.attemptedAt = now
	v.mu.Unlock()
	return true, v.refreshJWKS(ctx)
}

// keySetStale reports whether the cached key set is older than maxAge.
func (v *Verifier) keySetStale() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.fetchedAt.IsZero() || time.Since(v.fetchedAt) > v.maxAge
}

func rsaFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	// The exponent is refused rather than repaired. Substituting a guessed 65537
	// for one that did not parse means verifying against a key the provider did
	// not publish, and silently: the caller sees a working verifier either way.
	if len(eb) == 0 || len(eb) > 8 {
		return nil, fmt.Errorf("oidc: jwk exponent is %d bytes, want 1..8", len(eb))
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf("oidc: jwk exponent %d is not a usable RSA public exponent", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func (v *Verifier) keyFor(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

// Verify checks an RS256 JWT and returns its claims. It validates the signature
// against the issuer's JWKS, the exact issuer, expiry/not-before (with leeway),
// and (if configured) the audience.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed token (want 3 parts)")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("oidc: header json: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported alg %q (RS256 only in this build)", hdr.Alg)
	}
	// A stale key set is refreshed BEFORE it is consulted. Refreshing only on a
	// cache miss would leave the decision of whether a revoked key is still
	// honoured to whoever chooses the kid — which is the presenter of the token.
	if v.keySetStale() {
		// tryRefresh returns (false, nil) when the minimum-interval limiter
		// refuses -- a refusal, not an error. Discarding that bool meant a
		// throttled refusal fell through and the EXPIRED key set was consulted
		// anyway: once the JWKS endpoint is unreachable, one request per interval
		// fails and every other request in the window verifies against keys the
		// operator's maxAge says are no longer trustworthy, indefinitely. That is
		// a fail-open on revocation, and it contradicted the comment above it.
		fetched, err := v.tryRefresh(ctx)
		if err != nil {
			return nil, err
		}
		if !fetched {
			return nil, errors.New("oidc: key set is older than maxAge and a refresh was refused by the minimum-interval limiter; refusing to verify against it")
		}
	}
	pub := v.keyFor(hdr.Kid)
	if pub == nil { // key rotation — one rate-limited refresh, then decide
		fetched, err := v.tryRefresh(ctx)
		if err != nil {
			return nil, err
		}
		if pub = v.keyFor(hdr.Kid); pub == nil {
			if !fetched {
				// Refused by the minimum interval. Say so, so an operator
				// looking at a real rotation can tell it from an unknown key.
				return nil, fmt.Errorf("oidc: no signing key for kid %q (key set not refetched; "+
					"minimum refresh interval %s not yet elapsed)", hdr.Kid, v.minInterval)
			}
			return nil, fmt.Errorf("oidc: no signing key for kid %q", hdr.Kid)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: signature b64: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("oidc: signature invalid: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: payload b64: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, fmt.Errorf("oidc: payload json: %w", err)
	}
	if iss := claims.Str("iss"); strings.TrimRight(iss, "/") != v.issuer {
		return nil, fmt.Errorf("oidc: issuer %q != expected %q", iss, v.issuer)
	}
	now := time.Now()
	// exp is REQUIRED: a token with no expiry would never age out. Reject it
	// rather than treat a missing exp as "never expires" (fail closed).
	exp, hasExp := numTime(claims["exp"])
	if !hasExp {
		return nil, errors.New("oidc: token missing required exp")
	}
	if now.After(exp.Add(v.leeway)) {
		return nil, errors.New("oidc: token expired")
	}
	if nbf, ok := numTime(claims["nbf"]); ok && now.Add(v.leeway).Before(nbf) {
		return nil, errors.New("oidc: token not yet valid (nbf)")
	}
	if len(v.audiences) > 0 && !v.audienceOK(claims) {
		return nil, errors.New("oidc: audience mismatch")
	}
	return claims, nil
}

// audienceOK matches only `aud`. See WithAudience for why `azp` is not accepted
// here: it names the client that asked for the token, not the resource entitled
// to consume it, so a match on it would admit every token that client holds.
func (v *Verifier) audienceOK(c Claims) bool {
	switch a := c["aud"].(type) {
	case string:
		return v.audiences[a]
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && v.audiences[s] {
				return true
			}
		}
	}
	return false
}

// numTime converts a JSON numeric (float64) epoch-seconds claim to a time.
func numTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

func (v *Verifier) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}
