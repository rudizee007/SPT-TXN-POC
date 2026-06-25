package verifier_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// forgeToken mints a compact JWT with attacker-chosen claims, signed by key.
// Used to test that the verifier re-derives guarantees from presented tokens
// rather than trusting that issuance enforced them.
func forgeToken(claims map[string]any, key ed25519.PrivateKey) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	si := b64u(hdr) + "." + b64u(body)
	sig := ed25519.Sign(key, []byte(si))
	return si + "." + b64u(sig)
}

// Algorithm-confusion: a token with alg:none and an empty signature must be
// rejected at signature verification — the verifier forces Ed25519.
func TestSec_AlgConfusion(t *testing.T) {
	h := build(t)
	parts := strings.Split(h.in.TxnToken, ".")
	forgedHeader := b64u([]byte(`{"alg":"none","typ":"JWT"}`))
	h.in.TxnToken = forgedHeader + "." + parts[1] + "." // empty signature
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 1)
}

// A degenerate all-zero issuer key, even if registered active (review C2), must
// not be usable to accept a token.
func TestSec_ZeroKeyRejected(t *testing.T) {
	h := build(t)
	ctx := context.Background()
	_ = h.reg.Revoke(ctx, issTTS, trustregistry.RoleTTSIssuer, time.Now())
	if err := h.reg.Register(ctx, &trustregistry.Record{
		Iss: issTTS, Role: trustregistry.RoleTTSIssuer,
		PublicKey: make([]byte, 32), KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, h.eng.Verify(ctx, h.in), 1)
}

// Review H3: a maliciously over-scoped CT — validly signed by the CT issuer but
// claiming more scope than its parent CAT — must be rejected by the verifier's
// own monotonicity check, independent of issuance.
func TestSec_OverScopedCT_Forged(t *testing.T) {
	h := build(t)
	forged := forgeToken(map[string]any{
		"iss":                        issCT,
		"sub":                        "alice",
		"iat":                        time.Now().Add(-time.Minute).Unix(),
		"exp":                        time.Now().Add(time.Hour).Unix(),
		"jti":                        h.ct.Claims["jti"], // keep spt_ct_ref matching
		"txn_token_type":             "CT",
		"human_anchor":               h.ct.HumanAnchor,
		"capability_scope":           map[string]any{"max_amount": 999999, "currency": "USD"}, // > CAT's 10000
		"delegation_depth_remaining": 2,
		"holder_key":                 hex.EncodeToString(h.agentPub),
		"spt_cat_ref":                h.cat.Claims["jti"],
		"spt_parent_hash":            "x",
	}, h.ctPriv)
	h.in.CT = forged
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

// A non-positive transaction amount must be rejected (ledger amount validation),
// caught at the context-binding step when the hash is recomputed.
func TestSec_NegativeAmount(t *testing.T) {
	h := build(t)
	h.in.Txn.Amount = "-5000"
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 8)
}

// A token minted for a different audience must not verify here even if otherwise
// valid (cross-domain replay).
func TestSec_CrossDomainAudience(t *testing.T) {
	h := build(t)
	h.in.Audience = "domain-c.someone-else"
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 3)
}
