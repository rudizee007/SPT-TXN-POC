package verifier_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
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

// decodeClaims returns the (unverified) claims of a compact JWT for tests that
// re-forge a token with one field changed.
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: %d parts", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return m
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

// VER-2: a signature-verified SPT-Txn Token carrying a non-string human_anchor
// (e.g. a JSON object) must be rejected cleanly at the chain step — never panic
// the verifier by comparing uncomparable `any` values with !=.
func TestSec_NonStringHumanAnchor_NoPanic(t *testing.T) {
	h := build(t)
	claims := decodeClaims(t, h.in.TxnToken)
	claims["human_anchor"] = map[string]any{"evil": "uncomparable"} // not a string
	forged := forgeToken(claims, h.ttsPriv)
	// Re-bind a fresh DPoP proof to the re-signed token so steps 1-5 pass and the
	// chain step (6) is reached.
	proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(forged))
	if err != nil {
		t.Fatal(err)
	}
	h.in.TxnToken = forged
	h.in.DPoPProof = proof
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

// VER-1: a CT presented with a different (but validly-signed) CAT than the one
// it was issued against must be rejected — its spt_parent_hash no longer matches
// the presented CAT.
func TestSec_CTPresentedWithDifferentCAT(t *testing.T) {
	h := build(t)
	other, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: h.agentPub,
	}, h.ctPriv)
	if err != nil {
		t.Fatalf("other CAT: %v", err)
	}
	h.in.CAT = other.Token
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

// VER-1 (direct): swapping in a CAT whose jti the CT *does* reference but whose
// bytes differ must still be rejected by the spt_parent_hash check. We forge a
// CAT reusing the original CAT's jti (so the spt_cat_ref linkage passes) and the
// same human_anchor, leaving spt_parent_hash as the only check that can fire.
func TestSec_CTParentHashMismatch(t *testing.T) {
	h := build(t)
	catClaims := decodeClaims(t, h.cat.Token)
	catClaims["sub"] = "alice-tampered" // change the bytes, keep jti + human_anchor
	forgedCAT := forgeToken(catClaims, h.ctPriv)
	if forgedCAT == h.cat.Token {
		t.Fatal("forged CAT must differ from the original")
	}
	h.in.CAT = forgedCAT
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

// VER-3: a token whose iat is well in the future (beyond the skew tolerance)
// must be rejected at the expiry step even though its exp is still valid.
func TestSec_FutureIAT(t *testing.T) {
	h := build(t)
	claims := decodeClaims(t, h.in.TxnToken)
	claims["iat"] = float64(time.Now().Add(2 * time.Hour).Unix())
	claims["exp"] = float64(time.Now().Add(3 * time.Hour).Unix())
	forged := forgeToken(claims, h.ttsPriv)
	h.in.TxnToken = forged
	// step2 runs before DPoP, so the original proof binding is irrelevant here.
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 2)
}

// ── monotonic TTL, final hop (adversarial review #3, F2) ─────────────────────

// reforgeTxn re-signs the SPT-Txn with mutated claims and refreshes the DPoP
// proof, which is bound to the token by `ath`. Without the refresh the request
// dies at step 5 and the test would pass for the wrong reason.
func reforgeTxn(t *testing.T, h *harness, mutate func(map[string]any)) {
	t.Helper()
	claims := decodeClaims(t, h.in.TxnToken)
	mutate(claims)
	h.in.TxnToken = forgeToken(claims, h.ttsPriv)
	proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(h.in.TxnToken))
	if err != nil {
		t.Fatal(err)
	}
	h.in.DPoPProof = proof
}

// A malicious or compromised TTS mints an SPT-Txn that outlives the capability
// authorizing it. `txntoken.Issue` refuses this, so the token must be forged —
// which is exactly the threat invariant 2 names: the check exists at
// verification *because* a malicious issuer must not be able to extend a
// lifetime. Authority would otherwise persist after its grant expired.
func TestSec_TxnMustNotOutliveItsLeafCapability(t *testing.T) {
	h := build(t)
	leafExp := decodeClaims(t, h.in.CT)["exp"].(float64)
	reforgeTxn(t, h, func(c map[string]any) { c["exp"] = leafExp + 1 })
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

// Property: across a spread of offsets from the leaf's expiry, the engine
// permits EXACTLY when the transaction token does not outlive its capability.
//
// Both directions matter. A test that only asserts denial of over-long tokens
// passes just as well against an engine that denies everything, and the scope
// attenuation property test in internal/cttoken — the model for this one — is
// issuance-side and would not have caught any of F2.
func TestSec_TxnLifetimeAttenuationProperty(t *testing.T) {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	t.Logf("seed %d", seed)

	for i := 0; i < 200; i++ {
		h := build(t)
		leafExp := int64(decodeClaims(t, h.in.CT)["exp"].(float64))

		// Spread across the boundary: comfortably inside, exactly at, one past,
		// well past.
		//
		// The "inside" case must stay strictly in the FUTURE. An earlier version
		// drew an unbounded negative offset and produced already-expired tokens,
		// which step 2 rejected — correctly. "Does not outlive its parent" and
		// "is still valid" are different properties, and only the first is under
		// test here. That confusion surfaced because this asserts both
		// directions; a deny-only test would have passed straight over it.
		now := time.Now().Unix()
		span := leafExp - now
		if span < 2 {
			t.Fatalf("fixture leaf CT expires in %ds — too soon to draw an interior point", span)
		}
		var txExp int64
		switch i % 4 {
		case 0:
			txExp = now + 1 + rng.Int63n(span) // (now, leafExp]
		case 1:
			txExp = leafExp
		case 2:
			txExp = leafExp + 1
		default:
			txExp = leafExp + 1 + rng.Int63n(86400)
		}
		reforgeTxn(t, h, func(c map[string]any) { c["exp"] = float64(txExp) })

		d := h.eng.Verify(context.Background(), h.in)
		wantAllow := txExp <= leafExp
		if d.Allow != wantAllow {
			t.Fatalf("txExp %d (leafExp %+d, now %+d): allow=%v want %v (step %d: %s)",
				txExp, txExp-leafExp, txExp-now, d.Allow, wantAllow, d.Step, d.Reason)
		}
	}
}

// ── temporal bounds, both sides (adversarial review #3, F5) ─────────────────

// The iat check previously ran only when the claim was present and numeric, so
// omitting it — or sending a string — switched it off. A check an attacker can
// disable by leaving a field out is not a check.
func TestSec_IatIsRequiredNotOptional(t *testing.T) {
	for _, c := range []struct {
		name string
		iat  any
	}{
		{"absent", nil},
		{"string", "1750000000"},
		{"bool", true},
		{"null", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t)
			reforgeTxn(t, h, func(m map[string]any) {
				if c.iat == nil {
					delete(m, "iat")
					return
				}
				m["iat"] = c.iat
			})
			mustDeny(t, h.eng.Verify(context.Background(), h.in), 2)
		})
	}
}

// exp MUST be strictly after iat (invariant 2). An inverted or zero-length
// window is malformed, and no clock skew makes it legitimate — this is a
// relationship between two fields of one token.
func TestSec_ExpMustBeStrictlyAfterIat(t *testing.T) {
	for _, name := range []string{"equal", "inverted"} {
		t.Run(name, func(t *testing.T) {
			h := build(t)
			reforgeTxn(t, h, func(m map[string]any) {
				exp := m["exp"].(float64)
				if name == "equal" {
					m["iat"] = exp
				} else {
					m["iat"] = exp + 60
				}
			})
			mustDeny(t, h.eng.Verify(context.Background(), h.in), 2)
		})
	}
}

// Clock skew must be able to reject early and never to accept late. A token
// already past exp is not rescued by the iat allowance.
func TestSec_SkewNeverExtendsExpiry(t *testing.T) {
	h := build(t)
	reforgeTxn(t, h, func(m map[string]any) {
		now := float64(time.Now().Unix())
		m["iat"] = now - 120
		m["exp"] = now - 1 // one second past
	})
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 2)
}

// And the permit direction: a well-formed window is still accepted, so none of
// the above is satisfied by an engine that rejects everything.
func TestSec_WellFormedTemporalWindowIsAccepted(t *testing.T) {
	h := build(t)
	reforgeTxn(t, h, func(m map[string]any) {
		now := float64(time.Now().Unix())
		m["iat"] = now - 5
		m["exp"] = now + 30
	})
	if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
		t.Fatalf("well-formed window denied at step %d: %s", d.Step, d.Reason)
	}
}
