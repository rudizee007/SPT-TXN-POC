package verifier_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/txntoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
)

const (
	issCT  = "domain-a.authorg"
	issTTS = "domain-a.tts"
	aud    = "domain-b.execorg"
	htm    = "POST"
	htu    = "https://foss.violetskysecurity.com/b/verify"
)

type harness struct {
	eng       *verifier.Engine
	reg       *trustregistry.MockRegistry
	in        verifier.Input
	ctPub     ed25519.PublicKey
	ctPriv    ed25519.PrivateKey
	ttsPub    ed25519.PublicKey
	ttsPriv   ed25519.PrivateKey
	agentPub  ed25519.PublicKey
	agentPriv ed25519.PrivateKey
	cat       *cattoken.CAT
	ct       *cttoken.CT
	tc        ledger.TxnContext
	l         ledger.Ledger
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func register(t *testing.T, reg *trustregistry.MockRegistry, iss string, role trustregistry.Role, pub ed25519.PublicKey) {
	t.Helper()
	err := reg.Register(context.Background(), &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	})
	if err != nil {
		t.Fatalf("register %s/%s: %v", iss, role, err)
	}
}

func build(t *testing.T) *harness {
	t.Helper()
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{reg: reg}
	h.ctPub, h.ctPriv = genKey(t)
	h.ttsPub, h.ttsPriv = genKey(t)
	h.agentPub, h.agentPriv = genKey(t)
	register(t, reg, issCT, trustregistry.RoleCTIssuer, h.ctPub)
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, h.ttsPub)

	h.cat, err = cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: h.agentPub,
	}, h.ctPriv)
	if err != nil {
		t.Fatalf("CAT: %v", err)
	}
	h.ct, err = cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: h.cat.Token, ParentIssuerKey: h.ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: h.agentPub,
	}, h.ctPriv)
	if err != nil {
		t.Fatalf("CT: %v", err)
	}

	h.l, err = ledger.Get("xrpl")
	if err != nil {
		t.Fatal(err)
	}
	h.tc = ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "5000", Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: h.ct.Token, ParentIssuerKey: h.ctPub,
		HolderPublicKey: h.agentPub, Ledger: h.l, Txn: h.tc,
	}, h.ttsPriv)
	if err != nil {
		t.Fatalf("SPT-Txn: %v", err)
	}
	proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}

	h.eng = verifier.New(reg)
	h.in = verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CT: h.ct.Token, CAT: h.cat.Token, Txn: h.tc, Audience: aud,
	}
	return h
}

func mustDeny(t *testing.T, d verifier.Decision, step int) {
	t.Helper()
	if d.Allow {
		t.Fatalf("expected deny at step %d, got allow", step)
	}
	if d.Step != step {
		t.Fatalf("expected deny at step %d (%s), got step %d (%s): %s",
			step, "", d.Step, d.StepName, d.Reason)
	}
}

func TestVerify_AllowsValidChain(t *testing.T) {
	h := build(t)
	d := h.eng.Verify(context.Background(), h.in)
	if !d.Allow {
		t.Fatalf("valid chain must be allowed; denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

func TestVerify_Step1_BadSignature(t *testing.T) {
	h := build(t)
	// Corrupt the FIRST character of the signature segment (always significant,
	// unlike the last base64url char of a 64-byte signature whose low bits are
	// padding).
	b := []byte(h.in.TxnToken)
	dot := len(b) - 1
	for dot >= 0 && b[dot] != '.' {
		dot--
	}
	sig0 := dot + 1
	if b[sig0] == 'A' {
		b[sig0] = 'B'
	} else {
		b[sig0] = 'A'
	}
	h.in.TxnToken = string(b)
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 1)
}

func TestVerify_Step2_Expired(t *testing.T) {
	h := build(t)
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: h.ct.Token, ParentIssuerKey: h.ctPub,
		HolderPublicKey: h.agentPub, Ledger: h.l, Txn: h.tc, TTL: -time.Minute,
	}, h.ttsPriv)
	if err != nil {
		t.Fatal(err)
	}
	h.in.TxnToken = txn.Token
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 2)
}

func TestVerify_Step3_WrongAudience(t *testing.T) {
	h := build(t)
	h.in.Audience = "domain-x.intruder"
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 3)
}

func TestVerify_Step4_RevokedTTSKey(t *testing.T) {
	h := build(t)
	// Revoking the TTS issuer makes step 1 (which resolves the same key) the
	// decider; revocation is enforced by active-only key resolution.
	if err := h.reg.Revoke(context.Background(), issTTS, trustregistry.RoleTTSIssuer, time.Now()); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 1)
}

// A revoked CT issuer key is caught when the chain resolves its key at step 6,
// since Lookup returns only active records — not via an unverified pre-check.
func TestVerify_RevokedCTKey_DeniedAtChain(t *testing.T) {
	h := build(t)
	if err := h.reg.Revoke(context.Background(), issCT, trustregistry.RoleCTIssuer, time.Now()); err != nil {
		t.Fatal(err)
	}
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

func TestVerify_Step5_WrongDPoPKey(t *testing.T) {
	h := build(t)
	_, rogue := genKey(t)
	proof, err := dpop.Proof(rogue, htm, htu, dpop.ATH(h.in.TxnToken)) // not the bound agent key
	if err != nil {
		t.Fatal(err)
	}
	h.in.DPoPProof = proof
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 5)
}

// Replaying the exact same token + DPoP proof must be rejected the second time
// (review H1: single-use jti).
func TestVerify_Step5_Replay(t *testing.T) {
	h := build(t)
	d1 := h.eng.Verify(context.Background(), h.in)
	if !d1.Allow {
		t.Fatalf("first presentation should be allowed; denied at step %d: %s", d1.Step, d1.Reason)
	}
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 5)
}

func TestVerify_Step6_BrokenChain(t *testing.T) {
	h := build(t)
	// A different, validly-signed CT whose jti the SPT-Txn does not reference.
	other, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: h.cat.Token, ParentIssuerKey: h.ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: h.agentPub,
	}, h.ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	h.in.CT = other.Token
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 6)
}

func TestVerify_Step7_ScopeOverflow(t *testing.T) {
	h := build(t)
	h.in.Txn.Amount = "9000" // exceeds the CT ceiling of 8000
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 7)
}

func TestVerify_Step8_ContextMismatch(t *testing.T) {
	h := build(t)
	// Within scope (amount unchanged) but a different beneficiary, so the
	// context hash no longer matches what the token bound.
	h.in.Txn.Beneficiary = "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT"
	mustDeny(t, h.eng.Verify(context.Background(), h.in), 8)
}
