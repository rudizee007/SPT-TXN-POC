package verifier_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// issCTA is agent A's own delegation-issuer identity. In the agentic model a
// party that sub-delegates is itself a registered ct_issuer, so revoking issCTA
// collapses everything A delegated downstream without touching A's own
// capability (which was issued by the org issuer, issCT).
const issCTA = "agent-a.delegator"

// agenticChain holds a built CAT -> CT_A -> CT_B agentic delegation chain plus
// the keys needed to mint SPT-Txn tokens at either the A or B hop.
type agenticChain struct {
	reg        *trustregistry.MockRegistry
	eng        *verifier.Engine
	l          ledger.Ledger
	ttsPriv    ed25519.PrivateKey // SPT-Txn (TTS) issuer key (issTTS)
	orgPriv    ed25519.PrivateKey // org issuer key (issCT) — signs the CAT and CT_A
	ctaPriv    ed25519.PrivateKey // agent A's delegation-issuer private key (issCTA)
	ctaPub     ed25519.PublicKey
	cat        *cattoken.CAT
	ctA        *cttoken.CT // hop 1, held by agent A
	ctB        *cttoken.CT // hop 2, held by sub-agent B
	agentAPub  ed25519.PublicKey
	agentAPriv ed25519.PrivateKey
	agentBPub  ed25519.PublicKey
	agentBPriv ed25519.PrivateKey
}

func buildAgentic(t *testing.T) *agenticChain {
	t.Helper()
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	a := &agenticChain{reg: reg}

	ctPub, ctPriv := genKey(t) // org issuer (issCT) — signs CAT + CT_A
	a.ctaPub, a.ctaPriv = genKey(t)
	ttsPub, ttsPriv := genKey(t)
	a.agentAPub, a.agentAPriv = genKey(t)
	a.agentBPub, a.agentBPriv = genKey(t)

	register(t, reg, issCT, trustregistry.RoleCTIssuer, ctPub)
	register(t, reg, issCTA, trustregistry.RoleCTIssuer, a.ctaPub)
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	// Root authority for the human.
	a.cat, err = cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: a.agentAPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CAT: %v", err)
	}
	// Hop 1: org issues CT_A to agent A (remaining 2).
	a.ctA, err = cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: a.cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: a.agentAPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CT_A: %v", err)
	}
	// Hop 2: agent A delegates a narrower CT_B to sub-agent B (remaining 1),
	// signed by A's own delegation-issuer key.
	a.ctB, err = cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issCTA, ParentCT: a.ctA.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: a.agentBPub,
	}, a.ctaPriv)
	if err != nil {
		t.Fatalf("CT_B (delegate): %v", err)
	}

	a.l, err = ledger.Get("xrpl")
	if err != nil {
		t.Fatal(err)
	}
	a.eng = verifier.New(reg)
	a.ttsPriv = ttsPriv
	a.orgPriv = ctPriv
	return a
}

// txnFor mints an SPT-Txn for the given leaf CT and holder, and returns the
// token plus a matching DPoP proof — so each test presents a fresh, single-use
// proof (the verifier's replay cache rejects a reused one).
func (a *agenticChain) txnFor(t *testing.T, leafCT string, leafIssuerKey ed25519.PublicKey, holderPriv ed25519.PrivateKey, holderPub ed25519.PublicKey, tc ledger.TxnContext) (string, string) {
	t.Helper()
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: leafCT, ParentIssuerKey: leafIssuerKey,
		HolderPublicKey: holderPub, Ledger: a.l, Txn: tc,
	}, a.ttsPriv)
	if err != nil {
		t.Fatalf("SPT-Txn: %v", err)
	}
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}
	return txn.Token, proof
}

func paymentTxn(amount string) ledger.TxnContext {
	return ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      amount, Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
}

// TestAgentic_TwoHopAllows: a full human -> agent A -> sub-agent B chain, with B
// minting a per-transaction token within B's (narrowest) scope, verifies offline.
func TestAgentic_TwoHopAllows(t *testing.T) {
	a := buildAgentic(t)
	tc := paymentTxn("4000") // within CT_B's 5000 ceiling
	txn, proof := a.txnFor(t, a.ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tc)

	d := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, a.ctB.Token}, CAT: a.cat.Token,
		Txn: tc, Audience: aud,
	})
	if !d.Allow {
		t.Fatalf("two-hop agentic chain must be allowed; denied at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}

// TestAgentic_RevokeSubAgentIssuer_Cascades is the headline guarantee: revoking
// agent A's delegation authority (issCTA) immediately kills sub-agent B's action
// at the chain step — while agent A's OWN capability, issued by the org (issCT),
// keeps working. Granular, offline-enforced revocation cascade.
func TestAgentic_RevokeSubAgentIssuer_Cascades(t *testing.T) {
	a := buildAgentic(t)

	// Revoke A's delegation-issuer key.
	if err := a.reg.Revoke(context.Background(), issCTA, trustregistry.RoleCTIssuer, time.Now()); err != nil {
		t.Fatal(err)
	}

	// B's two-hop action now fails closed at the chain step (its CT_B issuer key
	// is no longer active).
	tcB := paymentTxn("4000")
	txnB, proofB := a.txnFor(t, a.ctB.Token, a.ctaPub, a.agentBPriv, a.agentBPub, tcB)
	dB := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txnB, DPoPProof: proofB, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token, a.ctB.Token}, CAT: a.cat.Token,
		Txn: tcB, Audience: aud,
	})
	if dB.Allow {
		t.Fatal("sub-agent B action must be denied after A's delegation issuer is revoked")
	}
	if dB.Step != 6 {
		t.Fatalf("expected deny at step 6 (chain), got step %d (%s): %s", dB.Step, dB.StepName, dB.Reason)
	}

	// Agent A's own one-hop action (leaf = CT_A, issued by the still-active org
	// issuer) remains valid — the cascade is scoped to A's downstream delegations.
	tcA := paymentTxn("7000") // within CT_A's 8000 ceiling
	txnA, proofA := a.txnFor(t, a.ctA.Token /*CT_A issuer=*/, keyOf(t, a.reg, issCT), a.agentAPriv, a.agentAPub, tcA)
	dA := a.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txnA, DPoPProof: proofA, HTM: htm, HTU: htu,
		CTChain: []string{a.ctA.Token}, CAT: a.cat.Token,
		Txn: tcA, Audience: aud,
	})
	if !dA.Allow {
		t.Fatalf("agent A's own capability must still be allowed; denied at step %d (%s): %s", dA.Step, dA.StepName, dA.Reason)
	}
}

// keyOf returns the active Ed25519 public key registered for (iss, ct_issuer).
func keyOf(t *testing.T, reg *trustregistry.MockRegistry, iss string) ed25519.PublicKey {
	t.Helper()
	rec, err := reg.Lookup(context.Background(), iss, trustregistry.RoleCTIssuer)
	if err != nil {
		t.Fatalf("lookup %s: %v", iss, err)
	}
	return ed25519.PublicKey(rec.PublicKey)
}
