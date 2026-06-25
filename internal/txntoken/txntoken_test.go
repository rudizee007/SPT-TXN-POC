package txntoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
	"github.com/violetskysecurity/spt-txn-poc/internal/txntoken"
)

func kp(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// buildChain issues CAT -> CT and returns the CT token plus the agent
// (holder) keypair bound to it, and the ct_issuer public key.
func buildChain(t *testing.T) (ctToken string, ctIssuerPub ed25519.PublicKey, agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey) {
	t.Helper()
	ctIssuerPub, ctIssuerPriv := kp(t)
	agentPub, agentPriv = kp(t)

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             "domain-a.authorg",
		Subject:            "alice",
		PrincipalName:      "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3,
		TTL:                time.Hour,
		HolderPublicKey:    agentPub,
	}, ctIssuerPriv)
	if err != nil {
		t.Fatalf("CAT: %v", err)
	}

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: ctIssuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub, // same agent carries the capability
	}, ctIssuerPriv)
	if err != nil {
		t.Fatalf("CT: %v", err)
	}
	return ct.Token, ctIssuerPub, agentPub, agentPriv
}

func xrplTxn() (ledger.Ledger, ledger.TxnContext) {
	l, _ := ledger.Get("xrpl")
	tc := ledger.TxnContext{
		Chain:       "xrpl",
		Originator:  "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "5000",
		Currency:    "USD",
		Timestamp:   1750000000,
		Extra:       map[string]string{"DestinationTag": "42"},
	}
	return l, tc
}

func TestIssue_FullChainAndVerify(t *testing.T) {
	ctToken, ctIssuerPub, agentPub, agentPriv := buildChain(t)
	ttsPub, ttsPriv := kp(t)
	l, tc := xrplTxn()

	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer:          "domain-a.tts",
		Audience:        "domain-b.execorg",
		ParentCT:       ctToken,
		ParentIssuerKey: ctIssuerPub,
		HolderPublicKey: agentPub,
		Ledger:          l,
		Txn:             tc,
	}, ttsPriv)
	if err != nil {
		t.Fatalf("issue SPT-Txn: %v", err)
	}

	// Type and 30s lifetime.
	if txn.Claims["txn_token_type"] != "TXN" {
		t.Errorf("type = %v, want TXN", txn.Claims["txn_token_type"])
	}
	if d := txn.ExpiresAt.Sub(txn.IssuedAt); d != txntoken.DefaultTTL {
		t.Errorf("TTL = %v, want %v", d, txntoken.DefaultTTL)
	}
	if txn.Claims["spt_txn_chain"] != "xrpl" {
		t.Errorf("chain = %v, want xrpl", txn.Claims["spt_txn_chain"])
	}

	// Signature verifies under the TTS key.
	claims, err := txntoken.Verify(txn.Token, ttsPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Step 8: context hash recomputes from the same transaction.
	if err := txntoken.VerifyContextHash(claims, tc); err != nil {
		t.Errorf("context hash must verify: %v", err)
	}
	// Tampered amount must break the binding.
	bad := tc
	bad.Amount = "9999"
	if err := txntoken.VerifyContextHash(claims, bad); err == nil {
		t.Error("tampered transaction must fail context-hash check")
	}

	// Step 5: DPoP sender constraint.
	proof, err := dpop.Proof(agentPriv, "POST", "https://foss.violetskysecurity.com/b/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	jkt, _, err := dpop.Verify(proof, "POST", "https://foss.violetskysecurity.com/b/verify", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := txntoken.CheckSenderConstraint(claims, jkt); err != nil {
		t.Errorf("sender constraint must hold for the bound agent key: %v", err)
	}
	// A different key must fail the sender constraint.
	otherPub, _ := kp(t)
	if err := txntoken.CheckSenderConstraint(claims, dpop.Thumbprint(otherPub)); err == nil {
		t.Error("sender constraint must fail for a non-bound key")
	}
}

func TestIssue_TxnExceedsCapability(t *testing.T) {
	ctToken, ctIssuerPub, agentPub, _ := buildChain(t) // CT ceiling 8000
	_, ttsPriv := kp(t)
	l, tc := xrplTxn()
	tc.Amount = "9000" // over the 8000 capability ceiling

	_, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer:          "domain-a.tts",
		Audience:        "domain-b.execorg",
		ParentCT:       ctToken,
		ParentIssuerKey: ctIssuerPub,
		HolderPublicKey: agentPub,
		Ledger:          l,
		Txn:             tc,
	}, ttsPriv)
	if err == nil {
		t.Fatal("transaction exceeding capability ceiling must be rejected")
	}
}

func TestIssue_WrongHolderRejected(t *testing.T) {
	ctToken, ctIssuerPub, _, _ := buildChain(t)
	_, ttsPriv := kp(t)
	wrongPub, _ := kp(t) // not the agent bound to the CT
	l, tc := xrplTxn()

	_, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer:          "domain-a.tts",
		Audience:        "domain-b.execorg",
		ParentCT:       ctToken,
		ParentIssuerKey: ctIssuerPub,
		HolderPublicKey: wrongPub,
		Ledger:          l,
		Txn:             tc,
	}, ttsPriv)
	if err == nil {
		t.Fatal("holder key not matching the capability must break the sender-constraint chain")
	}
}

func TestIssue_ExpiredTokenFailsVerify(t *testing.T) {
	ctToken, ctIssuerPub, agentPub, _ := buildChain(t)
	ttsPub, ttsPriv := kp(t)
	l, tc := xrplTxn()

	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer:          "domain-a.tts",
		Audience:        "domain-b.execorg",
		ParentCT:       ctToken,
		ParentIssuerKey: ctIssuerPub,
		HolderPublicKey: agentPub,
		Ledger:          l,
		Txn:             tc,
		TTL:             1 * time.Nanosecond,
	}, ttsPriv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := txntoken.Verify(txn.Token, ttsPub); err == nil {
		t.Error("expired SPT-Txn Token must fail verification")
	}
}
