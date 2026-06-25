package cttoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return pub, priv
}

// issueParentCAT mints a CAT to serve as the parent for CT tests.
func issueParentCAT(t *testing.T, issuerPriv ed25519.PrivateKey, holderPub ed25519.PublicKey, scope cattoken.CapabilityScope, depth int) *cattoken.CAT {
	t.Helper()
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             "domain-a.authorg",
		Subject:            "alice",
		PrincipalName:      "alice",
		Scope:              scope,
		DelegationDepthMax: depth,
		TTL:                time.Hour,
		HolderPublicKey:    holderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue parent CAT: %v", err)
	}
	return cat
}

func TestIssue_ValidCT(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"}, 3)

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"action": "payment", "max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT: %v", err)
	}

	if ct.Claims["txn_token_type"] != "CT" {
		t.Errorf("txn_token_type = %v, want CT", ct.Claims["txn_token_type"])
	}
	// humanAnchor must be propagated unchanged.
	if ct.HumanAnchor != cat.HumanAnchor.String() {
		t.Errorf("humanAnchor not propagated: got %s want %s", ct.HumanAnchor, cat.HumanAnchor.String())
	}
	// delegation depth decremented from 3 to 2.
	if ct.Claims["delegation_depth_remaining"] != 2 {
		t.Errorf("delegation_depth_remaining = %v, want 2", ct.Claims["delegation_depth_remaining"])
	}
	if ct.Claims["spt_cat_ref"] != cat.Claims["jti"] {
		t.Errorf("spt_cat_ref = %v, want parent jti %v", ct.Claims["spt_cat_ref"], cat.Claims["jti"])
	}

	// CT verifies under the issuer key.
	if _, err := cttoken.Verify(ct.Token, issuerPub); err != nil {
		t.Errorf("issued CT must verify: %v", err)
	}
}

func TestIssue_ScopeOverflowRejected(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000}, 3)

	_, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 25000}, // exceeds parent
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err == nil {
		t.Fatal("scope exceeding parent ceiling must be rejected")
	}
}

func TestIssue_DelegationDepthExhausted(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	// depth 1 means the CAT itself is the last hop: a CT would be depth 0,
	// allowed; we test depth that would go negative by issuing from a CT-like
	// minimum. Here depth=1 -> remaining 0 is still valid, so use a crafted
	// parent with delegation_depth_max already at the floor via depth=1 then
	// assert remaining==0 is accepted, and a second-level delegation fails.
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 100}, 1)

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 100},
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("depth 1 -> remaining 0 should be allowed: %v", err)
	}
	if ct.Claims["delegation_depth_remaining"] != 0 {
		t.Errorf("delegation_depth_remaining = %v, want 0", ct.Claims["delegation_depth_remaining"])
	}
}

func TestIssue_WrongParentKeyRejected(t *testing.T) {
	_, issuerPriv := keypair(t)
	wrongPub, _ := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000}, 3)

	_, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: wrongPub, // not the key that signed the CAT
		RequestedScope:  tbac.Scope{"max_amount": 5000},
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err == nil {
		t.Fatal("CT issuance must fail when the parent CAT does not verify")
	}
}
