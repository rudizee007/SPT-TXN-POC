package cttoken_test

// TTL monotonicity at construction: docs/spec/DELEGATION-INTENT-MCP.md §1.2.

import (
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

func TestIssue_ExplicitTTLBeyondParentRejected(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holder, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holder,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 1000, "currency": "USD"}, 2)

	_, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 500},
		HolderPublicKey: holder,
		TTL:             48 * time.Hour, // parent CAT lives 1h
	}, issuerPriv)
	if err == nil {
		t.Fatal("CT outliving its parent CAT was issued")
	}
}

func TestIssue_DefaultTTLClampsToParent(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holder, _ := keypair(t)
	// Short-lived CAT: shorter than cttoken.DefaultTTL (10 minutes).
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer:             "domain-a.authorg",
		Subject:            "alice",
		PrincipalName:      "alice",
		Scope:              cattoken.CapabilityScope{"max_amount": 1000, "currency": "USD"},
		DelegationDepthMax: 2,
		TTL:                2 * time.Minute,
		HolderPublicKey:    holder,
	}, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 500},
		HolderPublicKey: holder,
		// TTL zero → default → must clamp to the CAT's remaining life.
	}, issuerPriv)
	if err != nil {
		t.Fatalf("default-TTL issuance under short parent failed: %v", err)
	}
	if ct.ExpiresAt.After(cat.ExpiresAt) {
		t.Fatalf("default TTL not clamped: CT exp %v > CAT exp %v", ct.ExpiresAt, cat.ExpiresAt)
	}
}

func TestDelegate_ExplicitTTLBeyondParentRejected(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderA, _ := keypair(t)
	holderB, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderA,
		cattoken.CapabilityScope{"max_amount": 1000, "currency": "USD"}, 3)
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 800},
		HolderPublicKey: holderA,
		TTL:             5 * time.Minute,
	}, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        ctA.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 100},
		HolderPublicKey: holderB,
		TTL:             time.Hour, // parent CT lives 5 minutes
	}, issuerPriv)
	if err == nil {
		t.Fatal("delegated CT outliving its parent CT was issued")
	}
}
