package cttoken_test

import (
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// A delegator that narrows only the amount says nothing about the unit.
// Containment permits dropping the currency, but a CT sealed that way would
// carry a ceiling that bounds the amount in EVERY currency. The issuer carries
// the parent's unit down with the ceiling instead.
func TestIssue_CarriesParentCurrencyDownWithTheCeiling(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"}, 3)

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000}, // currency not requested
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("narrowing only the amount must remain a legitimate request: %v", err)
	}

	scope, ok := ct.Claims["capability_scope"].(map[string]any)
	if !ok {
		t.Fatalf("CT has no capability_scope: %v", ct.Claims)
	}
	if scope["currency"] != "USD" {
		t.Fatalf("sealed ceiling is not denominated: capability_scope = %v", scope)
	}
	if _, ok := scope["max_amount"]; !ok {
		t.Fatalf("the requested ceiling was lost: capability_scope = %v", scope)
	}
}

// Inheriting the unit must never override a unit the child asked for, and must
// never let the child pick a different one (that is a widening, and containment
// already refuses it).
func TestIssue_RequestedCurrencyIsNotOverriddenAndCannotDiffer(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)

	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"}, 3)

	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT: %v", err)
	}
	scope := ct.Claims["capability_scope"].(map[string]any)
	if scope["currency"] != "USD" {
		t.Fatalf("requested currency was not preserved: %v", scope)
	}

	if _, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "EUR"},
		HolderPublicKey: ctHolderPub,
	}, issuerPriv); err == nil {
		t.Fatal("a child changed the currency of its parent's ceiling")
	}
}
