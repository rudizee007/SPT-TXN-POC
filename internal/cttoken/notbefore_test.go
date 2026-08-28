package cttoken_test

import (
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// nbf (not-before) is the mirror of exp: it opens a token's validity window.
// These tests pin the ISSUANCE-side attenuation -- a child may not open before
// its parent -- which is the first piece of window-bound sub-bands. Runtime
// enforcement (now < nbf -> not yet valid) is the verifier's job, a separate
// increment. Durations stay well inside the parent CAT's 1h TTL so the exp rule
// is not what rejects a case.

// A CT may introduce a not-before window where the parent CAT declares none --
// how a day-band is placed under a month-long authority.
func TestNotBefore_CTMayIntroduceAWindow(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"}, 3)

	open := time.Now().Add(10 * time.Minute).UTC()
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
		TTL:             45 * time.Minute, // exp well after the opening, inside the CAT
		NotBefore:       open,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CT with a window: %v", err)
	}
	nbf, ok := ct.Claims["nbf"].(int64)
	if !ok || nbf != open.Unix() {
		t.Errorf("nbf claim = %v, want %d", ct.Claims["nbf"], open.Unix())
	}
}

// Absent a NotBefore, no nbf claim is emitted -- the token stays valid from
// issuance, exactly the prior behaviour. Guards against polluting every CT.
func TestNotBefore_AbsentLeavesNoClaim(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000, "currency": "USD"}, 3)

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
	if _, present := ct.Claims["nbf"]; present {
		t.Errorf("no NotBefore requested, yet an nbf claim was emitted: %v", ct.Claims["nbf"])
	}
}

// A delegated child must not open before its parent CT -- opening earlier would
// grant authority during a time the parent's window had not yet opened.
func TestNotBefore_ChildCannotOpenBeforeParent(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)
	subPub, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000, "currency": "USD"}, 3)

	parentOpen := time.Now().Add(10 * time.Minute).UTC()
	parent, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
		TTL:             45 * time.Minute,
		NotBefore:       parentOpen,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue parent CT: %v", err)
	}

	// child opening 5 minutes BEFORE the parent's window -> must be refused
	_, err = cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        parent.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 2500, "currency": "USD"},
		HolderPublicKey: subPub,
		TTL:             30 * time.Minute,
		NotBefore:       parentOpen.Add(-5 * time.Minute),
	}, issuerPriv)
	if err == nil {
		t.Fatal("a child opening before its parent must be refused")
	}
}

// A child requesting no opening inherits the parent's, so it does not become
// valid ahead of a not-yet-open parent.
func TestNotBefore_ChildInheritsParentWindow(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)
	subPub, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000, "currency": "USD"}, 3)

	parentOpen := time.Now().Add(10 * time.Minute).UTC()
	parent, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
		TTL:             45 * time.Minute,
		NotBefore:       parentOpen,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue parent CT: %v", err)
	}
	child, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer:          "domain-a.authorg",
		ParentCT:        parent.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 2500, "currency": "USD"},
		HolderPublicKey: subPub,
		TTL:             30 * time.Minute,
		// no NotBefore -> inherit the parent's opening
	}, issuerPriv)
	if err != nil {
		t.Fatalf("delegate child: %v", err)
	}
	nbf, ok := child.Claims["nbf"].(int64)
	if !ok || nbf != parentOpen.Unix() {
		t.Errorf("child nbf = %v, want inherited parent nbf %d", child.Claims["nbf"], parentOpen.Unix())
	}
}

// An empty window -- opening at or after expiry -- is refused. Here TTL puts exp
// ~20 minutes out while the opening is ~50 minutes out (still inside the CAT, so
// it is the emptiness that is caught, not exp attenuation).
func TestNotBefore_EmptyWindowRefused(t *testing.T) {
	issuerPub, issuerPriv := keypair(t)
	holderPub, _ := keypair(t)
	ctHolderPub, _ := keypair(t)
	cat := issueParentCAT(t, issuerPriv, holderPub,
		cattoken.CapabilityScope{"max_amount": 10000, "currency": "USD"}, 3)

	_, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer:          "domain-a.authorg",
		ParentCAT:       cat.Token,
		ParentIssuerKey: issuerPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: ctHolderPub,
		TTL:             20 * time.Minute,
		NotBefore:       time.Now().Add(50 * time.Minute).UTC(),
	}, issuerPriv)
	if err == nil {
		t.Fatal("an opening at or after expiry (empty window) must be refused")
	}
}
