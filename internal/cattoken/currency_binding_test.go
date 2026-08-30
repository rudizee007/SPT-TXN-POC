package cattoken_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
)

// A root CAT has no ancestor to inherit a unit from, so a monetary ceiling it
// declares must name the currency it is denominated in. Without one the ceiling
// bounds the amount in every currency at once and is not a ceiling at all.
func TestIssue_RefusesMoneyCeilingWithoutCurrency(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	for name, scope := range map[string]cattoken.CapabilityScope{
		"bare ceiling":     {"max_amount": 10000},
		"ceiling + action": {"action": "transfer", "max_amount": 10000},
		"empty currency":   {"max_amount": 10000, "currency": ""},
		"numeric currency": {"max_amount": 10000, "currency": 840},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cattoken.Issue(cattoken.IssueRequest{
				Issuer:             "domain-a.authorg",
				Subject:            "alice",
				PrincipalName:      "alice",
				Scope:              scope,
				DelegationDepthMax: 3,
				TTL:                time.Hour,
				HolderPublicKey:    holderPub,
			}, issuerPriv)
			if err == nil {
				t.Fatal("a CAT with an unqualified monetary ceiling was issued")
			}
			if !strings.Contains(err.Error(), "capability scope") {
				t.Errorf("error should name the capability scope, got: %v", err)
			}
		})
	}
}

// The check must not over-deny: scopes that declare no monetary ceiling, and
// scopes that qualify theirs, must still issue.
func TestIssue_AllowsQualifiedAndNonMonetaryScopes(t *testing.T) {
	_, issuerPriv := generateTestKeypair(t)
	holderPub, _ := generateTestKeypair(t)

	for name, scope := range map[string]cattoken.CapabilityScope{
		"qualified ceiling": {"action": "transfer", "max_amount": 10000, "currency": "USD"},
		"no ceiling":        {"action": "read"},
		"privilege tier":    {"action": "read", "tier": 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cattoken.Issue(cattoken.IssueRequest{
				Issuer:             "domain-a.authorg",
				Subject:            "alice",
				PrincipalName:      "alice",
				Scope:              scope,
				DelegationDepthMax: 3,
				TTL:                time.Hour,
				HolderPublicKey:    holderPub,
			}, issuerPriv); err != nil {
				t.Fatalf("legitimate scope refused: %v", err)
			}
		})
	}
}
