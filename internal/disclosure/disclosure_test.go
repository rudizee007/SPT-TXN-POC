package disclosure_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/disclosure"
	"github.com/violetskysecurity/spt-txn-poc/internal/sdjwt"
)

func credential(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := sdjwt.Issue("kyc-provider", map[string]any{
		"name":    "Alice Example",
		"country": "US",
		"dob":     "1990-01-01",
		"account": "GB29NWBK60161331926819",
	}, priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cred, pub
}

// Consent + scope-selection: discloses only requested ∩ consented; reports withheld.
func TestDisclosure_ConsentAndScope(t *testing.T) {
	cred, pub := credential(t)
	req, err := disclosure.NewRequest("beneficiary-vasp", "Travel Rule check", []string{"name", "country"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Holder consents to "name" only, withholding "country".
	resp, err := disclosure.Respond(req, cred, disclosure.Grant{Allow: []string{"name"}}, time.Now())
	if err != nil {
		t.Fatalf("respond: %v", err)
	}

	claims, withheld, err := disclosure.Verify(req, resp, pub, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["name"] != "Alice Example" {
		t.Errorf("name not disclosed: %v", claims["name"])
	}
	if _, ok := claims["country"]; ok {
		t.Error("country disclosed despite no consent")
	}
	if _, ok := claims["dob"]; ok {
		t.Error("unrequested field dob leaked")
	}
	if len(withheld) != 1 || withheld[0] != "country" {
		t.Errorf("withheld = %v, want [country]", withheld)
	}
}

// An expired request is refused on both the holder and verifier sides.
func TestDisclosure_Expired(t *testing.T) {
	cred, pub := credential(t)
	req := disclosure.Request{ID: "req-1", Fields: []string{"name"}, ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	if _, err := disclosure.Respond(req, cred, disclosure.Grant{Allow: []string{"name"}}, time.Now()); err == nil {
		t.Error("respond accepted an expired request")
	}
	pres, _ := sdjwt.Present(cred, []string{"name"})
	resp := disclosure.Response{RequestID: "req-1", Presentation: pres, Disclosed: []string{"name"}}
	if _, _, err := disclosure.Verify(req, resp, pub, time.Now()); err == nil {
		t.Error("verify accepted an expired request")
	}
}

// A response for a different request id is rejected.
func TestDisclosure_RequestMismatch(t *testing.T) {
	cred, pub := credential(t)
	req, _ := disclosure.NewRequest("v", "p", []string{"name"}, time.Hour)
	pres, _ := sdjwt.Present(cred, []string{"name"})
	resp := disclosure.Response{RequestID: "some-other-id", Presentation: pres, Disclosed: []string{"name"}}
	if _, _, err := disclosure.Verify(req, resp, pub, time.Now()); err == nil {
		t.Error("verify accepted a response for the wrong request")
	}
}

// Disclosing a field that was never requested is a scope violation.
func TestDisclosure_RejectsOutOfScope(t *testing.T) {
	cred, pub := credential(t)
	req, _ := disclosure.NewRequest("v", "p", []string{"name", "country"}, time.Hour)
	pres, _ := sdjwt.Present(cred, []string{"account"}) // not in the request
	resp := disclosure.Response{RequestID: req.ID, Presentation: pres, Disclosed: []string{"account"}}
	if _, _, err := disclosure.Verify(req, resp, pub, time.Now()); err == nil {
		t.Error("verify accepted an out-of-scope disclosure")
	}
}
