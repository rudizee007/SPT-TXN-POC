package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
	"github.com/rudizee007/spt-txn-poc/pkg/verify"
)

const slURI = "https://status.example/lists/1"

func newList(t *testing.T, revoke ...int) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l, err := statuslist.New(2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range revoke {
		if err := l.Set(i, statuslist.StatusInvalid); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := statuslist.SignToken(l, slURI, time.Now(), time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok, pub
}

func loadedVerifier(t *testing.T) *verify.Verifier {
	t.Helper()
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())
	v, err := verify.FromSignedSnapshot(manifest, body, freshOpts(pub))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The finding: revocation was unreachable through this package. The engine field
// existed and only cmd/spt-demo ever set it, so every embedder — including the
// reference gateway — ran with revocation off and no way to turn it on.
func TestEnableRevocation_IsReachableAndReportsItsPosture(t *testing.T) {
	v := loadedVerifier(t)

	if v.RevocationEnabled() {
		t.Fatal("a freshly loaded verifier claims to check revocation before any list is installed")
	}

	tok, pub := newList(t, 7)
	if err := v.EnableRevocation(time.Now(), verify.StatusList{Token: tok, URI: slURI, Key: pub}); err != nil {
		t.Fatalf("EnableRevocation: %v", err)
	}
	if !v.RevocationEnabled() {
		t.Fatal("revocation was installed and the verifier still reports it off")
	}
}

// Enabling with nothing installed would deny every token carrying a status
// claim. Refusing to do that is not politeness — it stops an operator turning
// revocation "on" and quietly breaking every request.
func TestEnableRevocation_RefusesAnEmptyInstall(t *testing.T) {
	v := loadedVerifier(t)
	if err := v.EnableRevocation(time.Now()); err == nil {
		t.Fatal("enabling revocation with no lists was accepted")
	}
	if v.RevocationEnabled() {
		t.Fatal("a failed install left revocation enabled")
	}
}

// A list this verifier cannot check is not installed, and a partial install must
// not leave the verifier half-configured.
func TestEnableRevocation_RefusesUncheckableLists(t *testing.T) {
	tok, pub := newList(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for name, l := range map[string]verify.StatusList{
		"wrong key":     {Token: tok, URI: slURI, Key: otherPub},
		"wrong uri":     {Token: tok, URI: "https://status.example/lists/2", Key: pub},
		"no uri":        {Token: tok, URI: "", Key: pub},
		"short key":     {Token: tok, URI: slURI, Key: ed25519.PublicKey{1, 2, 3}},
		"garbage token": {Token: "not.a.jwt", URI: slURI, Key: pub},
		"empty token":   {Token: "", URI: slURI, Key: pub},
	} {
		t.Run(name, func(t *testing.T) {
			v := loadedVerifier(t)
			if err := v.EnableRevocation(time.Now(), l); err == nil {
				t.Fatal("an uncheckable status list was installed")
			}
			if v.RevocationEnabled() {
				t.Fatal("a failed install left revocation enabled")
			}
		})
	}
}

// An expired list must not install. A verifier holding one would be enforcing
// against revocation state it has no reason to believe is current.
func TestEnableRevocation_RefusesAnExpiredList(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l, err := statuslist.New(2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := statuslist.SignToken(l, slURI, time.Now().Add(-48*time.Hour), time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}

	v := loadedVerifier(t)
	if err := v.EnableRevocation(time.Now(), verify.StatusList{Token: tok, URI: slURI, Key: pub}); err == nil {
		t.Fatal("an expired status list was installed")
	}
}
