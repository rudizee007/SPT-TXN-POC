package trustregistry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

// The operator path end to end: seed a registry, export a canonical body, sign
// it, open it verified. This is what cmd/snapshot does, exercised as a test so
// the generator and the verifier cannot drift apart unnoticed — if Sign and
// Verify ever disagree about the signing input or the digest, this goes red
// rather than one of them quietly passing.
func TestOpenVerified_TheOperatorPathRoundTrips(t *testing.T) {
	body, manifest, pub := signedFixture(t)

	reg, err := OpenVerified(manifest, body, opts(pub))
	if err != nil {
		t.Fatalf("a snapshot this repository just signed was refused: %v", err)
	}
	defer reg.Close()

	recs, err := reg.List(context.Background(), RoleCTIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("the verified registry has no ct_issuer records")
	}
}

// The acceptance criterion, at the layer every reader now shares.
func TestOpenVerified_RefusesABodyThatIsNotTheSignedBody(t *testing.T) {
	body, manifest, pub := signedFixture(t)

	raw, err := os.ReadFile(body)
	if err != nil {
		t.Fatal(err)
	}
	attacker, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := injectRecord(t, raw, attacker)
	if err := os.WriteFile(body, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = OpenVerified(manifest, body, opts(pub))
	if !errors.Is(err, trustsnapshot.ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got: %v", err)
	}
}

func TestOpenVerified_RefusesAMissingManifest(t *testing.T) {
	body, manifest, pub := signedFixture(t)
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVerified(manifest, body, opts(pub)); err == nil {
		t.Fatal("a body with no manifest was opened as a root of trust")
	}
}

// ExportBody must be deterministic, or an operator cannot diff two snapshots and
// cannot reproduce a digest they were given.
func TestExportBody_IsDeterministic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	reg := seed(t, path)
	defer reg.Close()

	first, err := reg.ExportBody()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := reg.ExportBody()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("ExportBody is not deterministic (iteration %d)", i)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func opts(pub ed25519.PublicKey) trustsnapshot.Options {
	return trustsnapshot.Options{PinnedKeys: []ed25519.PublicKey{pub}, MaxAge: time.Hour}
}

func seed(t *testing.T, path string) *PersistentRegistry {
	t.Helper()
	reg, err := NewPersistentRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []struct {
		iss  string
		role Role
	}{{"domain-a", RoleCTIssuer}, {"domain-b", RoleTTSIssuer}, {"domain-a", RoleTTSIssuer}} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(ctx, &Record{
			Iss: r.iss, Role: r.role, KeyType: KeyTypeEd25519, PublicKey: pub,
			ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(24 * time.Hour),
			Status: StatusActive,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func signedFixture(t *testing.T) (bodyPath, manifestPath string, pub ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	bodyPath = filepath.Join(dir, "registry.json")

	reg := seed(t, bodyPath)
	body, err := reg.ExportBody()
	if err != nil {
		t.Fatal(err)
	}
	ids := reg.IssuerIDs()
	_ = reg.Close()

	if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := trustsnapshot.Sign(body, "snapshot-test", time.Now(), ids, nil, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := trustsnapshot.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath = ManifestPathFor(bodyPath)
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return bodyPath, manifestPath, pub
}

func injectRecord(t *testing.T, body []byte, pub ed25519.PublicKey) []byte {
	t.Helper()
	var ff fileFormat
	if err := jsonUnmarshal(body, &ff); err != nil {
		t.Fatal(err)
	}
	ff.Records = append(ff.Records, &Record{
		Iss: "did:web:bank-issuer", Role: RoleCTIssuer, KeyType: KeyTypeEd25519, PublicKey: pub,
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(365 * 24 * time.Hour),
		Status: StatusActive,
	})
	out, err := jsonMarshalIndent(ff)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
