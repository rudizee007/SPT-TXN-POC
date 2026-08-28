package verify_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/pkg/verify"
)

func genPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func hasKey(set []ed25519.PublicKey, k ed25519.PublicKey) bool {
	for _, s := range set {
		if bytes.Equal(s, k) {
			return true
		}
	}
	return false
}

// TestIssuerKeys asserts the accessor returns exactly the token-issuance keys
// (CT + TTS issuers, any status) and excludes audit and escrow keys — so a
// receipt/log key can be cross-checked against the issuance keys it must differ
// from, without excluding the audit role it legitimately holds.
func TestIssuerKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "snapshot.json")

	reg, err := trustregistry.NewPersistentRegistry(path)
	if err != nil {
		t.Fatalf("NewPersistentRegistry: %v", err)
	}
	from := time.Now().UTC().Add(-time.Hour)
	until := time.Now().UTC().Add(365 * 24 * time.Hour)

	ttsPub := genPub(t)
	ctPub := genPub(t)
	auditPub := genPub(t)  // must NOT be returned (audit is what a log key is)
	escrowPub := genPub(t) // must NOT be returned (X25519 encryption key)

	mustRegister := func(iss string, role trustregistry.Role, keyType string, pub []byte) {
		if err := reg.Register(ctx, &trustregistry.Record{
			Iss: iss, Role: role, KeyType: keyType, PublicKey: pub,
			ValidFrom: from, ValidUntil: until, Status: trustregistry.StatusActive,
		}); err != nil {
			t.Fatalf("Register %s/%s: %v", iss, role, err)
		}
	}
	mustRegister("domain-a", trustregistry.RoleTTSIssuer, trustregistry.KeyTypeEd25519, ttsPub)
	mustRegister("domain-a", trustregistry.RoleCTIssuer, trustregistry.KeyTypeEd25519, ctPub)
	mustRegister("domain-a", trustregistry.RoleAudit, trustregistry.KeyTypeEd25519, auditPub)
	mustRegister("domain-a", trustregistry.RoleEscrow, trustregistry.KeyTypeX25519, escrowPub)
	// A rotated (revoked) issuer key must still be reported — reusing a retired
	// issuance key as a log key is exactly what the guard must catch.
	rotatedPub := genPub(t)
	if err := reg.Register(ctx, &trustregistry.Record{
		Iss: "domain-b", Role: trustregistry.RoleTTSIssuer, KeyType: trustregistry.KeyTypeEd25519,
		PublicKey: rotatedPub, ValidFrom: from, ValidUntil: until, Status: trustregistry.StatusRevoked,
	}); err != nil {
		t.Fatalf("Register rotated: %v", err)
	}
	_ = reg.Close()

	manifest, pub := signSnapshot(t, path, time.Now())
	v, err := verify.FromSignedSnapshot(manifest, path, freshOpts(pub))
	if err != nil {
		t.Fatalf("FromSignedSnapshot: %v", err)
	}
	keys, err := v.IssuerKeys(ctx)
	if err != nil {
		t.Fatalf("IssuerKeys: %v", err)
	}

	if !hasKey(keys, ttsPub) {
		t.Error("TTS issuer key missing from IssuerKeys")
	}
	if !hasKey(keys, ctPub) {
		t.Error("CT issuer key missing from IssuerKeys")
	}
	if !hasKey(keys, rotatedPub) {
		t.Error("rotated/revoked issuer key must still be reported (a retired issuance key must not be reusable as a log key)")
	}
	if hasKey(keys, auditPub) {
		t.Error("audit key must NOT be reported as an issuer key — it is what a log/receipt key legitimately is")
	}
	if hasKey(keys, escrowPub) {
		t.Error("escrow key must NOT be reported as an issuer key")
	}
}
