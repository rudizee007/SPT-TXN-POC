package regdisclosure

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/audit"
	"github.com/violetskysecurity/spt-txn-poc/internal/sdjwt"
)

func entries(n int) []audit.Entry {
	es := make([]audit.Entry, n)
	for i := range es {
		h := sha256.Sum256([]byte(fmt.Sprintf("audit-%d", i)))
		es[i] = audit.Entry{Seq: uint64(i), Type: "verify_decision", Hash: h[:]}
	}
	return es
}

func TestRegDisclosure_BuildAndVerify(t *testing.T) {
	issPub, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	auditPub, auditPriv, _ := ed25519.GenerateKey(rand.Reader)

	claims := map[string]any{
		"given_name": "Alice",
		"surname":    "Smith",
		"dob":        "1990-01-01",
	}
	combined, err := sdjwt.Issue("issuer.example", claims, issPriv, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	es := entries(5)
	root := audit.PublishRoot(es, auditPriv)

	// Authority is entitled only to the surname.
	req := Request{Fields: []string{"surname"}, LegalBasis: "order-2026-42", Requester: "FIU-LU"}
	pkg, err := Build(combined, issPub, req, es, 2, root)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if _, ok := pkg.Disclosed["surname"]; !ok {
		t.Fatalf("surname not disclosed: %v", pkg.Disclosed)
	}
	if _, leaked := pkg.Disclosed["dob"]; leaked {
		t.Fatalf("dob leaked — disclosure not minimal: %v", pkg.Disclosed)
	}

	if err := pkg.Verify(issPub, auditPub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRegDisclosure_TamperedEntryFails(t *testing.T) {
	issPub, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	auditPub, auditPriv, _ := ed25519.GenerateKey(rand.Reader)
	combined, _ := sdjwt.Issue("iss", map[string]any{"surname": "Smith"}, issPriv, time.Hour)

	es := entries(4)
	root := audit.PublishRoot(es, auditPriv)
	pkg, err := Build(combined, issPub, Request{Fields: []string{"surname"}, LegalBasis: "x", Requester: "y"}, es, 1, root)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	bad := sha256.Sum256([]byte("forged"))
	pkg.Entry.Hash = bad[:]
	if err := pkg.Verify(issPub, auditPub); err == nil {
		t.Fatal("expected verify to fail on tampered audit entry")
	}
}

func TestRegDisclosure_WrongAuditKeyFails(t *testing.T) {
	issPub, issPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, auditPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	combined, _ := sdjwt.Issue("iss", map[string]any{"surname": "Smith"}, issPriv, time.Hour)

	es := entries(3)
	root := audit.PublishRoot(es, auditPriv)
	pkg, _ := Build(combined, issPub, Request{Fields: []string{"surname"}, LegalBasis: "x", Requester: "y"}, es, 0, root)

	if err := pkg.Verify(issPub, otherPub); err == nil {
		t.Fatal("expected verify to fail under the wrong audit key")
	}
}
