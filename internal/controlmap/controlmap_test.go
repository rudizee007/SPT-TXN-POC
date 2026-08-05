package controlmap

import (
	"crypto/ed25519"
	"testing"

	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

func signedReceipt(t *testing.T, decision, class, rule string, intent string) receipt.Receipt {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receipt.New("pep.test", decision, class, rule, receipt.TokenHash("tok"), receipt.TokenHash("policy"))
	if err != nil {
		t.Fatal(err)
	}
	r.IntentDigest = intent
	r.Jurisdiction = "EU-DORA"
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return *r
}

func hasControl(rows []EvidenceRow, fw, id string) bool {
	for _, r := range rows {
		if r.Framework == fw && r.ControlID == id {
			return true
		}
	}
	return false
}

func TestPermitEvidencesAccessAndAudit(t *testing.T) {
	r := signedReceipt(t, receipt.DecisionPermit, receipt.ClassOK, "authorize.ok", "abc")
	rows := Rows(r, "rh-abc", "")
	if !hasControl(rows, "NIST-SP-800-53", "AC-3") {
		t.Error("permit missing AC-3 access enforcement")
	}
	if !hasControl(rows, "NIST-SP-800-53", "AU-10") {
		t.Error("permit missing AU-10 non-repudiation")
	}
	if !hasControl(rows, "NIST-SP-800-53", "AC-4") {
		t.Error("intent-bound receipt missing AC-4 info-flow enforcement")
	}
	// Every row must carry the receipt hash (the proof anchor).
	for _, row := range rows {
		if row.ReceiptHash == "" {
			t.Fatal("evidence row missing receipt hash")
		}
	}
}

func TestViolationEvidencesLeastPrivilege(t *testing.T) {
	r := signedReceipt(t, receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch", "")
	rows := Rows(r, "rh", "")
	if !hasControl(rows, "NIST-SP-800-53", "AC-6") {
		t.Error("violation deny missing AC-6 least privilege")
	}
	if hasControl(rows, "NIST-SP-800-53", "AC-4") {
		t.Error("no-intent receipt should not evidence AC-4")
	}
}

func TestUnavailableEvidencesFailClosed(t *testing.T) {
	r := signedReceipt(t, receipt.DecisionDeny, receipt.ClassUnavailable, "token.verify-unavailable", "")
	rows := Rows(r, "rh", "")
	if !hasControl(rows, "NIST-SP-800-53", "SC-24") {
		t.Error("unavailable deny missing SC-24 fail-in-known-state")
	}
	if hasControl(rows, "NIST-SP-800-53", "AC-6") {
		t.Error("unavailable deny should not evidence AC-6 (that's for violations)")
	}
}

func TestFrameworkFilter(t *testing.T) {
	r := signedReceipt(t, receipt.DecisionDeny, receipt.ClassViolation, "rule", "")
	rows := Rows(r, "rh", DORA)
	if len(rows) == 0 {
		t.Fatal("no DORA rows")
	}
	for _, row := range rows {
		if row.Framework != string(DORA) {
			t.Fatalf("filter leaked framework %s", row.Framework)
		}
	}
}
