package pepevidence

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/rudizee007/spt-txn-pep/evidence"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// The adapter passes decision and class values straight through rather than
// mapping them. That is only sound while both modules use the same strings, so
// assert it: if either side ever renames a constant, this test fails instead of
// the adapter silently writing a receipt with a vocabulary the spec does not
// define.
func TestVocabulariesAreIdentical(t *testing.T) {
	pairs := []struct{ name, pep, engine string }{
		{"permit", evidence.Permit, receipt.DecisionPermit},
		{"deny", evidence.Deny, receipt.DecisionDeny},
		{"ok", evidence.ClassOK, receipt.ClassOK},
		{"violation", evidence.ClassViolation, receipt.ClassViolation},
		{"unavailable", evidence.ClassUnavailable, receipt.ClassUnavailable},
	}
	for _, p := range pairs {
		if p.pep != p.engine {
			t.Errorf("%s: pep %q != engine %q — the adapter would need a mapping", p.name, p.pep, p.engine)
		}
	}
}

func newEmitter(t *testing.T) (*Emitter, *audit.Log, ed25519.PublicKey) {
	t.Helper()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	em, err := New(log, priv)
	if err != nil {
		t.Fatalf("new emitter: %v", err)
	}
	return em, log, pub
}

func TestEmitRecordsAPermitAndReturnsItsHash(t *testing.T) {
	em, log, _ := newEmitter(t)

	loc, err := em.Emit(evidence.Receipt{
		PEP:        "gateway/test",
		Decision:   evidence.Permit,
		Class:      evidence.ClassOK,
		RulePath:   "policy/allow",
		TokenHash:  receipt.TokenHash("a-compact-token"),
		PolicyHash: "cGxhY2Vob2xkZXI",
	})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if loc == "" {
		t.Fatal("emit returned an empty locator")
	}

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("want 1 log entry, got %d", len(entries))
	}
	if entries[0].Subject != loc {
		t.Errorf("log subject %q != returned locator %q", entries[0].Subject, loc)
	}
	if err := log.Verify(); err != nil {
		t.Errorf("hash chain broken after emit: %v", err)
	}
}

func TestEmitCarriesTheOptionalFields(t *testing.T) {
	em, log, _ := newEmitter(t)

	if _, err := em.Emit(evidence.Receipt{
		PEP:          "gateway/test",
		Decision:     evidence.Deny,
		Class:        evidence.ClassViolation,
		RulePath:     "policy/amount-ceiling",
		PolicyHash:   "cGxhY2Vob2xkZXI",
		IntentDigest: "aW50ZW50",
		Jurisdiction: "eu/mica",
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if n := len(log.Entries()); n != 1 {
		t.Fatalf("want 1 log entry, got %d", n)
	}
}

// A mislabeled receipt is a defect in the evidence chain. It must be refused at
// construction, and the refusal must reach the PEP as an error so the request
// is denied rather than served without sound evidence.
func TestMislabeledReceiptsAreRefusedAndNothingIsWritten(t *testing.T) {
	cases := []struct {
		name string
		in   evidence.Receipt
	}{
		{"permit with a violation class", evidence.Receipt{
			PEP: "p", Decision: evidence.Permit, Class: evidence.ClassViolation, RulePath: "r"}},
		{"deny with an ok class", evidence.Receipt{
			PEP: "p", Decision: evidence.Deny, Class: evidence.ClassOK, RulePath: "r"}},
		{"unknown decision", evidence.Receipt{
			PEP: "p", Decision: "MAYBE", Class: evidence.ClassOK, RulePath: "r"}},
		{"empty PEP identity", evidence.Receipt{
			PEP: "", Decision: evidence.Permit, Class: evidence.ClassOK, RulePath: "r"}},
		{"empty rule path", evidence.Receipt{
			PEP: "p", Decision: evidence.Permit, Class: evidence.ClassOK, RulePath: ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			em, log, _ := newEmitter(t)
			if _, err := em.Emit(c.in); err == nil {
				t.Fatal("want an error, got nil — the PEP would have served this request")
			}
			if n := len(log.Entries()); n != 0 {
				t.Errorf("a refused receipt wrote %d log entries; want 0", n)
			}
		})
	}
}

// evidence.None is the deliberate no-op. A real emitter must never be mistaken
// for it, or a deployment recording nothing would look conformant.
func TestARealEmitterIsNotDetectedAsANoop(t *testing.T) {
	em, _, _ := newEmitter(t)
	if _, isNoop := any(em).(evidence.Noop); isNoop {
		t.Fatal("the real emitter claims the no-op marker")
	}
	if _, isNoop := any(evidence.None{}).(evidence.Noop); !isNoop {
		t.Fatal("evidence.None does not claim the no-op marker")
	}
}

func TestDurableIsAsserted(t *testing.T) {
	em, _, _ := newEmitter(t)
	if !em.Durable() {
		t.Fatal("audit.Log.Append fsyncs, so Durable must report true")
	}
}
