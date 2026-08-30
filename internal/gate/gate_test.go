package gate

import (
	"context"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/escrow"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// Real-format testnet-style XRPL addresses so the ledger adapter's address
// validation passes (the values are not funded; the gate is offline).
const (
	testAgent    = "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT"
	testMerchant = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW"
)

func TestGate_AllowUnderCeiling(t *testing.T) {
	g, err := New("xrpl", testAgent, "5000", "XRP")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, err := g.Authorize(Request{Price: "1000", Currency: "XRP", PayTo: testMerchant, SourceTag: "402"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("want ALLOW for 1000 <= 5000, got DENY: %s", d.Reason)
	}
	if d.Memo == "" || d.ContextHash == "" || d.Attestation == "" {
		t.Errorf("ALLOW must carry Memo/ContextHash/Attestation, got %+v", d)
	}
	if d.Destination != testMerchant || d.Amount != "1000" {
		t.Errorf("stamp fields wrong: dest=%s amount=%s", d.Destination, d.Amount)
	}
}

func TestGate_DenyOverCeiling(t *testing.T) {
	g, err := New("xrpl", testAgent, "5000", "XRP")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, err := g.Authorize(Request{Price: "9000", Currency: "XRP", PayTo: testMerchant, SourceTag: "402"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow {
		t.Fatal("payment 9000 over ceiling 5000 must DENY")
	}
	if d.Reason == "" {
		t.Error("DENY must carry a reason")
	}
}

// TestGate_AnchorStable: the humanAnchor is fixed for the agent's standing
// capability and carried on every authorized payment.
func TestGate_AnchorStable(t *testing.T) {
	g, err := New("xrpl", testAgent, "5000", "XRP")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Anchor() == "" {
		t.Fatal("anchor must be set")
	}
	d, _ := g.Authorize(Request{Price: "1000", Currency: "XRP", PayTo: testMerchant, SourceTag: "402"})
	if d.Memo != g.Anchor() {
		t.Errorf("payment Memo %q != gate anchor %q", d.Memo, g.Anchor())
	}
}

// TestGate_BundleVerifiesAgainstIssuerRegistry does exactly what the merchant
// does in P2: rebuild a trust registry from the gate's issuer records and re-run
// the eight-step verifier on the bundle. A valid bundle passes; a tampered
// attestation fails.
func TestGate_BundleVerifiesAgainstIssuerRegistry(t *testing.T) {
	g, err := New("xrpl", testAgent, "5000", "XRP")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, err := g.Authorize(Request{Price: "1000", Currency: "XRP", PayTo: testMerchant, SourceTag: "402"})
	if err != nil || !d.Allow {
		t.Fatalf("Authorize: allow=%v err=%v", d.Allow, err)
	}

	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	for _, r := range g.IssuerRecords() {
		if err := reg.Register(context.Background(), r); err != nil {
			t.Fatalf("register issuer: %v", err)
		}
	}

	in := verifier.Input{
		TxnToken: d.Attestation, DPoPProof: d.DPoP, HTM: d.HTM, HTU: d.HTU,
		CTChain: d.CTChain, CAT: d.CAT, Txn: *d.Txn, Audience: d.Audience,
	}
	if dec := verifier.New(reg).Verify(context.Background(), in); !dec.Allow {
		t.Fatalf("merchant-side verify should ALLOW, denied at step %d (%s): %s", dec.Step, dec.StepName, dec.Reason)
	}

	// Tamper the attestation signature -> verification must fail.
	in.TxnToken = d.Attestation[:len(d.Attestation)-4] + "AAAA"
	if dec := verifier.New(reg).Verify(context.Background(), in); dec.Allow {
		t.Fatal("tampered attestation must fail merchant-side verification")
	}
}

// TestGate_SealIdentityRecoverable: the identity sealed at issuance (keyed by
// the humanAnchor) is recoverable by the escrow authority's key — the P3
// accountability path.
func TestGate_SealIdentityRecoverable(t *testing.T) {
	g, err := New("xrpl", testAgent, "5000", "XRP")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	esk, err := escrow.NewEscrowKey()
	if err != nil {
		t.Fatalf("NewEscrowKey: %v", err)
	}
	identity := "Alice Q. Public, passport ZA-X1234567"
	env, err := g.SealIdentity(esk.PublicKey(), identity)
	if err != nil {
		t.Fatalf("SealIdentity: %v", err)
	}
	if env.HumanAnchor != g.Anchor() {
		t.Errorf("envelope keyed by %q, want humanAnchor %q", env.HumanAnchor, g.Anchor())
	}
	got, err := env.Open(esk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != identity {
		t.Fatalf("recovered %q, want %q", got, identity)
	}
}
