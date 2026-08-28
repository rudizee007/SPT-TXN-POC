package verifier_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// End-to-end: a band-CT whose window has not yet opened denies the whole chain
// at verification -- even though a TXN can still be MINTED under it, because
// cttoken.Verify stays light (signature + expiry) and the engine's per-hop
// checkChainTokenTemporal is the enforcement point. This is what makes "$3 today,
// not tomorrow's $3 today" real (VELOCITY-AND-CUMULATIVE-SPEND-DESIGN sec 3a).
func TestVerify_NotYetOpenBand_Denied(t *testing.T) {
	h := build(t)

	// A band opening in 30 minutes and expiring in 50 -- inside the CAT's 1h life.
	band, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: h.cat.Token, ParentIssuerKey: h.ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: h.agentPub,
		TTL:             50 * time.Minute,
		NotBefore:       time.Now().Add(30 * time.Minute).UTC(),
	}, h.ctPriv)
	if err != nil {
		t.Fatalf("issue band CT: %v", err)
	}

	// Minting a TXN under the not-yet-open band SUCCEEDS -- the engine, not the
	// mint, is where the window is enforced.
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: band.Token, ParentIssuerKey: h.ctPub,
		HolderPublicKey: h.agentPub, Ledger: h.l, Txn: h.tc,
	}, h.ttsPriv)
	if err != nil {
		t.Fatalf("mint TXN under a not-yet-open band should succeed at mint time: %v", err)
	}
	proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}

	d := h.eng.Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CT: band.Token, CAT: h.cat.Token, Txn: h.tc, Audience: aud,
	})
	if d.Allow {
		t.Fatal("a chain through a not-yet-open band must be denied")
	}
	if !strings.Contains(d.Reason, "not yet valid") {
		t.Errorf("want denial reason 'not yet valid', got step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}
}
