package verifier_test

// Sub-band chains and single-use records. The mutation script
// scripts/mutate-chain-guards.sh reverts each control here and requires the
// matching test to fail. These run against the real engine, cattoken, cttoken
// and txntoken packages.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

// budgetWorld is a CAT whose budget is 100 USD cumulative, committed to one
// division of ten 10-USD bands, the first of which is live now.
type budgetWorld struct {
	reg            *trustregistry.MockRegistry
	eng            *verifier.Engine
	ctPub          ed25519.PublicKey
	ctPriv         ed25519.PrivateKey
	ttsPriv        ed25519.PrivateKey
	agentPub       ed25519.PublicKey
	agentPriv      ed25519.PrivateKey
	cat            *cattoken.CAT
	bands          []tbac.Band
	divNbf, divExp int64
	l              ledger.Ledger
}

func buildBudgetWorld(t *testing.T, committed bool) *budgetWorld {
	t.Helper()
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	w := &budgetWorld{reg: reg}
	w.ctPub, w.ctPriv = genKey(t)
	ttsPub, ttsPriv := genKey(t)
	w.ttsPriv = ttsPriv
	w.agentPub, w.agentPriv = genKey(t)
	register(t, reg, issCT, trustregistry.RoleCTIssuer, w.ctPub)
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	now := time.Now().Unix()
	w.divNbf, w.divExp = now-10, now+10*3600
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "max_amount": 100, "currency": "USD"}
	for i := 0; i < 10; i++ {
		w.bands = append(w.bands, tbac.Band{
			Scope:     tbac.Scope{"max_cumulative": 10, "currency": "USD"},
			NotBefore: now - 10 + int64(i)*3600, Expiry: now - 10 + int64(i+1)*3600,
		})
	}
	req := cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: 11 * time.Hour, HolderPublicKey: w.agentPub,
	}
	if committed {
		root, _, _, err := tbac.CommitBandDivision(tbac.SuiteSHA3_256, tbac.Scope(budget), w.divNbf, w.divExp, w.bands)
		if err != nil {
			t.Fatal(err)
		}
		req.SubbandGroupRoot = root[:]
		req.SubbandGroupSize = 10
		req.SubbandHashSuite = tbac.SuiteSHA3_256
	}
	w.cat, err = cattoken.Issue(req, w.ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	w.l, _ = ledger.Get("xrpl")
	w.eng = verifier.New(reg)
	return w
}

func (w *budgetWorld) slices(t *testing.T) []*cttoken.CT {
	t.Helper()
	slices, err := cttoken.IssueSubbands(cttoken.SubbandIssueRequest{
		Issuer: issCT, ParentCAT: w.cat.Token, ParentIssuerKey: w.ctPub,
		HashSuite: tbac.SuiteSHA3_256, DivisionNbf: w.divNbf, DivisionExp: w.divExp,
		Bands: w.bands, HolderPublicKeys: []ed25519.PublicKey{w.agentPub},
	}, w.ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	return slices
}

// mintTxn mints an SPT-Txn under ct for amount, with a fresh DPoP proof.
func (w *budgetWorld) mintTxn(t *testing.T, ct, amount string) verifier.Input {
	t.Helper()
	tc := paymentTxn(amount)
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct, ParentIssuerKey: w.ctPub,
		HolderPublicKey: w.agentPub, Ledger: w.l, Txn: tc,
	}, w.ttsPriv)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	proof, err := dpop.Proof(w.agentPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}
	return verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CT: ct, CAT: w.cat.Token, Txn: tc, Audience: aud,
	}
}

// plainCTUnsafe mints an ordinary CT (no max_cumulative) under the world's CAT
// without going through cttoken.Issue's own refusal: a NON-CONFORMING issuer
// holding the registered key. The verifier must refuse the chain on its own —
// a check that exists only at the issuer is hygiene, not enforcement.
//
// Built by minting a valid CT under an unbudgeted twin CAT (same keys, same
// holder, same anchor) and re-pointing its parent bindings at the budgeted CAT,
// re-signed with the real CT issuer key — the same technique forgedChain uses.
func (w *budgetWorld) plainCTUnsafe(t *testing.T) string {
	t.Helper()
	twin, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"max_amount": 100, "currency": "USD"},
		DelegationDepthMax: 3, TTL: 11 * time.Hour, HolderPublicKey: w.agentPub,
	}, w.ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: twin.Token, ParentIssuerKey: w.ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 100, "currency": "USD"},
		HolderPublicKey: w.agentPub, TTL: time.Hour,
	}, w.ctPriv)
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeClaims(t, ct.Token)
	catClaims := decodeClaims(t, w.cat.Token)
	sum := sha256.Sum256([]byte(w.cat.Token))
	claims["spt_parent_hash"] = base64.RawURLEncoding.EncodeToString(sum[:])
	claims["spt_cat_ref"] = catClaims["jti"]
	claims["human_anchor"] = catClaims["human_anchor"]
	return forgeToken(claims, w.ctPriv)
}

// TestChain_ChildOfBudgetedParentMustBeASlice: the CAT committed one division
// of its 100-USD budget. A child that declares no max_cumulative is not a
// slice and is refused at step 6, whether or not the issuer would have minted
// it.
func TestChain_ChildOfBudgetedParentMustBeASlice(t *testing.T) {
	w := buildBudgetWorld(t, true)

	// Issuance hygiene: the honest issuer refuses to mint it at all.
	if _, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: w.cat.Token, ParentIssuerKey: w.ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 100, "currency": "USD"},
		HolderPublicKey: w.agentPub, TTL: time.Hour,
	}, w.ctPriv); err == nil {
		t.Fatal("cttoken.Issue minted an ordinary CT under a budgeted CAT")
	}

	// Enforcement: a dishonest issuer mints it anyway; the verifier refuses.
	ct := w.plainCTUnsafe(t)
	d := w.eng.Verify(context.Background(), w.mintTxn(t, ct, "100"))
	if d.Allow {
		t.Fatal("a non-slice child of a budgeted CAT was allowed")
	}
	if d.Step != 6 || !strings.Contains(d.Reason, "budget") {
		t.Fatalf("expected a step-6 sub-band refusal, got step %d: %s", d.Step, d.Reason)
	}
}

// TestChain_DeclaredBudgetWithoutDivisionHasNoChildren: a CAT that declares
// max_cumulative but committed no division authorizes no children at all.
func TestChain_DeclaredBudgetWithoutDivisionHasNoChildren(t *testing.T) {
	w := buildBudgetWorld(t, false)
	ct := w.plainCTUnsafe(t)
	d := w.eng.Verify(context.Background(), w.mintTxn(t, ct, "100"))
	if d.Allow {
		t.Fatal("a child of a CAT that declares a budget but committed no division was allowed")
	}
	if d.Step != 6 {
		t.Fatalf("expected step 6, got %d: %s", d.Step, d.Reason)
	}
}

// TestSingleUse_Slice: a genuine 10-USD slice authorizes ONE transaction at
// this enforcement point.
func TestSingleUse_Slice(t *testing.T) {
	w := buildBudgetWorld(t, true)
	slices := w.slices(t)

	if d := w.eng.Verify(context.Background(), w.mintTxn(t, slices[0].Token, "10")); !d.Allow {
		t.Fatalf("first use of a live slice denied at step %d: %s", d.Step, d.Reason)
	}
	d := w.eng.Verify(context.Background(), w.mintTxn(t, slices[0].Token, "10"))
	if d.Allow {
		t.Fatal("the same slice authorized a second transaction (fresh SPT-Txn, fresh DPoP proof)")
	}
	if d.Step != 8 || !strings.Contains(d.Reason, "already used") {
		t.Fatalf("expected the single-use refusal, got step %d: %s", d.Step, d.Reason)
	}
}

// TestSingleUse_SliceIdentityIsTheCommittedTuple: the issuer mints the same
// division twice (fresh jti, same tuple). Membership verifies for both — it is
// a property of the tuple — so the consumption record is keyed on the
// committed root and leg, never the jti.
func TestSingleUse_SliceIdentityIsTheCommittedTuple(t *testing.T) {
	w := buildBudgetWorld(t, true)
	first := w.slices(t)
	second := w.slices(t)
	if first[0].Token == second[0].Token {
		t.Fatal("test precondition: the two mints must be distinct tokens")
	}
	if d := w.eng.Verify(context.Background(), w.mintTxn(t, first[0].Token, "10")); !d.Allow {
		t.Fatalf("first batch slice 0 denied: %s", d.Reason)
	}
	d := w.eng.Verify(context.Background(), w.mintTxn(t, second[0].Token, "10"))
	if d.Allow {
		t.Fatal("a re-minted copy of a consumed slice was allowed")
	}
}

// TestSingleUse_SPTTxn: one transaction token, one transaction, even with a
// fresh DPoP proof (which the holder can always make).
func TestSingleUse_SPTTxn(t *testing.T) {
	h := build(t)
	if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
		t.Fatalf("first presentation denied: %v", d)
	}
	again := h.in
	proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(h.in.TxnToken))
	if err != nil {
		t.Fatal(err)
	}
	again.DPoPProof = proof
	d := h.eng.Verify(context.Background(), again)
	if d.Allow {
		t.Fatal("the same SPT-Txn was allowed twice with a fresh proof")
	}
	if d.Step != 8 || !strings.Contains(d.Reason, "already used") {
		t.Fatalf("expected the single-use refusal at step 8, got step %d: %s", d.Step, d.Reason)
	}
}

// TestSingleUse_Settlement: the settle path has no DPoP step; it records the
// SPT-Txn itself. A settlement is the use.
func TestSingleUse_Settlement(t *testing.T) {
	h := build(t)
	facts, d := h.eng.VerifyForSettlement(context.Background(), h.in)
	if !d.Allow {
		t.Fatalf("first settlement verify denied: %v", d)
	}
	if facts.NotAfter == 0 {
		t.Fatal("SettlementFacts.NotAfter is zero: a settler cannot bound its window by the token")
	}
	for i := 0; i < 4; i++ {
		if _, d := h.eng.VerifyForSettlement(context.Background(), h.in); d.Allow {
			t.Fatalf("identical settlement presentation %d accepted again", i+2)
		}
	}
}

// TestSingleUse_RefusalBurnsNothing: a presentation refused at any earlier step
// must not consume the token: a presentation with a bad proof must leave the
// holder's own presentation usable.
func TestSingleUse_RefusalBurnsNothing(t *testing.T) {
	h := build(t)
	bad := h.in
	bad.DPoPProof = "" // fails step 5
	if d := h.eng.Verify(context.Background(), bad); d.Allow || d.Step != 5 {
		t.Fatalf("expected a step-5 refusal, got %v", d)
	}
	if d := h.eng.Verify(context.Background(), h.in); !d.Allow {
		t.Fatalf("a refused presentation consumed the token: %v", d)
	}
}

// TestSingleUse_ConcurrentPresentationsAllowExactlyOne: two presentations of
// the same token racing through the engine must not both pass — the record is
// check-then-set under one lock.
func TestSingleUse_ConcurrentPresentationsAllowExactlyOne(t *testing.T) {
	h := build(t)
	const n = 64
	inputs := make([]verifier.Input, n)
	for i := range inputs {
		in := h.in
		proof, err := dpop.Proof(h.agentPriv, htm, htu, dpop.ATH(h.in.TxnToken))
		if err != nil {
			t.Fatal(err)
		}
		in.DPoPProof = proof
		inputs[i] = in
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(in verifier.Input) {
			defer wg.Done()
			if h.eng.Verify(context.Background(), in).Allow {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}(inputs[i])
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("%d of %d concurrent presentations of one SPT-Txn were allowed; want exactly 1", allowed, n)
	}
}

// TestSettlementFacts_ReportsTheTighterCeiling: a slice's cumulative
// budget is the ceiling TxnScope projects at spend; a settler pinning its cap
// to MaxAmount alone pins the wrong number. Both are reported.
func TestSettlementFacts_ReportsTheTighterCeiling(t *testing.T) {
	w := buildBudgetWorld(t, true)
	slices := w.slices(t)
	facts, d := w.eng.VerifyForSettlement(context.Background(), w.mintTxn(t, slices[0].Token, "10"))
	if !d.Allow {
		t.Fatalf("denied: %v", d)
	}
	if facts.MaxCumulative != "10" {
		t.Fatalf("MaxCumulative = %q, want 10", facts.MaxCumulative)
	}
}
