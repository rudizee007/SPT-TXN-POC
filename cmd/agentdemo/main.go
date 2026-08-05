// Command agentdemo is a runnable, offline demonstration of SPT-Txn agentic
// authorization (Milestone 7). It builds a human -> agent A -> sub-agent B
// delegation chain, has each party act within its (monotonically narrowing)
// scope, verifies every action offline with the eight-step engine, and then
// revokes agent A's delegation authority to show the cascade: B's actions fail
// closed while A's own capability keeps working.
//
// Nothing here contacts a network or a ledger — verification uses only the
// presented tokens and a locally-held Trust Registry snapshot.
//
//	go run ./cmd/agentdemo
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
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

const (
	issOrg = "domain-a.authorg"  // the org that authorized the human
	issA   = "agent-a.delegator" // agent A's own delegation-issuer identity
	issTTS = "domain-a.tts"      // SPT-Txn (token exchange) issuer
	aud    = "domain-b.execorg"  // the executing domain (verifier)
	htm    = "POST"
	htu    = "https://foss.violetskysecurity.com/b/verify"
)

func main() {
	ctx := context.Background()

	// ── Trust Registry snapshot (held locally by the verifier) ──────────
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		log.Fatal(err)
	}
	orgPub, orgPriv := genKey()
	aPub, aPriv := genKey() // agent A's delegation-issuer key
	ttsPub, ttsPriv := genKey()
	agentAPub, agentAPriv := genKey()
	agentBPub, agentBPriv := genKey()

	mustReg(reg, issOrg, trustregistry.RoleCTIssuer, orgPub)
	mustReg(reg, issA, trustregistry.RoleCTIssuer, aPub)
	mustReg(reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	l, err := ledger.Get("xrpl")
	if err != nil {
		log.Fatal(err)
	}
	eng := verifier.New(reg)

	// ── Build the delegation chain: human -> agent A -> sub-agent B ─────
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issOrg, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: agentAPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CAT: %v", err)
	}
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issOrg, ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentAPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CT_A: %v", err)
	}
	ctB, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issA, ParentCT: ctA.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: agentBPub,
	}, aPriv)
	if err != nil {
		log.Fatalf("CT_B (delegate): %v", err)
	}

	fmt.Println("SPT-Txn agentic authorization — offline demo")
	fmt.Println("============================================")
	fmt.Printf("  human (alice)   CAT   depth=3   ceiling=$10000   anchor=%s…\n", short(cat.HumanAnchor.String()))
	fmt.Printf("  agent A         CT_A  remaining=%v  ceiling=$8000   (issued by %s)\n", ctA.Claims["delegation_depth_remaining"], issOrg)
	fmt.Printf("  sub-agent B     CT_B  remaining=%v  ceiling=$5000   (delegated by %s)\n\n", ctB.Claims["delegation_depth_remaining"], issA)

	// ── Scenario 1: B acts within scope → ALLOW ─────────────────────────
	report("1. sub-agent B pays $4000 (within B's $5000 ceiling)",
		verify(ctx, eng, l, ttsPriv, ctB.Token, aPub, agentBPriv, agentBPub,
			[]string{ctA.Token, ctB.Token}, cat.Token, "4000"))

	// ── Scenario 2: B exceeds its scope → DENY (step 7) ─────────────────
	report("2. sub-agent B tries $6000 (exceeds B's $5000 ceiling)",
		verify(ctx, eng, l, ttsPriv, ctB.Token, aPub, agentBPriv, agentBPub,
			[]string{ctA.Token, ctB.Token}, cat.Token, "6000"))

	// ── Scenario 3: revoke A's delegation authority → B cascades to DENY ─
	if err := reg.Revoke(ctx, issA, trustregistry.RoleCTIssuer, time.Now()); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n  >> revoked agent A's delegation authority (%s)\n\n", issA)
	report("3. sub-agent B pays $4000 again, after revocation",
		verify(ctx, eng, l, ttsPriv, ctB.Token, aPub, agentBPriv, agentBPub,
			[]string{ctA.Token, ctB.Token}, cat.Token, "4000"))

	// ── Scenario 4: agent A's OWN action is unaffected → ALLOW ──────────
	report("4. agent A pays $7000 (its own capability, issued by the org)",
		verify(ctx, eng, l, ttsPriv, ctA.Token, orgPub, agentAPriv, agentAPub,
			[]string{ctA.Token}, cat.Token, "7000"))

	fmt.Println("\nThe revocation is granular and offline: cutting A's delegation key")
	fmt.Println("kills everything A handed downstream, while A's own authority stands.")
}

// verify mints an SPT-Txn for the leaf CT + holder, builds a fresh DPoP proof,
// and runs the eight-step engine. leafIssuerKey is the key the leaf CT was
// signed with (so the token-exchange issuer can verify its parent).
func verify(ctx context.Context, eng *verifier.Engine, l ledger.Ledger, ttsPriv ed25519.PrivateKey,
	leafCT string, leafIssuerKey ed25519.PublicKey, holderPriv ed25519.PrivateKey, holderPub ed25519.PublicKey,
	chain []string, catTok, amount string) verifier.Decision {

	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      amount, Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: leafCT, ParentIssuerKey: leafIssuerKey,
		HolderPublicKey: holderPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		// The token-exchange issuer enforces scope at MINT time: an honest issuer
		// will not even produce an SPT-Txn that exceeds the capability ceiling, so
		// an over-scope action is refused here rather than reaching the verifier.
		// (The verifier's step 7 is the defense-in-depth for a forged token.)
		return verifier.Decision{Allow: false, StepName: "mint", Reason: err.Error()}
	}
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		log.Fatalf("dpop: %v", err)
	}
	return eng.Verify(ctx, verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: chain, CAT: catTok, Txn: tc, Audience: aud,
	})
}

func report(label string, d verifier.Decision) {
	switch {
	case d.Allow:
		fmt.Printf("  %-58s  ALLOW\n", label)
	case d.StepName == "mint":
		fmt.Printf("  %-58s  DENY (refused at mint: scope)\n", label)
	default:
		fmt.Printf("  %-58s  DENY (step %d: %s)\n", label, d.Step, d.StepName)
	}
}

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pub, priv
}

func mustReg(reg *trustregistry.MockRegistry, iss string, role trustregistry.Role, pub ed25519.PublicKey) {
	err := reg.Register(context.Background(), &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	})
	if err != nil {
		log.Fatalf("register %s/%s: %v", iss, role, err)
	}
}

func short(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}
