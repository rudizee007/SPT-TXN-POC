// Command spt-demo runs the whole SPT-Txn story end to end, in-process, with
// real cryptography, narrating each step. It is the "watch it work" artifact
// for a collaborator, a standards reviewer, or a due-diligence team:
//
//	go run ./cmd/spt-demo
//
// The narrative:
//  1. Attest a workload's SPIFFE JWT-SVID.
//  2. Establish the human identity root: verify a Civic Pass / SAS attestation.
//  3. Seal the attestation + the verified human anchor into a root CAT.
//  4. Delegate agent -> sub-agent, scope attenuating at each hop.
//  5. The sub-agent declares an intent and mints a transaction token bound to it.
//  6. Verify the whole chain OFFLINE (signatures, attenuation, status list) -> ALLOW.
//  7. Emit a signed receipt into the transparency log.
//  8. Revoke the leaf via the status list -> the same request now DENIES.
//  9. Show intent binding: a hijacked call DENIES even with a valid token.
//
// 10. Witnesses co-sign the log's tree head; a rewritten history is refused.
// 11. Export the receipt to NIST/DORA/SOC2 control evidence.
// 12. Crypto-agility: the suite id is covered by the signature.
//
// Everything here is exercised by the package tests; this program is the guided
// tour, not a substitute for them.
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/attest"
	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/civicpass"
	"github.com/rudizee007/spt-txn-poc/internal/controlmap"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
	"github.com/rudizee007/spt-txn-poc/internal/suite"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

const (
	issCT   = "domain-a.authorg"
	issTTS  = "domain-a.tts"
	aud     = "domain-b.execorg"
	htm     = "POST"
	htu     = "https://foss.violetskysecurity.com/b/verify"
	slURI   = "https://domain-a.authorg/statuslists/1"
	svidAud = "spt-txn-exchange"
)

func main() {
	ctx := context.Background()

	banner("SPT-Txn — end-to-end walkthrough")
	fmt.Println("Everyone else authorizes by role. Watch SPT-Txn authorize one declared")
	fmt.Println("transaction, conditioned on what the actor is and how fresh its attestation")
	fmt.Println("is, and prove the decision — offline, with revocation and an audit trail.")

	// ── keys & registry ────────────────────────────────────────────────
	ctPub, ctPriv := genKey()
	ttsPub, ttsPriv := genKey()
	svidPub, svidPriv := genKey()     // the workload's SPIFFE signer (its trust domain)
	statusPub, statusPriv := genKey() // status-list signer
	logPub, logPriv := genKey()       // transparency-log signer

	reg := mustReg()
	regRegister(reg, issCT, trustregistry.RoleCTIssuer, ctPub)
	regRegister(reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	agentPub, _ := genKey() // agent holds the CAT/CT_A; the sub-agent transacts
	subPub, subPriv := genKey()

	// ── 1. attest the workload ─────────────────────────────────────────
	step(1, "Attest the workload (SPIFFE JWT-SVID)")
	svid := mintSVID("k1", svidPriv)
	ks := attest.NewStaticKeySource(map[string]crypto.PublicKey{"k1": svidPub})
	id, err := attest.VerifySPIFFEJWTSVID(ctx, svid, []string{svidAud}, ks)
	check(err, "verify SVID")
	fmt.Printf("   attested subject : %s\n", id.Subject)
	fmt.Printf("   trust domain     : %s\n", id.TrustDomain)
	fmt.Printf("   evidence digest  : %s…\n", id.EvidenceDigest[:16])

	// ── 2. establish the human identity root (Civic Pass / SAS) ────────
	// The identity root is a swappable dependency (docs/spec/IDENTITY-ROOT-SEAM.md).
	// A shipping root — here Civic Pass / the Solana Attestation Service — is
	// VERIFIED (not asserted) and its anchor sealed as the CAT humanAnchor. Swap
	// the provider (mock, or a future .zkdid) and this issuance code is unchanged.
	step(2, "Establish the human identity root — verify a Civic Pass / SAS attestation")
	attPub, attPriv := genKey() // the identity root (Civic gatekeeper / SAS attester)
	nullKey := make([]byte, 32)
	_, err = rand.Read(nullKey)
	check(err, "nullifier key")
	idroot, _, err := civicpass.NewVerifier(nullKey)
	check(err, "new identity-root verifier")
	check(idroot.TrustAttester("civic-gatekeeper:uniqueness-v1", attPub), "trust attester")
	idroot.AllowClaim("proof-of-personhood")
	pass := &civicpass.Attestation{
		Scheme: civicpass.SchemeCivicPass, Attester: "civic-gatekeeper:uniqueness-v1",
		Subject: "So1anaWa11et:" + id.Subject, Claim: "proof-of-personhood",
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}
	pass.Sign(attPriv) // in production: an on-chain Civic Pass / SAS attestation account
	check(idroot.Present(pass), "verify identity-root attestation")
	human, err := idroot.Resolve(ctx, "So1anaWa11et:"+id.Subject, issCT)
	check(err, "resolve human identity root")
	fmt.Printf("   identity root    : civic-pass (verified, not asserted; fail-closed)\n")
	fmt.Printf("   humanAnchor      : %s…  (fresh; nullifier is context-scoped)\n", human.Anchor.String()[:16])

	// ── 3. seal it into a root CAT ─────────────────────────────────────
	step(3, "Issue a root CAT with the attestation + verified human anchor sealed")
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "workload:" + id.Subject, PrincipalName: id.Subject,
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: 4 * time.Minute, HolderPublicKey: agentPub,
		Attestation:    id.SealClaim(),
		Status:         statusRef(0),
		IdentityAnchor: human.Anchor.Bytes(), // ← the identity-root seam
	}, ctPriv)
	check(err, "issue CAT")
	fmt.Printf("   CAT scope        : max_amount=10000 USD, action=payment (depth<=3)\n")
	fmt.Printf("   spt_attestation  : sealed (%v)\n", cat.Claims["spt_attestation"] != nil)
	fmt.Printf("   humanAnchor      : sealed from the verified identity root (%s)\n", okStr(cat.HumanAnchor == human.Anchor))

	// ── 4. delegate, attenuating scope ─────────────────────────────────
	step(4, "Delegate agent -> sub-agent; scope can only narrow")
	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub, Status: statusRef(1),
	}, ctPriv)
	check(err, "issue CT_A")
	ctB, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issCT, ParentCT: ctA.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 5000, "currency": "USD"},
		HolderPublicKey: subPub, Status: statusRef(2),
	}, ctPriv)
	check(err, "delegate CT_B")
	fmt.Printf("   CAT(10000) -> CT_A(8000) -> CT_B(5000)  — monotonic, offline-verifiable\n")

	// ── 5. declare intent + mint the transaction token ─────────────────
	step(5, "Sub-agent declares its intent and mints a transaction-bound token")
	declared := intent.Intent{
		Tool:   "payments.transfer",
		Params: json.RawMessage(`{"amount":"3000","beneficiary":"rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW","currency":"USD"}`),
		Target: "mcp://payments",
	}
	intentDigest, err := declared.Digest()
	check(err, "intent digest")
	l, err := ledger.Get("xrpl")
	check(err, "ledger")
	tc := paymentTxn("3000", "USD")
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ctB.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: subPub, Ledger: l, Txn: tc, IntentDigest: intentDigest,
	}, ttsPriv)
	check(err, "issue txn")
	fmt.Printf("   intent digest    : %s…\n", intentDigest[:16])
	fmt.Printf("   txn              : transfer 3000 USD (within CT_B's 5000 ceiling)\n")

	// ── 6. verify offline (with status list active) -> ALLOW ───────────
	step(6, "Verify the whole chain OFFLINE — signatures, attenuation, freshness, status")
	sl, err := statuslist.New(2, 1024)
	check(err, "new status list")
	slTok, err := statuslist.SignToken(sl, slURI, time.Now(), time.Hour, statusPriv)
	check(err, "sign status list")
	res := statuslist.NewResolver()
	check(res.AddVerified(slTok, slURI, statusPub, time.Now()), "cache status list")

	eng := verifier.New(reg)
	eng.StatusResolver = res
	in := mkInput(txn.Token, subPriv, []string{ctA.Token, ctB.Token}, cat.Token, tc)
	d := eng.Verify(ctx, in)
	fmt.Printf("   decision         : %s\n", allowStr(d.Allow, d))
	if !d.Allow {
		fail("expected ALLOW, got deny at step %d (%s): %s", d.Step, d.StepName, d.Reason)
	}

	// ── 7. emit a signed receipt into the transparency log ─────────────
	step(7, "Emit a signed receipt into the append-only transparency log")
	dir, _ := os.MkdirTemp("", "spt-demo")
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "audit.jsonl")
	alog, err := audit.Open(logPath)
	check(err, "open log")
	em, err := receiptlog.NewLogEmitter(alog, logPriv)
	check(err, "emitter")
	permit := mkReceipt(receipt.DecisionPermit, receipt.ClassOK, "authorize.ok", txn.Token, intentDigest)
	rhash, err := em.Emit(permit)
	check(err, "emit receipt")
	fmt.Printf("   receipt          : PERMIT/ok  hash=%s…\n", rhash[:16])
	fmt.Printf("   log integrity    : %s\n", okStr(alog.Verify() == nil))

	// ── 8. revoke the leaf via the status list -> DENY ─────────────────
	step(8, "Revoke the leaf CT via the status list — an equivalent request now denies")
	_ = sl.Set(2, statuslist.StatusInvalid) // flip CT_B's slot to REVOKED
	slTok2, err := statuslist.SignToken(sl, slURI, time.Now(), time.Hour, statusPriv)
	check(err, "re-sign status list")
	res2 := statuslist.NewResolver()
	check(res2.AddVerified(slTok2, slURI, statusPub, time.Now()), "cache revoked list")
	eng.StatusResolver = res2
	// Mint a FRESH transaction token so the only thing that changed is the
	// status list — the deny is provably from revocation, not single-use replay.
	txn2, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ctB.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: subPub, Ledger: l, Txn: tc, IntentDigest: intentDigest,
	}, ttsPriv)
	check(err, "mint fresh txn")
	in2 := mkInput(txn2.Token, subPriv, []string{ctA.Token, ctB.Token}, cat.Token, tc)
	d2 := eng.Verify(ctx, in2)
	fmt.Printf("   decision         : %s\n", allowStr(d2.Allow, d2))
	if d2.Allow {
		fail("revoked leaf still allowed")
	}
	eng.StatusResolver = res // restore for later steps

	// ── 9. intent binding: a hijacked call denies ──────────────────────
	step(9, "Goal hijack: same valid token, a DIFFERENT call — intent binding denies it")
	hijacked := declared
	hijacked.Params = json.RawMessage(`{"amount":"999999","beneficiary":"rATTACKER","currency":"USD"}`)
	if err := intent.Match(intentDigest, hijacked); err != nil {
		fmt.Printf("   hijacked transfer: DENIED  (%s)\n", "intent digest mismatch")
	} else {
		fail("hijacked call matched the bound intent")
	}
	if err := intent.Match(intentDigest, declared); err != nil {
		fail("the real declared call failed intent match: %v", err)
	}
	fmt.Printf("   declared transfer: matches — the token works only for what it declared\n")

	// ── 10. witness co-signing: a rewritten log is refused ─────────────
	step(10, "Witnesses co-sign the tree head; a rewritten history is refused")
	entries := alog.Entries()
	sr := audit.PublishRoot(entries, logPriv)
	w1Pub, w1Priv := genKey()
	w2Pub, w2Priv := genKey()
	w1, _ := audit.NewWitness("witness-1", w1Priv)
	w2, _ := audit.NewWitness("witness-2", w2Priv)
	cs1, err := w1.Cosign(sr, logPub, entries)
	check(err, "witness-1 cosign")
	cs2, err := w2.Cosign(sr, logPub, entries)
	check(err, "witness-2 cosign")
	cr := audit.CosignedRoot{SignedRoot: sr, OperatorPub: logPub, Cosigs: []audit.WitnessSig{cs1, cs2}}
	set := map[string]ed25519.PublicKey{"witness-1": w1Pub, "witness-2": w2Pub}
	check(audit.VerifyCosigned(cr, logPub, set, 2), "verify 2-of-2 cosign")
	fmt.Printf("   tree head        : co-signed 2-of-2, count=%d\n", sr.Count)
	// The operator appends another decision, then tries to REWRITE the first
	// logged entry and re-sign the fork. The witness refuses because the fork's
	// prefix no longer reproduces the root it already attested.
	_, err = em.Emit(mkReceipt(receipt.DecisionDeny, receipt.ClassViolation, "intent.digest-mismatch", txn.Token, ""))
	check(err, "emit 2nd receipt")
	forked := alog.Entries() // a copy of the slice; copy the leaf hash before mutating
	forked[0].Hash = append([]byte(nil), forked[0].Hash...)
	forked[0].Hash[0] ^= 0xFF // rewrite a previously-committed entry
	srFork := audit.PublishRoot(forked, logPriv)
	if _, err := w1.Cosign(srFork, logPub, forked); err != nil {
		fmt.Printf("   rewritten history: REFUSED by witness (not an append-only extension)\n")
	} else {
		fail("witness co-signed a rewritten history")
	}

	// ── 11. control-framework export ───────────────────────────────────
	step(11, "Export the receipt to NIST 800-53 / DORA / SOC2 control evidence")
	rows := controlmap.Rows(*permit, rhash, "")
	shown := 0
	for _, r := range rows {
		if shown >= 4 {
			break
		}
		fmt.Printf("   %-14s %-8s %s\n", r.Framework, r.ControlID, r.ControlTitle)
		shown++
	}
	fmt.Printf("   (+%d more rows across frameworks, each anchored to receipt %s…)\n", len(rows)-shown, rhash[:12])

	// ── 12. crypto-agility ─────────────────────────────────────────────
	step(12, "Crypto-agility: the suite id is covered by the signature")
	env, err := suite.Seal(suite.SuiteEdDSA, []byte("policy-decision-envelope"), suite.PrivateKeySet{Ed25519: logPriv})
	check(err, "seal envelope")
	check(suite.Verify(env, suite.PublicKeySet{Ed25519: logPub}, suite.ModeVerifyBoth, nil, ""), "verify envelope")
	env.Suite = suite.SuiteHybrid65 // attacker rewrites the dispatch field
	if err := suite.Verify(env, suite.PublicKeySet{Ed25519: logPub}, suite.ModeVerifyEither, nil, ""); err != nil {
		fmt.Printf("   suite downgrade  : REJECTED (id is inside the signed bytes)\n")
	} else {
		fail("suite-id rewrite verified")
	}

	banner("Done — attested, transaction-scoped, delegated, revocable, provable. Offline.")
	fmt.Println("No shipping product completes that sentence today.")
}

// ── helpers ────────────────────────────────────────────────────────────

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err, "keygen")
	return pub, priv
}

func mustReg() *trustregistry.MockRegistry {
	reg, err := trustregistry.NewMockRegistry("")
	check(err, "registry")
	return reg
}

func regRegister(reg *trustregistry.MockRegistry, iss string, role trustregistry.Role, pub ed25519.PublicKey) {
	err := reg.Register(context.Background(), &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	})
	check(err, "register "+iss)
}

func statusRef(idx int) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": idx, "uri": slURI}}
}

func mintSVID(kid string, priv ed25519.PrivateKey) string {
	now := time.Now()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"sub": "spiffe://prod.example/ns/pay/sa/charger",
		"aud": []string{svidAud},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	si := b64(hdr) + "." + b64(claims)
	return si + "." + b64(ed25519.Sign(priv, []byte(si)))
}

func paymentTxn(amount, currency string) ledger.TxnContext {
	return ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      amount, Currency: currency, Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
}

func mkInput(txnTok string, holderPriv ed25519.PrivateKey, chain []string, cat string, tc ledger.TxnContext) verifier.Input {
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txnTok))
	check(err, "dpop proof")
	return verifier.Input{
		TxnToken: txnTok, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: chain, CAT: cat, Txn: tc, Audience: aud,
	}
}

func mkReceipt(decision, class, rule, token, intentDigest string) *receipt.Receipt {
	r, err := receipt.New("demo.pep", decision, class, rule, receipt.TokenHash(token), receipt.TokenHash("policy-v1"))
	check(err, "new receipt")
	r.IntentDigest = intentDigest
	r.Jurisdiction = "EU-DORA"
	return r
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func banner(s string) { fmt.Printf("\n\033[1m%s\033[0m\n%s\n", s, line(len(s))) }
func line(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}
func step(n int, s string) { fmt.Printf("\n[%d] %s\n", n, s) }

func allowStr(allow bool, d verifier.Decision) string {
	if allow {
		return "\033[32mALLOW\033[0m"
	}
	return fmt.Sprintf("\033[31mDENY\033[0m at step %d (%s): %s", d.Step, d.StepName, d.Reason)
}
func okStr(ok bool) string {
	if ok {
		return "verified"
	}
	return "FAILED"
}

func check(err error, what string) {
	if err != nil {
		fail("%s: %v", what, err)
	}
}
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\ndemo failed: "+format+"\n", args...)
	os.Exit(1)
}
