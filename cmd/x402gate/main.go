// Command x402gate is a proof-of-concept payer-side gate for x402 agentic
// payments. x402 settles a payment; this gate decides whether the agent is
// AUTHORIZED to make it before it signs anything.
//
// It serves two rails from one decision engine. -chain xrpl (the default, and
// the original behavior) decides an XRPL Payment and prints the Memo/SourceTag
// stamping. -chain base decides an EIP-3009 settlement on Base and emits a
// payergate.Decision document (-out) for the settlement client to consume:
// the ceiling comes from the CAT scope, the humanAnchor from the CAT itself,
// and the context hash from the same canonical encoding every other party
// derives independently.
//
// The PAYER-side gate answers "may this agent sign?", protecting the payer
// from a compromised agent. It is not the merchant-side gateway
// (spt-txn-gateway), which answers "may this request be served?" — opposite
// threat models, different keys, and the two must never merge. See
// PAYER-GATE-PLACEMENT-ADR-2026-08-27.md.
//
// Given an x402 payment requirement (price, currency, merchant pay-to address)
// and the agent's capability ceiling, it mints a real CAT -> CT -> SPT-Txn chain
// for the corresponding XRPL Payment and runs the eight-step verifier:
//
//   - If the payment is within the agent's capability scope, the gate ALLOWS it
//     and emits the humanAnchor (a zero-knowledge commitment to the accountable
//     person) as the XRPL Payment Memo, plus the SourceTag and the
//     spt_txn_context_hash — so the on-ledger payment is accountable and (for
//     regulated transfers) Travel-Rule-bindable, with no PII on the wire.
//   - If the payment exceeds the agent's scope, the SPT-Txn mint is refused and
//     the gate DENIES it: the agent must not sign the x402 payment.
//
// This is the SPT-Txn x402 payer-gate milestone: it reuses the same offline
// authorization engine as cmd/anchor. It does NOT submit anything to the network
// or call x402 facilitators; wiring it into T54's Python `x402-xrpl` client (so
// the gate runs before `x402_requests` signs the Payment) is the integration
// step. Nothing here contacts a ledger.
//
//	go run ./cmd/x402gate -price 1000 -ceiling 5000            # ALLOW
//	go run ./cmd/x402gate -price 9000 -ceiling 5000            # DENY (over scope)
//	go run ./cmd/x402gate -price 0.5 -currency RLUSD -ceiling 100
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
	"github.com/rudizee007/spt-txn-poc/pkg/payergate"
)

const (
	issOrg     = "domain-a.authorg"
	issTTS     = "domain-a.tts"
	aud        = "domain-b.execorg"
	htm        = "POST"
	htu        = "https://foss.violetskysecurity.com/b/verify"
	agentAddr  = "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT" // the payer agent's XRPL account
	defaultPay = "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW" // a sample merchant pay-to
)

func main() {
	price := flag.String("price", "1000", "x402 price to pay (XRP/drops or RLUSD amount, as the merchant declares)")
	currency := flag.String("currency", "XRP", "payment currency: XRP or RLUSD")
	payto := flag.String("payto", defaultPay, "merchant XRPL pay-to (classic r-address)")
	ceiling := flag.String("ceiling", "5000", "the agent's capability ceiling as a decimal string (max it may spend under its CT)")
	sourceTag := flag.String("sourcetag", "402", "x402 SourceTag stamped on the Payment (xrpl only)")
	chain := flag.String("chain", "xrpl", "rail to decide for: xrpl or base")
	payerAddr := flag.String("payer", "", "the paying account (required for -chain base; 0x-hex)")
	anchorHex := flag.String("anchor", "", "identity anchor for the CAT, 64 hex chars. "+
		"Empty mints a fresh commitment; supplying one makes the run deterministic and "+
		"lets a separately-run issuing authority pre-pin the same anchor")
	out := flag.String("out", "", "write the decision document (JSON) here — the settlement client's input")
	flag.Parse()

	// The chain decides the shape of everything below; refuse the combinations
	// that would silently hash the wrong payment rather than defaulting them.
	switch *chain {
	case "xrpl":
	case "base":
		if *payerAddr == "" {
			log.Fatal("-chain base requires -payer: the decision binds one paying account, " +
				"and a defaulted payer is a context hash for somebody else's payment")
		}
		if *currency == "XRP" {
			log.Fatal("-chain base requires -currency to be ETH or the ERC-20 token contract " +
				"address (0x…). XRP is the xrpl default, not a Base asset")
		}
	default:
		log.Fatalf("unknown -chain %q (xrpl or base)", *chain)
	}

	l, err := ledger.Get(*chain)
	if err != nil {
		log.Fatalf("%s adapter: %v", *chain, err)
	}

	// ── Trust Registry + issuer keys (held locally by the verifier) ────
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		log.Fatal(err)
	}
	orgPub, orgPriv := genKey()
	ttsPub, ttsPriv := genKey()
	holderPub, holderPriv := genKey()
	mustReg(reg, issOrg, trustregistry.RoleCTIssuer, orgPub)
	mustReg(reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	// ── The agent's authority: CAT -> CT bounded by the ceiling ────────
	var identityAnchor []byte
	if *anchorHex != "" {
		identityAnchor, err = hex.DecodeString(strings.TrimPrefix(*anchorHex, "0x"))
		if err != nil || len(identityAnchor) != 32 {
			log.Fatalf("-anchor must be 32 bytes of hex (64 characters); an odd-length value " +
				"is usually a big integer rendered with %%x, which drops leading zero nibbles")
		}
	}
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issOrg, Subject: "alice", PrincipalName: "alice",
		IdentityAnchor:     identityAnchor,
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": json.Number(*ceiling), "currency": *currency},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CAT: %v", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issOrg, ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": json.Number(*ceiling), "currency": *currency},
		HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CT: %v", err)
	}

	anchor := cat.HumanAnchor.String()

	// ── The x402 payment, as a transaction context for this rail. ──────
	//
	// On XRPL the humanAnchor rides in a Memo, so it is part of the context.
	// On Base an EIP-3009 authorization has NO free field — the anchor is
	// bound downstream as the nonce commitment instead — so the Base context
	// deliberately carries no anchor. Putting it in Extra here would make this
	// gate's context hash differ from the one the issuing authority and the
	// settlement client each derive from the bare payment fields, and the
	// mismatch would surface two processes later pointing at neither cause.
	issuedAt := time.Now().Unix()
	originator := agentAddr
	extra := map[string]string{"DestinationTag": *sourceTag, "Memo": anchor}
	if *chain == "base" {
		originator = *payerAddr
		extra = nil
	}
	tc := ledger.TxnContext{
		Chain: *chain, Originator: originator, Beneficiary: *payto,
		Amount: *price, Currency: *currency, Timestamp: issuedAt,
		Extra: extra,
	}

	fmt.Printf("SPT-Txn × x402 payer-gate (%s)\n", *chain)
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("  x402 requirement     : pay %s %s to %s\n", *price, *currency, *payto)
	fmt.Printf("  agent capability     : up to %s %s under its CT\n", *ceiling, *currency)

	// ── Gate: mint the SPT-Txn for this payment. Scope is enforced at mint;
	//    an over-ceiling payment is refused here — that is the gate saying NO. ──
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct.Token, ParentIssuerKey: orgPub,
		HolderPublicKey: holderPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		fmt.Println()
		fmt.Printf("  GATE: DENY — the agent must NOT sign this x402 payment.\n")
		fmt.Printf("  reason: payment is outside the agent's capability scope (%v)\n", err)
		emit(*out, payergate.Decision{
			Version: payergate.FormatVersion, Outcome: payergate.Deny,
			Reason:  fmt.Sprintf("mint refused: outside capability scope: %v", err),
			Ceiling: *ceiling,
			Context: decisionContext(tc), IssuedAt: issuedAt,
		})
		return
	}

	// ── Verify the whole chain offline for this exact payment ──────────
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		log.Fatalf("dpop: %v", err)
	}
	d := verifier.New(reg).Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ct.Token}, CAT: cat.Token, Txn: tc, Audience: aud,
	})
	if !d.Allow {
		fmt.Println()
		fmt.Printf("  GATE: DENY — verification failed at step %d (%s): %s\n", d.Step, d.StepName, d.Reason)
		emit(*out, payergate.Decision{
			Version: payergate.FormatVersion, Outcome: payergate.Deny,
			Reason: d.Reason, Step: d.Step, StepName: d.StepName,
			Ceiling: *ceiling,
			Context: decisionContext(tc), IssuedAt: issuedAt,
		})
		return
	}

	_, ctxHash, err := ledger.ContextHash(l, tc)
	if err != nil {
		log.Fatalf("context hash: %v", err)
	}

	fmt.Println()
	switch *chain {
	case "xrpl":
		fmt.Printf("  GATE: ALLOW — agent is authorized; sign the x402 payment and stamp:\n")
		fmt.Printf("    XRPL Payment.Destination     : %s\n", *payto)
		fmt.Printf("    XRPL Payment.Amount          : %s %s\n", *price, *currency)
		fmt.Printf("    XRPL Payment.SourceTag       : %s\n", *sourceTag)
		fmt.Printf("    XRPL Payment.Memos[0] (anchor): %s\n", anchor)
		fmt.Printf("    spt_txn_context_hash         : %s\n", ctxHash)
		fmt.Println()
		fmt.Println("  → accountable to one human (zero-knowledge anchor), scope-bounded,")
		fmt.Println("    and Travel-Rule-bindable — with no PII on the XRP Ledger.")
	case "base":
		fmt.Printf("  GATE: ALLOW — agent is authorized to settle on Base:\n")
		fmt.Printf("    payer                : %s\n", originator)
		fmt.Printf("    merchant             : %s\n", *payto)
		fmt.Printf("    amount               : %s (token %s)\n", *price, *currency)
		fmt.Printf("    humanAnchor (CAT)    : %s\n", anchor)
		fmt.Printf("    spt_txn_context_hash : %s\n", ctxHash)
		fmt.Println()
		fmt.Println("  → EIP-3009 has no memo; the anchor reaches chain state as the nonce")
		fmt.Println("    commitment. The settlement client re-derives this context hash from")
		fmt.Println("    the fields above and refuses the decision if the two disagree.")
	}

	emit(*out, payergate.Decision{
		Version: payergate.FormatVersion, Outcome: payergate.Allow,
		Reason: "in-scope under the CT; eight-step verification passed",
		Anchor: anchor, Ceiling: *ceiling,
		Context: decisionContext(tc), ContextHash: ctxHash,
		Chain:    payergate.Chain{CAT: cat.Token, CTs: []string{ct.Token}, TXN: txn.Token},
		IssuedAt: issuedAt, Verified: true,
	})
}

// decisionContext converts the ledger context into the decision document's
// shape. One conversion, here, so the two cannot disagree field-by-field at
// the call sites.
func decisionContext(tc ledger.TxnContext) payergate.Context {
	return payergate.Context{
		Chain: tc.Chain, Originator: tc.Originator, Beneficiary: tc.Beneficiary,
		Amount: tc.Amount, Currency: tc.Currency, Timestamp: tc.Timestamp,
		Extra: tc.Extra,
	}
}

// emit writes the decision document when -out is set. It is called on EVERY
// verdict, DENY included: a consumer polling for a decision file must find a
// refusal written down, not an absence it might misread as "not yet".
func emit(path string, d payergate.Decision) {
	if path == "" {
		return
	}
	if err := payergate.Write(path, d); err != nil {
		log.Fatalf("writing the decision to %s: %v", path, err)
	}
	fmt.Printf("\n  decision written to %s\n", path)
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
