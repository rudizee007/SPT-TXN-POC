// Command anchor closes the loop between an SPT-Txn token and an on-chain
// attestation anchor. It mints a real CAT -> CT -> SPT-Txn chain, computes the
// genuine spt_txn_context_hash for a chosen ledger, verifies the token offline
// with the eight-step engine, and prints ready-to-use anchor calldata for that
// chain. The value it prints is the SAME hash bound inside the SPT-Txn token —
// so anchoring it on-chain ties the on-chain record to an actual token, not a
// placeholder.
//
// Nothing here contacts a network or a ledger; it only produces the
// deterministic hash and the calldata you paste into the chain's CLI.
//
//	go run ./cmd/anchor -chain ethereum
//	go run ./cmd/anchor -chain starknet -amount 4200
//	go run ./cmd/anchor -chain aptos -onchain 4b505b...   # compare an on-chain root
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/cattoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/cttoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/dpop"
	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/tbac"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/txntoken"
	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
)

const (
	issOrg = "domain-a.authorg"
	issTTS = "domain-a.tts"
	aud    = "domain-b.execorg"
	htm    = "POST"
	htu    = "https://foss.violetskysecurity.com/b/verify"
)

func main() {
	chain := flag.String("chain", "ethereum", "ledger adapter: ethereum, arbitrum, optimism, base, avalanche, xdc, starknet, aptos, sui, solana, stellar, hedera, algorand, polkadot, xrpl")
	amount := flag.String("amount", "4000", "transfer amount (must be within the capability ceiling)")
	onchain := flag.String("onchain", "", "optional: an on-chain anchored root (64 hex) to compare against the computed hash")
	flag.Parse()

	l, err := ledger.Get(*chain)
	if err != nil {
		log.Fatalf("unknown -chain %q: %v", *chain, err)
	}
	tc, cur, err := chainContext(*chain, *amount)
	if err != nil {
		log.Fatal(err)
	}

	// ── Trust Registry + keys (held locally by the verifier) ───────────
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		log.Fatal(err)
	}
	orgPub, orgPriv := genKey()
	ttsPub, ttsPriv := genKey()
	holderPub, holderPriv := genKey()
	mustReg(reg, issOrg, trustregistry.RoleCTIssuer, orgPub)
	mustReg(reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	// ── Mint a real CAT -> CT -> SPT-Txn chain ─────────────────────────
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issOrg, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": cur},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CAT: %v", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issOrg, ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": cur},
		HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		log.Fatalf("CT: %v", err)
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct.Token, ParentIssuerKey: orgPub,
		HolderPublicKey: holderPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		log.Fatalf("SPT-Txn mint refused (scope?): %v", err)
	}

	// ── The genuine spt_txn_context_hash bound in the token ────────────
	_, hexHash, err := ledger.ContextHash(l, tc)
	if err != nil {
		log.Fatalf("context hash: %v", err)
	}

	// ── Verify the whole thing offline (eight-step engine) ─────────────
	proof, err := dpop.Proof(holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		log.Fatalf("dpop: %v", err)
	}
	d := verifier.New(reg).Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ct.Token}, CAT: cat.Token, Txn: tc, Audience: aud,
	})

	// ── Report ─────────────────────────────────────────────────────────
	fmt.Printf("SPT-Txn end-to-end anchor — chain=%s amount=%s %s\n", *chain, *amount, cur)
	fmt.Println(strings.Repeat("=", 60))
	if d.Allow {
		fmt.Println("  offline verification : ALLOW (all 8 steps passed)")
	} else {
		fmt.Printf("  offline verification : DENY (step %d: %s — %s)\n", d.Step, d.StepName, d.Reason)
	}
	fmt.Printf("  spt_txn_context_hash : %s\n", hexHash)
	fmt.Println()
	printCalldata(*chain, hexHash)

	if *onchain != "" {
		got := strings.TrimPrefix(strings.ToLower(*onchain), "0x")
		fmt.Println()
		if got == hexHash {
			fmt.Printf("  on-chain check       : MATCH — anchored root equals the token's context hash\n")
		} else {
			fmt.Printf("  on-chain check       : MISMATCH\n    on-chain: %s\n    token   : %s\n", got, hexHash)
		}
	}
}

// printCalldata renders the anchor arguments for each chain's CLI.
func printCalldata(chain, hexHash string) {
	switch chain {
	case "ethereum", "xdc", "avalanche", "arbitrum", "optimism", "base":
		fmt.Printf("  anchor calldata (EVM, bytes32):\n    cast send <ADDR> \"anchor(bytes32)\" 0x%s\n", hexHash)
	case "starknet":
		low, high := "0x"+hexHash[32:64], "0x"+hexHash[0:32]
		fmt.Printf("  anchor calldata (Cairo, u256 low high):\n    sncast --account spt invoke --contract-address <ADDR> --function anchor --calldata %s %s --network sepolia\n", low, high)
	case "aptos":
		fmt.Printf("  anchor calldata (Move; anchor takes book_owner + root):\n    aptos move run --function-id <ADDR>::attestation_anchor::anchor --args address:<BOOK_OWNER> hex:0x%s --assume-yes\n", hexHash)
	case "solana":
		fmt.Printf("  anchor memo (SPL memo):\n    spt-txn-anchor:%s\n", hexHash)
	case "hedera":
		fmt.Printf("  anchor to Hedera Consensus Service (clients/hcs-anchor, milestone A1):\n    hcs-anchor anchor -network testnet -topic 0.0.<TOPIC> -type ctx -hash %s\n", hexHash)
	default:
		fmt.Printf("  attestation root (anchor however %s records it): 0x%s\n", chain, hexHash)
	}
}

// chainContext returns a valid sample transfer for the chain, plus the currency
// to use in the capability scope (so the mint's scope check passes).
func chainContext(chain, amount string) (ledger.TxnContext, string, error) {
	mk := func(orig, ben, cur string, extra map[string]string) (ledger.TxnContext, string, error) {
		return ledger.TxnContext{Chain: chain, Originator: orig, Beneficiary: ben, Amount: amount, Currency: cur, Timestamp: 1750000000, Extra: extra}, cur, nil
	}
	switch chain {
	case "ethereum":
		return mk("0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH", nil)
	case "xdc":
		return mk("xdc0102030405060708090a0b0c0d0e0f1011121314", "xdcfFEEdDcCBbAa99887766554433221100ffEEddCc", "XDC", nil)
	case "avalanche":
		return mk("0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "AVAX", nil)
	case "optimism", "base":
		return mk("0x0102030405060708090a0b0c0d0e0f1011121314", "0xfFEEdDcCBbAa99887766554433221100ffEEddCc", "ETH", nil)
	case "starknet":
		return mk("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "STRK", nil)
	case "aptos":
		return mk("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "APT", nil)
	case "sui":
		return mk("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "0xffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", "SUI", nil)
	case "polkadot":
		return mk("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", "DOT", nil)
	case "solana":
		return mk("BeWdnfiJ52LpaGudU6ZhGLVcpeBEYxHYewZC4DZopVi4", "HiHP5wBk1iVLMPM42MviMqBirdSbaaQ9Szida8tGwVR2", "SOL", nil)
	case "stellar":
		return mk("GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW", "G234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ", "XLM", nil)
	case "hedera":
		return mk("0.0.1001", "0.0.2002", "HBAR", nil)
	case "algorand":
		return mk("KNTKMJFYXI2B43M7G4LJ3KU5I452GORN3FCDDMFUEHF7Q3OBNND3OQENZE", "IGIOJAQMOL2F42RGONSM6ONMYZ2M22TNDZODKIOT7TK7IRXGCZXQMHEKQY", "ALGO", nil)
	case "xrpl":
		return mk("rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT", "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW", "USD", map[string]string{"DestinationTag": "42"})
	default:
		return ledger.TxnContext{}, "", fmt.Errorf("no sample context for chain %q", chain)
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
