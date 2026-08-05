// Command xrpl-pay submits a real XRPL Payment to testnet (then mainnet) from an
// x402gate ALLOW decision — P0 of the agentic-x402 demo (docs/AGENTIC-X402-DEMO-PLAN.md).
//
// The offline core (cmd/x402gate) decides IF the agent may pay and emits the
// stamp fields (Destination, Amount, SourceTag, Memo=humanAnchor, context hash).
// This tool takes those fields and actually settles the Payment on the ledger,
// carrying the zero-knowledge human anchor in the Memo so the on-ledger payment
// is accountable and Travel-Rule-bindable with no PII on the wire.
//
// It lives in its own module so the XRPL SDK never enters the offline core or
// the hardened box's core build.
//
// Security:
//   - The account seed is read ONLY from an env var (never a flag / never the
//     repo). Testnet seeds are still treated as secret; never reuse a testnet
//     seed on mainnet.
//   - Default endpoint is TESTNET. Mainnet requires an explicit -endpoint.
//   - -dry-run builds and prints the transaction WITHOUT any network or submit,
//     so the build and field mapping can be verified before funding anything.
//
// Usage:
//
//	export SPT_XRPL_SEED=sEd...                       # testnet payer seed (faucet)
//	go run . -to rDEST... -amount 1000 -sourcetag 402 -memo <anchorHex> -dry-run
//	go run . -to rDEST... -amount 1000 -sourcetag 402 -memo <anchorHex>   # submit
//
// NOTE (API): written against github.com/Peersyst/xrpl-go v0.1.12 (the official
// XRPLF Go library). The transaction is built as a FlatTransaction map keyed by
// XRPL's documented JSON field names (stable) to avoid Go-struct-field guessing.
// The library calls used are the documented ones (NewClientConfig / NewClient /
// Autofill / wallet.FromSeed / wallet.Sign / SubmitTxBlobAndWait); if a name
// drifted between versions, only the small helpers below need adjusting.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Peersyst/xrpl-go/pkg/crypto"
	"github.com/Peersyst/xrpl-go/xrpl/rpc"
	"github.com/Peersyst/xrpl-go/xrpl/transaction"
	"github.com/Peersyst/xrpl-go/xrpl/wallet"
)

const (
	testnetRPC      = "https://s.altnet.rippletest.net:51234/"
	seedEnv         = "SPT_XRPL_SEED"
	defaultMemoType = "spt-txn/humanAnchor"
)

func main() {
	endpoint := flag.String("endpoint", testnetRPC, "XRPL JSON-RPC endpoint (default TESTNET; mainnet must be set explicitly)")
	to := flag.String("to", "", "destination classic r-address (required)")
	amount := flag.String("amount", "", "amount in drops for XRP (required); 1 XRP = 1,000,000 drops")
	currency := flag.String("currency", "XRP", "currency: XRP (native). RLUSD/IOU is a later step (needs a trustline)")
	sourceTag := flag.Uint("sourcetag", 0, "x402 SourceTag stamped on the Payment (0 = omit)")
	memo := flag.String("memo", "", "humanAnchor to carry in the Memo (from x402gate ALLOW)")
	memoType := flag.String("memo-type", defaultMemoType, "MemoType label")
	contextHash := flag.String("context-hash", "", "optional spt_txn_context_hash to carry as a second Memo")
	dryRun := flag.Bool("dry-run", false, "build and print the transaction without connecting or submitting")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the classic r-address derived from $SPT_XRPL_SEED and exit")
	genAccount := flag.Bool("genaccount", false, "generate a NEW XRPL account (address + seed) for a dedicated low-value demo wallet, then exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (for non-interactive use)")
	flag.Parse()

	if *genAccount {
		w, err := wallet.New(crypto.ED25519())
		if err != nil {
			log.Fatalf("generate account: %v", err)
		}
		fmt.Printf("address: %s\n", w.GetAddress())
		fmt.Printf("seed:    %s\n", w.Seed)
		fmt.Println()
		fmt.Println("SAVE THE SEED SECURELY. Never commit it, never paste it anywhere shared.")
		fmt.Println("Fund the ADDRESS with a small amount from your wallet, then:  export SPT_XRPL_SEED='<seed>'")
		return
	}

	if *whoami {
		seed := os.Getenv(seedEnv)
		if seed == "" {
			log.Fatalf("%s is not set", seedEnv)
		}
		checkSeed(seed)
		w, err := wallet.FromSeed(seed, "")
		if err != nil {
			log.Fatalf("wallet from seed: %v", err)
		}
		fmt.Println(string(w.GetAddress()))
		return
	}

	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if strings.ToUpper(*currency) != "XRP" {
		log.Fatalf("currency %q not yet supported: RLUSD/IOU needs a trustline to the issuer on both accounts (P1b). Use XRP for now.", *currency)
	}

	seed := os.Getenv(seedEnv)
	if seed == "" {
		log.Fatalf("%s is not set — export the testnet payer seed (never put it in a flag or the repo)", seedEnv)
	}
	checkSeed(seed)

	// Wallet from seed (offline; no network needed to derive the address).
	w, err := wallet.FromSeed(seed, "")
	if err != nil {
		log.Fatalf("wallet from seed: %v", err)
	}
	// GetAddress() returns a types.Address; the SDK's Autofill/validate path
	// asserts the FlatTransaction address fields as plain string, so store it as one.
	from := string(w.GetAddress())

	// Build the Payment as a FlatTransaction keyed by XRPL JSON field names.
	tx := transaction.FlatTransaction{
		"TransactionType": "Payment",
		"Account":         from,
		"Destination":     *to,
		"Amount":          *amount, // XRP drops as a string
	}
	if *sourceTag != 0 {
		tx["SourceTag"] = uint32(*sourceTag)
	}
	memos := []any{}
	if *memo != "" {
		memos = append(memos, memoObject(*memoType, *memo))
	}
	if *contextHash != "" {
		memos = append(memos, memoObject("spt-txn/contextHash", *contextHash))
	}
	if len(memos) > 0 {
		tx["Memos"] = memos
	}

	if !*jsonOut {
		fmt.Printf("xrpl-pay — %s\n", endpointLabel(*endpoint))
		fmt.Printf("  from (payer agent) : %s\n", from)
		fmt.Printf("  to (merchant)      : %s\n", *to)
		fmt.Printf("  amount             : %s drops XRP\n", *amount)
		if *sourceTag != 0 {
			fmt.Printf("  SourceTag          : %d\n", *sourceTag)
		}
		if *memo != "" {
			fmt.Printf("  Memo[humanAnchor]  : %s\n", *memo)
		}
	}

	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "tx": tx})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting. Transaction (pre-autofill):")
		for k, v := range tx {
			fmt.Printf("    %-16s %v\n", k, v)
		}
		return
	}

	// Real-money guardrail: on a non-testnet endpoint, require explicit
	// confirmation. Skipped in -json mode (driven by cmd/agent) or with -yes.
	if isMainnet(*endpoint) && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on a non-testnet ledger: %s drops to %s via %s\n   type 'yes' to proceed: ", *amount, *to, *endpoint)
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	// Connect, autofill (Fee/Sequence/LastLedgerSequence), sign, submit-and-wait.
	cfg, err := rpc.NewClientConfig(*endpoint)
	if err != nil {
		log.Fatalf("rpc config: %v", err)
	}
	client := rpc.NewClient(cfg)

	if err := client.Autofill(&tx); err != nil {
		log.Fatalf("autofill: %v", err)
	}
	blob, hash, err := w.Sign(tx)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	resp, err := client.SubmitTxBlobAndWait(blob, false)
	if err != nil {
		log.Fatalf("submit: %v", err)
	}

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{
			"tx_hash":  hash,
			"explorer": explorerBase(*endpoint) + hash,
			"status":   "submitted",
		})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    tx hash   : %s\n", hash)
	fmt.Printf("    result    : %v\n", resp)
	fmt.Printf("    explorer  : %s%s\n", explorerBase(*endpoint), hash)
}

// memoObject builds an XRPL Memo entry. XRPL requires MemoType and MemoData to be
// hex-encoded; we hex-encode the UTF-8 bytes so the values round-trip as text.
func memoObject(memoType, memoData string) any {
	return map[string]any{
		"Memo": map[string]any{
			"MemoType": strings.ToUpper(hex.EncodeToString([]byte(memoType))),
			"MemoData": strings.ToUpper(hex.EncodeToString([]byte(memoData))),
		},
	}
}

// checkSeed fails fast on the most common mistake: passing the account's
// r-ADDRESS instead of its secret seed. XRPL secrets start with 's'; addresses
// start with 'r'. Without this, an address silently derives an unrelated,
// unfunded account and the payment fails later with actNotFound.
func checkSeed(seed string) {
	if strings.HasPrefix(seed, "r") {
		short := seed
		if len(short) > 6 {
			short = short[:6]
		}
		log.Fatalf("%s looks like an r-ADDRESS (%s…), not a secret seed. Use the account's SECRET (starts with 's', e.g. sEd…) — the faucet's \"Secret\" field, not \"Address\".", seedEnv, short)
	}
}

// isMainnet is true for any endpoint that is not a known test network.
func isMainnet(ep string) bool {
	return !strings.Contains(ep, "altnet") && !strings.Contains(ep, "rippletest") && !strings.Contains(ep, "devnet")
}

func endpointLabel(ep string) string {
	if strings.Contains(ep, "altnet") || strings.Contains(ep, "rippletest") {
		return "XRPL TESTNET"
	}
	return "XRPL (" + ep + ")"
}

func explorerBase(ep string) string {
	if strings.Contains(ep, "altnet") || strings.Contains(ep, "rippletest") {
		return "https://testnet.xrpl.org/transactions/"
	}
	return "https://livenet.xrpl.org/transactions/"
}
