// Command hedera-pay submits a real Hedera HBAR transfer from an x402gate ALLOW
// decision — the Hedera analog of clients/xrpl-pay (demo phase P0-H).
//
// The offline core (cmd/gatesvc) decides IF the agent may pay and emits the
// stamp fields (destination, amount, humanAnchor). This tool settles the HBAR
// transfer on Hedera, carrying the zero-knowledge humanAnchor in the
// transaction memo — accountable, no PII on the wire.
//
// Lives in its own module so the Hedera SDK never enters the offline core.
//
// Credentials (env only — never a flag, never the repo), same as clients/hcs-anchor:
//
//	HEDERA_OPERATOR_ID    payer account, e.g. 0.0.1234567   (the "agent")
//	HEDERA_OPERATOR_KEY   its private key (DER or hex)
//
// Security:
//   - Default network is TESTNET. Mainnet requires -network mainnet AND passes a
//     confirmation prompt (skipped with -yes or -json).
//   - -dry-run builds and prints the transfer without any network call.
//
// Usage:
//
//	export HEDERA_OPERATOR_ID=0.0.xxxxx HEDERA_OPERATOR_KEY=302e0201...
//	go run . -to 0.0.yyyyy -amount 1000 -memo <anchorHex> -dry-run
//	go run . -to 0.0.yyyyy -amount 1000 -memo <anchorHex>            # settle on testnet
//
// -amount is in TINYBARS (1 HBAR = 100,000,000 tinybars), mirroring xrpl-pay's
// drops so the gate ceiling/price numbers carry over unchanged.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

const (
	opIDEnv  = "HEDERA_OPERATOR_ID"
	opKeyEnv = "HEDERA_OPERATOR_KEY"
)

func main() {
	network := flag.String("network", "testnet", "hedera network: testnet | mainnet | previewnet")
	to := flag.String("to", "", "destination account id, e.g. 0.0.12345 (required)")
	amount := flag.String("amount", "", "amount in TINYBARS (required); 1 HBAR = 100,000,000 tinybars")
	currency := flag.String("currency", "HBAR", "currency: HBAR (HTS tokens are a later step)")
	memo := flag.String("memo", "", "humanAnchor to carry in the transaction memo (from x402gate ALLOW)")
	// Accepted for cmd/agent compatibility (the agent passes the same flags to
	// any pay backend). Hedera has no source tag, and the anchor memo already
	// carries the binding, so these are ignored here.
	_ = flag.String("sourcetag", "", "ignored on Hedera (agent compatibility)")
	_ = flag.String("context-hash", "", "ignored on Hedera (agent compatibility)")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout (for cmd/agent)")
	whoami := flag.Bool("whoami", false, "print the operator account id from the environment and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt (non-interactive use)")
	dryRun := flag.Bool("dry-run", false, "build and print the transfer without connecting or submitting")
	flag.Parse()

	if *whoami {
		id := os.Getenv(opIDEnv)
		if id == "" {
			log.Fatalf("%s is not set", opIDEnv)
		}
		if _, err := hiero.AccountIDFromString(id); err != nil {
			log.Fatalf("%s: %v", opIDEnv, err)
		}
		fmt.Println(id)
		return
	}

	if *to == "" || *amount == "" {
		log.Fatal("both -to and -amount are required")
	}
	if strings.ToUpper(*currency) != "HBAR" {
		log.Fatalf("currency %q not yet supported: only HBAR for now (HTS tokens later)", *currency)
	}
	tinybars, err := strconv.ParseInt(strings.TrimSpace(*amount), 10, 64)
	if err != nil || tinybars <= 0 {
		log.Fatalf("-amount must be a positive integer of tinybars, got %q", *amount)
	}
	if len(*memo) > 100 {
		log.Fatalf("memo exceeds Hedera's 100-byte limit (%d bytes)", len(*memo))
	}

	opID := os.Getenv(opIDEnv)
	opKey := os.Getenv(opKeyEnv)
	if opID == "" || opKey == "" {
		log.Fatalf("set %s and %s in the environment (never a flag or the repo)", opIDEnv, opKeyEnv)
	}
	senderID, err := hiero.AccountIDFromString(opID)
	if err != nil {
		log.Fatalf("%s: %v", opIDEnv, err)
	}
	receiverID, err := hiero.AccountIDFromString(*to)
	if err != nil {
		log.Fatalf("-to %q: %v", *to, err)
	}
	if senderID.String() == receiverID.String() {
		log.Fatal("sender and receiver must differ (use your second testnet account as -to)")
	}

	if !*jsonOut {
		fmt.Printf("hedera-pay — %s\n", *network)
		fmt.Printf("  from (payer agent) : %s\n", opID)
		fmt.Printf("  to (merchant)      : %s\n", *to)
		fmt.Printf("  amount             : %d tinybars (%.8f HBAR)\n", tinybars, float64(tinybars)/1e8)
		if *memo != "" {
			fmt.Printf("  memo[humanAnchor]  : %s\n", *memo)
		}
	}

	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "from": opID, "to": *to, "tinybars": tinybars, "memo": *memo})
			fmt.Println(string(b))
			return
		}
		fmt.Println("\n  -dry-run: not connecting, not submitting.")
		return
	}

	// Real-money guardrail on mainnet.
	if isMainnet(*network) && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL payment on Hedera %s: %d tinybars to %s\n   type 'yes' to proceed: ", *network, tinybars, *to)
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	client, err := newClient(*network, senderID, opKey)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	amt := hiero.HbarFromTinybar(tinybars)
	tx := hiero.NewTransferTransaction().
		AddHbarTransfer(senderID, amt.Negated()).
		AddHbarTransfer(receiverID, amt)
	if *memo != "" {
		tx = tx.SetTransactionMemo(*memo)
	}
	resp, err := tx.Execute(client)
	if err != nil {
		log.Fatalf("execute transfer: %v", err)
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		log.Fatalf("transfer receipt: %v", err)
	}
	txID := resp.TransactionID.String()
	explorer := fmt.Sprintf("https://hashscan.io/%s/transaction/%s", *network, txID)

	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": txID, "explorer": explorer, "status": receipt.Status.String()})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n")
	fmt.Printf("    transaction id : %s\n", txID)
	fmt.Printf("    status         : %s\n", receipt.Status.String())
	fmt.Printf("    explorer       : %s\n", explorer)
}

// newClient builds a Hedera network client with the operator set (mirrors
// clients/hcs-anchor.newClient).
func newClient(network string, opID hiero.AccountID, opKeyStr string) (*hiero.Client, error) {
	var client *hiero.Client
	switch network {
	case "testnet":
		client = hiero.ClientForTestnet()
	case "mainnet":
		client = hiero.ClientForMainnet()
	case "previewnet":
		client = hiero.ClientForPreviewnet()
	default:
		return nil, fmt.Errorf("unknown network %q (want testnet|mainnet|previewnet)", network)
	}
	opKey, err := hiero.PrivateKeyFromString(opKeyStr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opKeyEnv, err)
	}
	client.SetOperator(opID, opKey)
	return client, nil
}

func isMainnet(network string) bool { return network == "mainnet" }
