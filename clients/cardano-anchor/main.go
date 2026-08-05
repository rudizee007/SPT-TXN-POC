// Command cardano-anchor writes an SPT-Txn context hash to the Cardano ledger as
// native TRANSACTION METADATA (no Plutus, no smart contract) — the Cardano analog
// of the Sui/Aptos Move and Starknet Cairo attestation anchors. It proves that an
// SPT-Txn attestation can be anchored on Cardano for tamper-evidence, and gives
// the project a Cardano footprint that underpins the Cardano/Midnight ecosystem
// story (Midnight is Cardano's privacy partner chain; Catalyst is Cardano's grant
// program).
//
// This is an ANCHOR, not an x402 payment submitter: Cardano is not an x402 chain,
// so the footprint is a metadata-anchored tx (a tiny self-payment carrying the
// hash in a labelled metadatum), mirroring the anchor clients on the other
// non-EVM chains.
//
// Credentials (env only — never a flag, never the repo):
//
//	CARDANO_SIGNING_KEY   payment signing key, bech32 "addr_sk1…" (cardano-cli /
//	                      cardano-address export). Cardano addresses cannot be
//	                      derived from the payment key alone, so the address is
//	                      supplied separately.
//	CARDANO_ADDRESS       the sender address, bech32 "addr_test1…"/"addr1…".
//	BLOCKFROST_PROJECT_ID a free Blockfrost API key. Its network (preprod / preview
//	                      / mainnet) MUST match -network.
//
// NOTE: cardano-go (echovl/cardano-go) is WIP and low-level (manual UTXO
// selection). Expect to iterate this on the Mac against the exact library version;
// spots that may need adjustment are marked LIB-CHECK.
//
// -amount is in LOVELACE (1 ADA = 1,000,000). The hash rides on-chain in metadata.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/echovl/cardano-go"
	"github.com/echovl/cardano-go/blockfrost"
	"github.com/echovl/cardano-go/crypto"
)

const (
	keyEnv  = "CARDANO_SIGNING_KEY"
	addrEnv = "CARDANO_ADDRESS"
	bfEnv   = "BLOCKFROST_PROJECT_ID"
)

func main() {
	network := flag.String("network", "testnet", "cardano network: testnet | mainnet (must match the Blockfrost key)")
	to := flag.String("to", "", "destination address (default: self / sender)")
	amount := flag.String("amount", "1500000", "output amount in LOVELACE (1 ADA = 1e6); must be >= min-UTXO (~1 ADA)")
	hash := flag.String("hash", "", "the SPT-Txn context hash (64 hex) to anchor in metadata (required)")
	memo := flag.String("memo", "", "alias for -hash (agent compatibility)")
	label := flag.Uint64("label", 8842, "metadata label for the anchor metadatum")
	jsonOut := flag.Bool("json", false, "print only a machine-readable JSON result to stdout")
	whoami := flag.Bool("whoami", false, "print the sender address from $CARDANO_ADDRESS and exit")
	yes := flag.Bool("yes", false, "skip the mainnet confirmation prompt")
	dryRun := flag.Bool("dry-run", false, "build but do not submit")
	// Accepted for cmd/agent compatibility; unused on the anchor path.
	_ = flag.String("sourcetag", "", "ignored on Cardano (compatibility)")
	_ = flag.String("currency", "ADA", "ignored on the anchor path (compatibility)")
	flag.Parse()

	senderStr := strings.TrimSpace(os.Getenv(addrEnv))
	if *whoami {
		if senderStr == "" {
			log.Fatalf("set %s in the environment", addrEnv)
		}
		fmt.Println(senderStr)
		return
	}
	if senderStr == "" {
		log.Fatalf("set %s in the environment", addrEnv)
	}
	anchor := *hash
	if anchor == "" {
		anchor = *memo
	}
	if anchor == "" {
		log.Fatal("-hash (the 64-hex context hash to anchor) is required")
	}
	lovelace, err := strconv.ParseUint(strings.TrimSpace(*amount), 10, 64)
	if err != nil || lovelace == 0 {
		log.Fatalf("-amount must be a positive integer of lovelace, got %q", *amount)
	}

	net := cardano.Testnet
	if *network == "mainnet" {
		net = cardano.Mainnet
	}
	projectID := strings.TrimSpace(os.Getenv(bfEnv))
	if projectID == "" {
		log.Fatalf("set %s in the environment (a free Blockfrost API key for %s)", bfEnv, *network)
	}

	sender, err := cardano.NewAddress(senderStr)
	if err != nil {
		log.Fatalf("%s: %v", addrEnv, err)
	}
	receiver := sender
	if *to != "" {
		receiver, err = cardano.NewAddress(strings.TrimSpace(*to))
		if err != nil {
			log.Fatalf("-to %q: %v", *to, err)
		}
	}

	if !*jsonOut {
		fmt.Printf("cardano-anchor — %s\n", *network)
		fmt.Printf("  from (sender)   : %s\n", senderStr)
		fmt.Printf("  to              : %s\n", func() string {
			if *to == "" {
				return senderStr + " (self)"
			}
			return *to
		}())
		fmt.Printf("  amount          : %d lovelace (%.6f ADA)\n", lovelace, float64(lovelace)/1e6)
		fmt.Printf("  metadata[%d]     : spt_txn_context_hash=%s (on-chain)\n", *label, anchor)
	}

	if *network == "mainnet" && !*jsonOut && !*yes {
		fmt.Printf("\n⚠  REAL Cardano MAINNET tx: %d lovelace + metadata anchor\n   type 'yes' to proceed: ", lovelace)
		var resp string
		_, _ = fmt.Scanln(&resp)
		if strings.TrimSpace(resp) != "yes" {
			log.Fatal("aborted (not confirmed)")
		}
	}

	node := blockfrost.NewNode(net, projectID)

	pparams, err := node.ProtocolParams()
	if err != nil {
		log.Fatalf("protocol params: %v", err)
	}
	tip, err := node.Tip()
	if err != nil {
		log.Fatalf("tip: %v", err)
	}
	utxos, err := node.UTxOs(sender)
	if err != nil {
		log.Fatalf("utxos: %v", err)
	}
	if len(utxos) == 0 {
		log.Fatalf("no UTxOs at %s — fund it from the %s faucet first", senderStr, *network)
	}
	// Coin selection (simple): pick the single UTxO with the most ADA; it must
	// cover the output + fee + change min-UTXO. LIB-CHECK: Value.Coin field.
	sort.Slice(utxos, func(i, j int) bool { return utxos[i].Amount.Coin > utxos[j].Amount.Coin })
	in := utxos[0]

	txBuilder := cardano.NewTxBuilder(pparams)
	txBuilder.AddInputs(cardano.NewTxInput(in.TxHash, uint64(in.Index), in.Amount)) // LIB-CHECK: UTxO fields
	txBuilder.AddOutputs(cardano.NewTxOutput(receiver, cardano.NewValue(cardano.Coin(lovelace))))
	txBuilder.AddAuxiliaryData(&cardano.AuxiliaryData{
		Metadata: cardano.Metadata{
			*label: map[string]interface{}{
				"spt_txn_context_hash": anchor,
				"v":                    1,
			},
		},
	})
	txBuilder.SetTTL(tip.Slot + 7200) // ~2h validity
	txBuilder.AddChangeIfNeeded(sender)

	sk, err := crypto.NewPrvKey(strings.TrimSpace(os.Getenv(keyEnv)))
	if err != nil {
		log.Fatalf("%s: %v (want bech32 addr_sk1…)", keyEnv, err)
	}
	txBuilder.Sign(sk)

	tx, err := txBuilder.Build()
	if err != nil {
		log.Fatalf("build tx: %v", err)
	}
	if *dryRun {
		if *jsonOut {
			b, _ := json.Marshal(map[string]any{"dry_run": true, "cbor": tx.Hex(), "anchor": anchor})
			fmt.Println(string(b))
			return
		}
		fmt.Printf("\n  -dry-run: built, not submitted.\n  cbor: %s\n", tx.Hex())
		return
	}

	txHash, err := node.SubmitTx(tx)
	if err != nil {
		log.Fatalf("submit: %v", err)
	}
	h := txHash.String()
	explorer := explorerURL(*network, h)
	if *jsonOut {
		b, _ := json.Marshal(map[string]any{"tx_hash": h, "explorer": explorer, "status": "submitted"})
		fmt.Println(string(b))
		return
	}
	fmt.Printf("\n  SUBMITTED\n    tx hash  : %s\n    explorer : %s\n", h, explorer)
}

func explorerURL(network, hash string) string {
	switch network {
	case "mainnet":
		return "https://cardanoscan.io/transaction/" + hash
	default: // preprod/preview testnet
		return "https://preprod.cardanoscan.io/transaction/" + hash
	}
}
