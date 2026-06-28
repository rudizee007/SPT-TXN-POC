// Command hcs-anchor anchors an SPT-Txn context hash or audit-log Merkle root to
// a Hedera Consensus Service (HCS) topic, and verifies anchors via the public
// mirror node. It is Hedera grant milestone A1.
//
// It deliberately lives OUTSIDE the SPT-Txn authorization core, in its own Go
// module: the verifier/token packages never import the Hedera SDK (the
// blockchain-agnostic invariant). This client holds the Hedera operator
// credentials and submits transactions; the core does not. The hash it anchors
// is produced by the main module's `cmd/anchor` (the real spt_txn_context_hash),
// or is an audit-log Merkle root.
//
// Credentials come from the ENVIRONMENT, never flags (flags leak via the process
// list and shell history):
//
//	HEDERA_OPERATOR_ID    e.g. 0.0.12345
//	HEDERA_OPERATOR_KEY   the operator private key string
//
// Subcommands:
//
//	hcs-anchor create-topic [-network testnet]
//	hcs-anchor anchor  -topic 0.0.X -type ctx -hash <64hex> [-network testnet]
//	hcs-anchor verify  -topic 0.0.X -hash <64hex>           [-network testnet]   (keyless)
//
// create-topic and anchor require the operator credentials + HBAR (your action).
// verify uses only the public mirror node — no key, no cost.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "create-topic":
		fs := flag.NewFlagSet("create-topic", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		_ = fs.Parse(os.Args[2:])
		err = cmdCreateTopic(*network)
	case "anchor":
		fs := flag.NewFlagSet("anchor", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		topic := fs.String("topic", "", "HCS topic id, e.g. 0.0.12345")
		typ := fs.String("type", "ctx", "anchor type: ctx (context hash) | audit (audit root)")
		hash := fs.String("hash", "", "32-byte hash in hex (the spt_txn_context_hash or audit root)")
		_ = fs.Parse(os.Args[2:])
		err = cmdAnchor(*network, *topic, *typ, *hash)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		topic := fs.String("topic", "", "HCS topic id, e.g. 0.0.12345")
		hash := fs.String("hash", "", "32-byte hash in hex to look for")
		_ = fs.Parse(os.Args[2:])
		err = cmdVerify(*network, *topic, *hash)
	case "did-create":
		fs := flag.NewFlagSet("did-create", flag.ExitOnError)
		network := fs.String("network", "testnet", "testnet|mainnet|previewnet")
		topic := fs.String("topic", "", "existing HCS topic id; empty creates a new one")
		issuerPub := fs.String("issuer-pub", "", "issuer Ed25519 public key hex (32 bytes); empty generates a demo key")
		anchor := fs.String("anchor", "", "humanAnchor commitment hex (32 bytes) to bind into the DID document")
		_ = fs.Parse(os.Args[2:])
		err = cmdDIDCreate(*network, *topic, *issuerPub, *anchor)
	case "did-resolve":
		fs := flag.NewFlagSet("did-resolve", flag.ExitOnError)
		did := fs.String("did", "", "did:hedera identifier to resolve")
		_ = fs.Parse(os.Args[2:])
		err = cmdDIDResolve(*did)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hcs-anchor — anchor SPT-Txn hashes to Hedera Consensus Service (milestone A1)

  hcs-anchor create-topic [-network testnet]
  hcs-anchor anchor      -topic 0.0.X -type ctx -hash <64hex> [-network testnet]
  hcs-anchor verify      -topic 0.0.X -hash <64hex>           [-network testnet]   (keyless)
  hcs-anchor did-create  [-topic 0.0.X] [-issuer-pub <64hex>] [-anchor <64hex>] [-network testnet]   (A2)
  hcs-anchor did-resolve -did did:hedera:testnet:..._0.0.X                                            (keyless)

create-topic / anchor / did-create read HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY from the environment.
verify and did-resolve use only the public mirror node (no key, no cost).
`)
}

// newClient builds a network client with the operator from the environment.
// Used only by the write subcommands; verify never calls it.
func newClient(network string) (*hiero.Client, error) {
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
	idStr, keyStr := os.Getenv("HEDERA_OPERATOR_ID"), os.Getenv("HEDERA_OPERATOR_KEY")
	if idStr == "" || keyStr == "" {
		return nil, fmt.Errorf("set HEDERA_OPERATOR_ID and HEDERA_OPERATOR_KEY in the environment")
	}
	opID, err := hiero.AccountIDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("HEDERA_OPERATOR_ID: %w", err)
	}
	opKey, err := hiero.PrivateKeyFromString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("HEDERA_OPERATOR_KEY: %w", err)
	}
	client.SetOperator(opID, opKey)
	return client, nil
}

func cmdCreateTopic(network string) error {
	client, err := newClient(network)
	if err != nil {
		return err
	}
	defer client.Close()

	resp, err := hiero.NewTopicCreateTransaction().
		SetTopicMemo("spt-txn anchor topic").
		Execute(client)
	if err != nil {
		return fmt.Errorf("create topic: %w", err)
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		return fmt.Errorf("create topic receipt: %w", err)
	}
	if receipt.TopicID == nil {
		return fmt.Errorf("no topic id in receipt (status %s)", receipt.Status)
	}
	fmt.Printf("created HCS topic %s on %s\n", receipt.TopicID.String(), network)
	fmt.Printf("anchor to it with:  hcs-anchor anchor -network %s -topic %s -type ctx -hash <64hex>\n", network, receipt.TopicID.String())
	return nil
}

func cmdAnchor(network, topic, typ, hash string) error {
	if topic == "" {
		return fmt.Errorf("-topic is required")
	}
	env, err := NewEnvelope(AnchorType(typ), hash)
	if err != nil {
		return err
	}
	msg, err := env.Bytes()
	if err != nil {
		return err
	}
	client, err := newClient(network)
	if err != nil {
		return err
	}
	defer client.Close()

	topicID, err := hiero.TopicIDFromString(topic)
	if err != nil {
		return fmt.Errorf("topic id %q: %w", topic, err)
	}
	resp, err := hiero.NewTopicMessageSubmitTransaction().
		SetTopicID(topicID).
		SetMessage(msg).
		Execute(client)
	if err != nil {
		return fmt.Errorf("submit message: %w", err)
	}
	receipt, err := resp.GetReceipt(client)
	if err != nil {
		return fmt.Errorf("submit receipt: %w", err)
	}
	fmt.Printf("anchored %s hash %s to topic %s (status %s)\n", env.Type, env.Hash, topic, receipt.Status)
	fmt.Printf("confirm the durable, keyless proof (consensus timestamp + sequence) with:\n")
	fmt.Printf("  hcs-anchor verify -network %s -topic %s -hash %s\n", network, topic, env.Hash)
	return nil
}

func cmdVerify(network, topic, hash string) error {
	if topic == "" || hash == "" {
		return fmt.Errorf("-topic and -hash are required")
	}
	proof, err := VerifyOnMirror(network, topic, hash, 25*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("ANCHORED  type=%s hash=%s\n", proof.Type, proof.Hash)
	fmt.Printf("  topic               : %s\n", proof.TopicID)
	fmt.Printf("  sequence number     : %d\n", proof.SequenceNumber)
	fmt.Printf("  consensus timestamp : %s\n", proof.ConsensusTimestamp)
	return nil
}

// cmdDIDCreate builds a did:hedera DID document for an issuer key (binding the
// humanAnchor), publishes it as a create event to an HCS topic, and prints the
// resulting DID. Milestone A2.
func cmdDIDCreate(network, topic, issuerPubHex, anchorHex string) error {
	var pub ed25519.PublicKey
	if issuerPubHex != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(issuerPubHex, "0x"))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("-issuer-pub must be a 32-byte Ed25519 public key in hex")
		}
		pub = ed25519.PublicKey(b)
	} else {
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pub = p
		fmt.Println("generated a demo issuer Ed25519 key (bind your real CT-issuer key with -issuer-pub):")
		fmt.Printf("  public : %s\n", hex.EncodeToString(p))
		fmt.Printf("  private: %s\n", hex.EncodeToString(s))
	}
	if anchorHex != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(anchorHex, "0x"))
		if err != nil || len(b) != 32 {
			return fmt.Errorf("-anchor must be a 32-byte humanAnchor commitment in hex")
		}
		anchorHex = strings.ToLower(strings.TrimPrefix(anchorHex, "0x"))
	}

	client, err := newClient(network)
	if err != nil {
		return err
	}
	defer client.Close()

	topicID := topic
	if topicID == "" {
		resp, err := hiero.NewTopicCreateTransaction().SetTopicMemo("spt-txn did:hedera topic").Execute(client)
		if err != nil {
			return fmt.Errorf("create DID topic: %w", err)
		}
		rcpt, err := resp.GetReceipt(client)
		if err != nil {
			return fmt.Errorf("create DID topic receipt: %w", err)
		}
		if rcpt.TopicID == nil {
			return fmt.Errorf("no topic id in receipt (status %s)", rcpt.Status)
		}
		topicID = rcpt.TopicID.String()
	}

	did, doc, err := BuildIssuerDID(network, topicID, pub, anchorHex)
	if err != nil {
		return err
	}
	event := DIDEvent{V: DIDEventVersion, Op: "create", DID: did, Document: &doc, Ts: time.Now().Unix()}
	msg, err := event.Bytes()
	if err != nil {
		return err
	}
	tid, err := hiero.TopicIDFromString(topicID)
	if err != nil {
		return fmt.Errorf("topic id %q: %w", topicID, err)
	}
	resp, err := hiero.NewTopicMessageSubmitTransaction().SetTopicID(tid).SetMessage(msg).Execute(client)
	if err != nil {
		return fmt.Errorf("publish DID create event: %w", err)
	}
	rcpt, err := resp.GetReceipt(client)
	if err != nil {
		return fmt.Errorf("DID create receipt: %w", err)
	}
	fmt.Printf("created DID (status %s):\n  %s\n  topic: %s\n", rcpt.Status, did, topicID)
	fmt.Printf("resolve (keyless): hcs-anchor did-resolve -did %s\n", did)
	return nil
}

// cmdDIDResolve resolves a did:hedera from the public mirror node (keyless) and
// prints the DID document.
func cmdDIDResolve(did string) error {
	if did == "" {
		return fmt.Errorf("-did is required")
	}
	doc, err := resolveDID(did, 25*time.Second)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
