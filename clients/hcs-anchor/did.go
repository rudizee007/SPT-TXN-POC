package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// did.go — a POC interpretation of the Hedera DID method (did:hedera) for
// SPT-Txn milestone A2. It follows the method's MECHANISM — a DID document
// created/updated via HCS messages and resolved by folding those messages from
// the public mirror node — but it is NOT the certified did-sdk-js/-java envelope
// (there is no Go DID SDK). The DID-document assembly, event encoding, and the
// resolution fold here are pure standard-library and unit-tested; only the
// publish step (in main.go) touches the Hedera SDK.

// base58 alphabet (Bitcoin/IPFS), used for the DID method-specific id and the
// Ed25519 publicKeyMultibase.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58btc(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	zero := big.NewInt(0)
	var out []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// ed25519Multibase encodes a public key as a multibase (base58btc, 'z') string
// with the Ed25519 multicodec prefix (0xed01) — the publicKeyMultibase form used
// by Ed25519VerificationKey2020.
func ed25519Multibase(pub ed25519.PublicKey) string {
	return "z" + base58btc(append([]byte{0xed, 0x01}, pub...))
}

type verificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// DIDDocument is a minimal W3C DID document for the issuer DID.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []verificationMethod `json:"verificationMethod"`
	AssertionMethod    []string             `json:"assertionMethod"`
	Service            []service            `json:"service,omitempty"`
}

// BuildIssuerDID constructs the did:hedera identifier and DID document for a CT/CAT
// issuer's Ed25519 key on the given network + topic, binding the (optional)
// humanAnchor commitment as a service. anchorHex, when present, must be 32 bytes.
func BuildIssuerDID(network, topicID string, pub ed25519.PublicKey, anchorHex string) (string, DIDDocument, error) {
	if _, err := mirrorBase(network); err != nil {
		return "", DIDDocument{}, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", DIDDocument{}, fmt.Errorf("issuer public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if topicID == "" {
		return "", DIDDocument{}, fmt.Errorf("topic id required for the DID method-specific id")
	}
	did := fmt.Sprintf("did:hedera:%s:%s_%s", network, base58btc(pub), topicID)
	vmID := did + "#did-root-key"
	doc := DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []verificationMethod{{
			ID:                 vmID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: ed25519Multibase(pub),
		}},
		AssertionMethod: []string{vmID},
	}
	if anchorHex != "" {
		doc.Service = []service{{
			ID:              did + "#human-anchor",
			Type:            "SptTxnHumanAnchor",
			ServiceEndpoint: "urn:spt-txn:humananchor:" + anchorHex,
		}}
	}
	return did, doc, nil
}

// DIDEventVersion is the on-wire DID-event format version.
const DIDEventVersion = 1

// DIDEvent is one CRUD message published to the DID's HCS topic. The resolved
// document is the fold of these events in consensus order.
type DIDEvent struct {
	V        int          `json:"v"`
	Op       string       `json:"op"` // "create" | "update"
	DID      string       `json:"did"`
	Document *DIDDocument `json:"document"`
	Ts       int64        `json:"ts,omitempty"`
}

// Bytes is the exact HCS message payload for a DID event.
func (e DIDEvent) Bytes() ([]byte, error) {
	if e.V != DIDEventVersion {
		return nil, fmt.Errorf("unsupported DID event version %d", e.V)
	}
	return json.Marshal(e)
}

// ParseDIDEvent decodes an HCS message into a DID event, rejecting unknown versions.
func ParseDIDEvent(b []byte) (DIDEvent, error) {
	var e DIDEvent
	if err := json.Unmarshal(b, &e); err != nil {
		return DIDEvent{}, fmt.Errorf("not a valid DID event: %w", err)
	}
	if e.V != DIDEventVersion {
		return DIDEvent{}, fmt.Errorf("unsupported DID event version %d", e.V)
	}
	return e, nil
}

// ResolveFromEvents folds DID events (in consensus order) into the current DID
// document for the given DID: the first `create` establishes it, later `update`s
// replace it. Events for other DIDs are ignored.
func ResolveFromEvents(events []DIDEvent, did string) (*DIDDocument, error) {
	var doc *DIDDocument
	for _, e := range events {
		if e.DID != did || e.Document == nil {
			continue
		}
		switch e.Op {
		case "create":
			if doc == nil {
				d := *e.Document
				doc = &d
			}
		case "update":
			d := *e.Document
			doc = &d
		}
	}
	if doc == nil {
		return nil, fmt.Errorf("no DID document resolved for %s", did)
	}
	return doc, nil
}

// topicFromDID extracts the network and topic id from a did:hedera identifier of
// the form did:hedera:<network>:<key>_<topicId>.
func topicFromDID(did string) (network, topicID string, err error) {
	const prefix = "did:hedera:"
	if !strings.HasPrefix(did, prefix) {
		return "", "", fmt.Errorf("not a did:hedera DID: %q", did)
	}
	rest := did[len(prefix):] // <network>:<key>_<topic>
	i := strings.Index(rest, ":")
	if i < 0 {
		return "", "", fmt.Errorf("malformed did:hedera (no network): %q", did)
	}
	network = rest[:i]
	methodID := rest[i+1:] // <key>_<topic>
	j := strings.LastIndex(methodID, "_")
	if j < 0 {
		return "", "", fmt.Errorf("malformed did:hedera (no topic): %q", did)
	}
	topicID = methodID[j+1:]
	if network == "" || topicID == "" {
		return "", "", fmt.Errorf("malformed did:hedera: %q", did)
	}
	return network, topicID, nil
}

// resolveDID reads the DID's topic from the public mirror node (keyless) and
// folds its events into the current DID document.
func resolveDID(did string, timeout time.Duration) (*DIDDocument, error) {
	network, topicID, err := topicFromDID(did)
	if err != nil {
		return nil, err
	}
	msgs, err := fetchTopicMessages(network, topicID, timeout)
	if err != nil {
		return nil, err
	}
	var events []DIDEvent
	for _, m := range msgs {
		e, err := ParseDIDEvent(m)
		if err != nil {
			continue // not a DID event
		}
		events = append(events, e)
	}
	return ResolveFromEvents(events, did)
}
