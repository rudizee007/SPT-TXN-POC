package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// deterministic 32-byte pubkey for stable assertions.
func testPub() ed25519.PublicKey {
	b := make([]byte, ed25519.PublicKeySize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return ed25519.PublicKey(b)
}

func TestBuildIssuerDID(t *testing.T) {
	pub := testPub()
	anchor := "944831c5815b38b7b2f65ff6e908b0b9e01ea09949c0bb39106dbde2e7547581"
	did, doc, err := BuildIssuerDID("testnet", "0.0.9357269", pub, anchor)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.HasPrefix(did, "did:hedera:testnet:") || !strings.HasSuffix(did, "_0.0.9357269") {
		t.Errorf("did shape wrong: %s", did)
	}
	if doc.ID != did {
		t.Errorf("doc.id %s != did %s", doc.ID, did)
	}
	if len(doc.VerificationMethod) != 1 || !strings.HasPrefix(doc.VerificationMethod[0].PublicKeyMultibase, "z") {
		t.Errorf("verificationMethod/multibase wrong: %+v", doc.VerificationMethod)
	}
	if len(doc.AssertionMethod) != 1 || doc.AssertionMethod[0] != doc.VerificationMethod[0].ID {
		t.Errorf("assertionMethod must reference the vm: %+v", doc.AssertionMethod)
	}
	if len(doc.Service) != 1 || !strings.Contains(doc.Service[0].ServiceEndpoint, anchor) {
		t.Errorf("humanAnchor service not bound: %+v", doc.Service)
	}
}

func TestBuildIssuerDID_Rejects(t *testing.T) {
	if _, _, err := BuildIssuerDID("testnet", "0.0.1", make([]byte, 31), ""); err == nil {
		t.Error("expected rejection of a short public key")
	}
	if _, _, err := BuildIssuerDID("bogusnet", "0.0.1", testPub(), ""); err == nil {
		t.Error("expected rejection of an unknown network")
	}
	if _, _, err := BuildIssuerDID("testnet", "", testPub(), ""); err == nil {
		t.Error("expected rejection of an empty topic")
	}
}

func TestDIDEvent_RoundTrip(t *testing.T) {
	pub := testPub()
	did, doc, _ := BuildIssuerDID("testnet", "0.0.5", pub, "")
	e := DIDEvent{V: DIDEventVersion, Op: "create", DID: did, Document: &doc, Ts: 1750000000}
	b, err := e.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	got, err := ParseDIDEvent(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.DID != did || got.Op != "create" || got.Document == nil || got.Document.ID != did {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestResolveFromEvents(t *testing.T) {
	pub := testPub()
	did, doc1, _ := BuildIssuerDID("testnet", "0.0.7", pub, "")
	// an unrelated event for a different DID must be ignored
	otherDID, otherDoc, _ := BuildIssuerDID("testnet", "0.0.8", pub, "")
	// an update that adds a humanAnchor service
	_, doc2, _ := BuildIssuerDID("testnet", "0.0.7", pub, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

	events := []DIDEvent{
		{V: DIDEventVersion, Op: "create", DID: did, Document: &doc1},
		{V: DIDEventVersion, Op: "create", DID: otherDID, Document: &otherDoc},
		{V: DIDEventVersion, Op: "update", DID: did, Document: &doc2},
	}
	resolved, err := ResolveFromEvents(events, did)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ID != did {
		t.Errorf("resolved wrong DID: %s", resolved.ID)
	}
	if len(resolved.Service) != 1 {
		t.Errorf("update not applied (expected humanAnchor service): %+v", resolved.Service)
	}
	if _, err := ResolveFromEvents(events, "did:hedera:testnet:nope_0.0.9"); err == nil {
		t.Error("expected error resolving a DID with no events")
	}
}

func TestTopicFromDID(t *testing.T) {
	net, topic, err := topicFromDID("did:hedera:testnet:abc123_0.0.9357269")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if net != "testnet" || topic != "0.0.9357269" {
		t.Errorf("got net=%s topic=%s", net, topic)
	}
	for _, bad := range []string{"did:web:example.com", "did:hedera:testnet:noTopic", "did:hedera::_0.0.1"} {
		if _, _, err := topicFromDID(bad); err == nil {
			t.Errorf("expected rejection of %q", bad)
		}
	}
}
