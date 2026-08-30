package cattoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// The refusal lives here, beside the length check, rather than in the one HTTP
// handler that happens to call Issue today — so this is where it is tested.
//
// The test demonstrates the property before asserting the refusal: these
// encodings are not magic constants, they are public keys under which one fixed
// 64-byte value verifies as a signature over any message. If a future toolchain
// stops behaving that way, the premise check below fails loudly rather than the
// refusal quietly becoming pointless.
func TestHolderKey_DegenerateEncodingsAreRefused(t *testing.T) {
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 0x01 // R = the neutral element, S = 0

	// The forgery rate depends on the point's order: the neutral element accepts
	// it for every message, the all-zero encoding for about one in four. So the
	// premise is measured over many messages rather than asserted for one — an
	// earlier version of this test probed a single message and would have
	// reported the order-4 encoding as safe three times out of four.
	for _, k := range degenerateHolderKeys {
		const probes = 200
		hits := 0
		for i := 0; i < probes; i++ {
			if ed25519.Verify(ed25519.PublicKey(k), []byte(fmt.Sprintf("probe-%d", i)), forged) {
				hits++
			}
		}
		if hits == 0 {
			t.Fatalf("premise failed for %x: this encoding accepted the forgery for none of %d "+
				"messages on this toolchain — re-derive the set rather than trusting the table", k[:4], probes)
		}
		t.Logf("%x accepts the fixed forgery for %d/%d messages", k[:4], hits, probes)
		if err := checkHolderKey(ed25519.PublicKey(k)); err == nil {
			t.Fatalf("%x was accepted as a holder key", k[:4])
		} else if !strings.Contains(err.Error(), "degenerate") {
			t.Fatalf("unhelpful diagnosis for %x: %v", k[:4], err)
		}
	}
}

func TestHolderKey_RealKeysAreAccepted(t *testing.T) {
	forged := make([]byte, ed25519.SignatureSize)
	forged[0] = 0x01
	for i := 0; i < 32; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519.Verify(pub, []byte("x"), forged) {
			t.Fatalf("a generated key accepted the forgery — %x", pub[:4])
		}
		if err := checkHolderKey(pub); err != nil {
			t.Fatalf("a real key was refused: %v", err)
		}
	}
}

// Issue itself must refuse, not just the helper — a guard nothing calls is not
// a guard.
func TestIssue_RefusesADegenerateHolderKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 0x01
	_, err = Issue(IssueRequest{
		Issuer: "iss", Subject: "sub", PrincipalName: "p",
		Scope:              CapabilityScope{"action": "transfer", "max_amount": 10, "currency": "USD"},
		DelegationDepthMax: 1,
		HolderPublicKey:    ed25519.PublicKey(identity),
	}, priv)
	if err == nil {
		t.Fatal("Issue sealed a holder key that constrains nobody")
	}
}
