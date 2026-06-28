package walletproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestProofOfControl_HappyPath_Solana(t *testing.T) {
	pub, priv := keypair(t)
	addr, _ := SolanaDeriver{}.Derive(pub)

	ch, err := NewChallenge("solana", addr, "0xanchor123", time.Minute)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	sig := ed25519.Sign(priv, ch.Bytes())

	proof, err := Verify(ch, Response{PublicKey: pub, Signature: sig}, time.Now(), SolanaDeriver{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if proof.Address != addr || proof.HumanAnchor != "0xanchor123" || proof.Chain != "solana" {
		t.Fatalf("proof fields wrong: %+v", proof)
	}
	if c := proof.Claims(); c["selfhosted_control"] != true {
		t.Fatalf("claims missing control flag: %v", c)
	}
}

func TestProofOfControl_WrongKeyRejected(t *testing.T) {
	pub, _ := keypair(t)
	_, otherPriv := keypair(t)
	addr, _ := SolanaDeriver{}.Derive(pub)
	ch, _ := NewChallenge("solana", addr, "anchor", time.Minute)
	sig := ed25519.Sign(otherPriv, ch.Bytes()) // signed by a different key

	if _, err := Verify(ch, Response{PublicKey: pub, Signature: sig}, time.Now(), SolanaDeriver{}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestProofOfControl_AddressMismatchRejected(t *testing.T) {
	pub, priv := keypair(t)
	ch, _ := NewChallenge("solana", "SomeOtherAddress11111111111111111111111111", "anchor", time.Minute)
	sig := ed25519.Sign(priv, ch.Bytes())
	if _, err := Verify(ch, Response{PublicKey: pub, Signature: sig}, time.Now(), SolanaDeriver{}); !errors.Is(err, ErrAddrMismatch) {
		t.Fatalf("got %v, want ErrAddrMismatch", err)
	}
}

func TestProofOfControl_Expired(t *testing.T) {
	pub, priv := keypair(t)
	addr, _ := SolanaDeriver{}.Derive(pub)
	ch, _ := NewChallenge("solana", addr, "anchor", time.Minute)
	sig := ed25519.Sign(priv, ch.Bytes())
	future := time.Now().Add(2 * time.Minute)
	if _, err := Verify(ch, Response{PublicKey: pub, Signature: sig}, future, SolanaDeriver{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestProofOfControl_TamperedChallengeRejected(t *testing.T) {
	pub, priv := keypair(t)
	addr, _ := SolanaDeriver{}.Derive(pub)
	ch, _ := NewChallenge("solana", addr, "anchor", time.Minute)
	sig := ed25519.Sign(priv, ch.Bytes())
	ch.HumanAnchor = "different-anchor" // change the bound anchor after signing
	if _, err := Verify(ch, Response{PublicKey: pub, Signature: sig}, time.Now(), SolanaDeriver{}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature on tampered anchor", err)
	}
}

func TestBase58_Vectors(t *testing.T) {
	// Hand-verified against the Bitcoin/Solana alphabet
	// "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x00}, "1"},       // single zero byte → one '1'
		{[]byte{0x00, 0x00}, "11"}, // two zero bytes → "11"
		{[]byte{0x00, 0x01}, "12"}, // leading zero preserved, then 1 → '2'
		{[]byte{57}, "z"},          // index 57 in the alphabet is 'z'
		{[]byte{58}, "21"},         // 58 = 1*58 + 0 → "21"
	}
	for _, c := range cases {
		if got := base58Encode(c.in); got != c.want {
			t.Fatalf("base58(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
