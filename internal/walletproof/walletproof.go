// Package walletproof implements proof-of-control for self-hosted (unhosted)
// wallets — the verification the EU Transfer of Funds Regulation requires for
// transfers to/from a self-hosted wallet at or above €1000: the CASP must
// establish that its customer owns or controls the address.
//
// The flow is a signed challenge:
//
//  1. The CASP issues a Challenge binding the customer's human_anchor, the chain,
//     and the claimed address, with a fresh nonce and short expiry.
//  2. The customer signs the challenge's canonical bytes with the wallet's
//     private key and returns the public key + signature.
//  3. Verify checks the signature, that the public key derives the claimed
//     address (per-chain AddressDeriver), and the expiry — producing a
//     ControlProof bound to the human_anchor that can be folded into the Travel
//     Rule attestation.
//
// Scope: Ed25519 wallets (Solana, and any chain whose address is an encoding of
// an Ed25519 key). secp256k1/EVM and chain-specific encodings (Stellar strkey,
// Aptos/Sui hash-with-scheme-flag) plug in by implementing AddressDeriver. The
// signature check itself is FIPS-approved Ed25519.
package walletproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrExpired       = errors.New("walletproof: challenge expired or not yet valid")
	ErrBadSignature  = errors.New("walletproof: signature does not verify under the public key")
	ErrAddrMismatch  = errors.New("walletproof: public key does not derive the claimed address")
	ErrBadPublicKey  = errors.New("walletproof: public key is not a 32-byte Ed25519 key")
	ErrEmptyField    = errors.New("walletproof: chain, address and humanAnchor are required")
)

// Challenge is the message the customer must sign to prove control. Its
// canonical bytes are domain-separated so a signature for one purpose can never
// be replayed for another.
type Challenge struct {
	Chain       string
	Address     string
	HumanAnchor string
	Nonce       string // hex, 32 random bytes
	IssuedAt    int64  // unix seconds
	Expiry      int64  // unix seconds
}

const domainTag = "spt-txn/wallet-control/v1"

// NewChallenge builds a fresh challenge with a random nonce and the given TTL.
func NewChallenge(chain, address, humanAnchor string, ttl time.Duration) (Challenge, error) {
	if chain == "" || address == "" || humanAnchor == "" {
		return Challenge{}, ErrEmptyField
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Challenge{}, fmt.Errorf("walletproof: nonce: %w", err)
	}
	now := time.Now().UTC()
	return Challenge{
		Chain:       chain,
		Address:     address,
		HumanAnchor: humanAnchor,
		Nonce:       hex.EncodeToString(nonce[:]),
		IssuedAt:    now.Unix(),
		Expiry:      now.Add(ttl).Unix(),
	}, nil
}

// Bytes is the deterministic, domain-separated preimage the customer signs.
// Newlines separate fields; fields cannot contain newlines (all are hex/IDs).
func (c Challenge) Bytes() []byte {
	var b strings.Builder
	b.WriteString(domainTag)
	b.WriteByte('\n')
	b.WriteString(c.Chain)
	b.WriteByte('\n')
	b.WriteString(c.Address)
	b.WriteByte('\n')
	b.WriteString(c.HumanAnchor)
	b.WriteByte('\n')
	b.WriteString(c.Nonce)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%d\n%d", c.IssuedAt, c.Expiry)
	return []byte(b.String())
}

// Response is the customer's reply.
type Response struct {
	PublicKey []byte // raw 32-byte Ed25519 public key
	Signature []byte // Ed25519 signature over Challenge.Bytes()
}

// ControlProof is the verified result: at VerifiedAt, the holder of the key
// behind Address (on Chain) controls it, and that control is bound to
// HumanAnchor.
type ControlProof struct {
	Chain       string
	Address     string
	HumanAnchor string
	VerifiedAt  int64
}

// Claims renders the proof as SD-JWT-ready claims (no secret material) so it can
// be folded into the Travel Rule attestation as evidence of self-hosted control.
func (p ControlProof) Claims() map[string]any {
	return map[string]any{
		"selfhosted_control":         true,
		"selfhosted_chain":           p.Chain,
		"selfhosted_address":         p.Address,
		"selfhosted_verified_at":     p.VerifiedAt,
		"selfhosted_bound_anchor":    p.HumanAnchor,
	}
}

// AddressDeriver maps an Ed25519 public key to a chain address string.
type AddressDeriver interface {
	Derive(pub ed25519.PublicKey) (string, error)
	Scheme() string
}

// Verify checks the response against the challenge and returns a ControlProof.
// It fails closed: expiry, key shape, address derivation, and signature are all
// required. now is passed in for testability.
func Verify(c Challenge, r Response, now time.Time, deriver AddressDeriver) (*ControlProof, error) {
	if c.Chain == "" || c.Address == "" || c.HumanAnchor == "" {
		return nil, ErrEmptyField
	}
	t := now.UTC().Unix()
	if t < c.IssuedAt || t > c.Expiry {
		return nil, ErrExpired
	}
	if len(r.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrBadPublicKey
	}
	pub := ed25519.PublicKey(r.PublicKey)
	got, err := deriver.Derive(pub)
	if err != nil {
		return nil, fmt.Errorf("walletproof: derive: %w", err)
	}
	if got != c.Address {
		return nil, ErrAddrMismatch
	}
	if !ed25519.Verify(pub, c.Bytes(), r.Signature) {
		return nil, ErrBadSignature
	}
	return &ControlProof{
		Chain:       c.Chain,
		Address:     c.Address,
		HumanAnchor: c.HumanAnchor,
		VerifiedAt:  t,
	}, nil
}

// ── Address derivers ─────────────────────────────────────────────────────────

// SolanaDeriver: a Solana address is the base58 encoding of the 32-byte Ed25519
// public key.
type SolanaDeriver struct{}

func (SolanaDeriver) Scheme() string { return "solana" }
func (SolanaDeriver) Derive(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", ErrBadPublicKey
	}
	return base58Encode(pub), nil
}

// HexDeriver: address is the lowercase hex of the public key. Useful for chains
// (and tests) that address by the raw key, and as a fallback.
type HexDeriver struct{}

func (HexDeriver) Scheme() string { return "hex" }
func (HexDeriver) Derive(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", ErrBadPublicKey
	}
	return hex.EncodeToString(pub), nil
}

// base58Encode encodes bytes with the Bitcoin/Solana base58 alphabet, preserving
// leading-zero bytes as leading '1's.
func base58Encode(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// count leading zero bytes
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, alphabet[0])
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
