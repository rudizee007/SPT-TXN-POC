// Package escrow implements the SPT-Txn Section 9.6 escrow envelope and
// deanonymization flow — Milestone 7.
//
// At CAT issuance the real identity behind a humanAnchor is sealed into an
// escrow envelope encrypted to the escrow authority's key. The envelope is
// stored keyed by humanAnchor and is never touched during normal transactions.
// It can be opened only via a signed, lawful-basis deanonymization request
// (deanon.go), giving accountable anonymity: holders are pseudonymous day to
// day, but recoverable under due process.
//
// Crypto: because escrow envelopes are STORED long-term (keyed by humanAnchor,
// for lawful deanon), they are the classic harvest-now-decrypt-later (HNDL)
// target — an adversary who copies ciphertext today could decrypt it with a
// future quantum computer. So new envelopes use a hybrid KEM (Scheme 2):
//
//	ss1 = X25519(eph, escrowPub)                    // classical ECDH
//	ss2, kemCT = ML-KEM-768.Encapsulate(escrowPub)  // FIPS 203 PQ KEM
//	key = HKDF-SHA256(ss1 ‖ ss2, salt = ephPub ‖ kemCT, info = ESC-3)
//	ciphertext = AES-256-GCM(key, identity, aad = humanAnchor|issuer|iat)
//
// The derived key is safe if EITHER primitive holds, so the envelope survives a
// break of X25519 (quantum) or a flaw in ML-KEM. Binding both transcript
// elements (ephPub, kemCT) in the HKDF salt is the standard concatenation-KEM
// combiner and prevents mix-and-match / re-encapsulation attacks.
//
// Scheme 1 (legacy X25519-only ECIES, info ESC-2) is still opened for
// back-compat and migration; Open dispatches on the Scheme byte. This is the
// crypto-agility property: v1 and v2 envelopes coexist, no hard cutover.
//
// Production hardening (unchanged plan): FROST threshold decryption of the
// classical half so no single party holds the escrow key; threshold ML-KEM is
// not yet standardized, so the PQ half stays under a smaller quorum / HSM for
// now (see docs/PQ-ESCROW-HYBRID-KEM-SCOPE.md §5). Uses the standard library
// (crypto/mlkem, Go 1.24+) plus golang.org/x/crypto for HKDF.
package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Scheme identifies the envelope's key-establishment method so v1 and v2
// envelopes coexist and Open dispatches on it.
const (
	// SchemeX25519 is the legacy single-party X25519 ECIES (info ESC-2).
	SchemeX25519 uint8 = 1
	// SchemeX25519MLKEM768 is the hybrid X25519 + ML-KEM-768 KEM (info ESC-3).
	// This is the default for all new seals.
	SchemeX25519MLKEM768 uint8 = 2
)

// ErrUnknownScheme indicates an envelope carries an unrecognized Scheme byte.
var ErrUnknownScheme = errors.New("escrow: unknown envelope scheme")

// Envelope is an encrypted escrow record. The AAD fields are stored in the
// clear (they are also the lookup key and binding context) but are
// authenticated: changing any of them makes Open fail.
type Envelope struct {
	Scheme        uint8  // 1 = X25519 ECIES (legacy), 2 = X25519+ML-KEM-768 hybrid
	EphemeralPub  []byte // X25519 ephemeral public key (32 bytes)
	KemCiphertext []byte // ML-KEM-768 ciphertext (1088 bytes); empty for Scheme 1
	Nonce         []byte // AES-GCM nonce (12 bytes)
	Ciphertext    []byte // AES-256-GCM sealed identity material
	HumanAnchor   string // vault key + AAD
	Issuer        string // AAD
	IssuedAt      int64  // AAD
}

func aad(humanAnchor, iss string, iat int64) []byte {
	return []byte(fmt.Sprintf("spt-txn-escrow-aad-v1|%s|%s|%d", humanAnchor, iss, iat))
}

// hkdfInfo binds the v1 derived key to the legacy scheme (ESC-2).
const hkdfInfo = "spt-txn-escrow-aead-v1"

// hkdfInfoHybrid binds the v2 derived key to the hybrid scheme (ESC-3).
const hkdfInfoHybrid = "spt-txn-escrow-aead-v2-hybrid"

// deriveKey turns a single X25519 shared secret into a 256-bit AES-GCM key
// using HKDF-SHA256 (ESC-2, Scheme 1 / legacy). The ephemeral X25519 key already
// randomizes the shared secret per envelope, so a fixed (nil) salt is
// acceptable; the info string provides domain separation. Retained so v1
// envelopes still open.
func deriveKey(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// deriveKeyHybrid is the concatenation-KEM combiner (ESC-3, Scheme 2). The
// secret is ss1‖ss2 (X25519 then ML-KEM shared secrets); the salt binds both
// transcript elements (ephemeral X25519 pub, ML-KEM ciphertext) so an attacker
// cannot substitute one KEM's output — the derived key is safe if either
// primitive holds.
func deriveKeyHybrid(ss1, ss2, ephPub, kemCT []byte) ([]byte, error) {
	secret := make([]byte, 0, len(ss1)+len(ss2))
	secret = append(secret, ss1...)
	secret = append(secret, ss2...)
	salt := make([]byte, 0, len(ephPub)+len(kemCT))
	salt = append(salt, ephPub...)
	salt = append(salt, kemCT...)
	r := hkdf.New(sha256.New, secret, salt, []byte(hkdfInfoHybrid))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

func sealAEAD(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openAEAD(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("escrow open failed (wrong key or tampered envelope): %w", err)
	}
	return plain, nil
}

// Seal encrypts identity material to the escrow public key using the hybrid
// X25519 + ML-KEM-768 KEM (Scheme 2), binding the envelope to
// (humanAnchor, issuer, iat) via AAD. This is the default for all new seals.
func Seal(identity []byte, pub *PublicKey, humanAnchor, issuer string, iat int64) (*Envelope, error) {
	if pub == nil || pub.x25519 == nil || pub.mlkem == nil {
		return nil, errors.New("escrow: incomplete hybrid escrow public key")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ss1, err := eph.ECDH(pub.x25519)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	ss2, kemCT := pub.mlkem.Encapsulate() // ss2 = 32B, kemCT = 1088B
	ephPub := eph.PublicKey().Bytes()

	key, err := deriveKeyHybrid(ss1, ss2, ephPub, kemCT)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := sealAEAD(key, identity, aad(humanAnchor, issuer, iat))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Scheme:        SchemeX25519MLKEM768,
		EphemeralPub:  ephPub,
		KemCiphertext: kemCT,
		Nonce:         nonce,
		Ciphertext:    ct,
		HumanAnchor:   humanAnchor,
		Issuer:        issuer,
		IssuedAt:      iat,
	}, nil
}

// sealClassical produces a legacy Scheme 1 (X25519-only) envelope. Retained for
// migration tooling and back-compat tests; new production seals use Seal.
func sealClassical(identity []byte, escrowPub *ecdh.PublicKey, humanAnchor, issuer string, iat int64) (*Envelope, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(escrowPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	key, err := deriveKey(shared)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := sealAEAD(key, identity, aad(humanAnchor, issuer, iat))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Scheme:       SchemeX25519,
		EphemeralPub: eph.PublicKey().Bytes(),
		Nonce:        nonce,
		Ciphertext:   ct,
		HumanAnchor:  humanAnchor,
		Issuer:       issuer,
		IssuedAt:     iat,
	}, nil
}

// Open decrypts the envelope with the escrow private key, dispatching on the
// Scheme byte. It fails if any AAD field was altered, the wrong key is used, or
// (for a hybrid envelope) the ML-KEM ciphertext was substituted.
func (e *Envelope) Open(k *Key) ([]byte, error) {
	if k == nil || k.x25519 == nil {
		return nil, errors.New("escrow: nil escrow key")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(e.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	ss1, err := k.x25519.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	var key []byte
	switch e.Scheme {
	case SchemeX25519:
		if key, err = deriveKey(ss1); err != nil {
			return nil, err
		}
	case SchemeX25519MLKEM768:
		if k.mlkem == nil {
			return nil, errors.New("escrow: hybrid envelope requires an ML-KEM decapsulation key")
		}
		ss2, derr := k.mlkem.Decapsulate(e.KemCiphertext)
		if derr != nil {
			return nil, fmt.Errorf("ml-kem decapsulate: %w", derr)
		}
		if key, err = deriveKeyHybrid(ss1, ss2, e.EphemeralPub, e.KemCiphertext); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownScheme, e.Scheme)
	}
	return openAEAD(key, e.Nonce, e.Ciphertext, aad(e.HumanAnchor, e.Issuer, e.IssuedAt))
}

// Key is a hybrid escrow private key: the X25519 half (classical ECDH) and the
// ML-KEM-768 half (FIPS 203 PQ KEM). Held by the escrow authority / threshold
// group; only the deanonymization handler ever uses it.
type Key struct {
	x25519 *ecdh.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
}

// PublicKey is the hybrid escrow public key registered under the "escrow" role.
// Issuers need both halves to build a Scheme 2 envelope.
type PublicKey struct {
	x25519 *ecdh.PublicKey
	mlkem  *mlkem.EncapsulationKey768
}

// NewEscrowKey generates a hybrid X25519 + ML-KEM-768 escrow keypair (POC
// helper; in production the public key is registered with role "escrow" and the
// private key is held by the escrow authority / threshold group).
func NewEscrowKey() (*Key, error) {
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	mk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ml-kem keygen: %w", err)
	}
	return &Key{x25519: xk, mlkem: mk}, nil
}

// PublicKey returns the hybrid public key (X25519 pub + ML-KEM encapsulation
// key) to register and to seal against.
func (k *Key) PublicKey() *PublicKey {
	return &PublicKey{x25519: k.x25519.PublicKey(), mlkem: k.mlkem.EncapsulationKey()}
}

// PrivateKeySize is the serialized length of a hybrid escrow private key:
// 32-byte X25519 scalar followed by the 64-byte ML-KEM-768 seed.
const PrivateKeySize = 32 + mlkem.SeedSize

// Bytes serializes the hybrid escrow PRIVATE key as x25519Scalar(32) ‖
// mlkemSeed(64). This is secret material — store it only in the escrow
// authority's hardened custody (HSM / restricted host), never in the repo.
func (k *Key) Bytes() []byte {
	out := make([]byte, 0, PrivateKeySize)
	out = append(out, k.x25519.Bytes()...) // 32-byte X25519 scalar
	out = append(out, k.mlkem.Bytes()...)   // 64-byte ML-KEM-768 seed
	return out
}

// ParseKey reconstructs a hybrid escrow private key from Bytes(). Used by the
// deanonymization service to load the escrow key at startup.
func ParseKey(b []byte) (*Key, error) {
	if len(b) != PrivateKeySize {
		return nil, fmt.Errorf("escrow: private key must be %d bytes, got %d", PrivateKeySize, len(b))
	}
	xk, err := ecdh.X25519().NewPrivateKey(b[:32])
	if err != nil {
		return nil, fmt.Errorf("x25519 private key: %w", err)
	}
	mk, err := mlkem.NewDecapsulationKey768(b[32:])
	if err != nil {
		return nil, fmt.Errorf("ml-kem decapsulation key: %w", err)
	}
	return &Key{x25519: xk, mlkem: mk}, nil
}

// X25519Bytes returns the 32-byte X25519 public key for registry storage.
func (p *PublicKey) X25519Bytes() []byte { return p.x25519.Bytes() }

// MlkemEncapKeyBytes returns the 1184-byte ML-KEM-768 encapsulation key for
// registry storage (add this beside the existing X25519 key in the escrow-role
// record).
func (p *PublicKey) MlkemEncapKeyBytes() []byte { return p.mlkem.Bytes() }

// NewPublicKey rebuilds a hybrid escrow public key from its registered byte
// forms (X25519 pub, ML-KEM-768 encapsulation key). Used by an issuer that
// reads the escrow-role record from the Trust Registry.
func NewPublicKey(x25519Pub, mlkemEncap []byte) (*PublicKey, error) {
	xp, err := ecdh.X25519().NewPublicKey(x25519Pub)
	if err != nil {
		return nil, fmt.Errorf("x25519 public key: %w", err)
	}
	ek, err := mlkem.NewEncapsulationKey768(mlkemEncap)
	if err != nil {
		return nil, fmt.Errorf("ml-kem encapsulation key: %w", err)
	}
	return &PublicKey{x25519: xp, mlkem: ek}, nil
}
