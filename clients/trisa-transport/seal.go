package trisatransport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrHMACMismatch = errors.New("trisatransport: envelope HMAC does not verify")
	ErrBadAlgorithm = errors.New("trisatransport: unsupported envelope algorithm")
	ErrShortPayload = errors.New("trisatransport: payload shorter than GCM nonce")
	ErrNotSealed    = errors.New("trisatransport: envelope is not sealed")
)

const (
	aesKeyLen     = 32 // AES-256
	hmacSecretLen = 32
)

// Seal produces a SecureEnvelope: it AES-256-GCM-encrypts payload under a fresh
// key, HMAC-SHA256s the ciphertext under a fresh secret, and seals both secrets
// to the recipient's RSA public key with RSA-OAEP/SHA-256. publicKeyID is an
// opaque tag identifying the recipient key (from KeyExchange/GDS); it may be "".
func Seal(payload []byte, recipientPub *rsa.PublicKey, publicKeyID string) (*SecureEnvelope, error) {
	if recipientPub == nil {
		return nil, errors.New("trisatransport: nil recipient public key")
	}

	aesKey := make([]byte, aesKeyLen)
	hmacSecret := make([]byte, hmacSecretLen)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("trisatransport: aes key: %w", err)
	}
	if _, err := rand.Read(hmacSecret); err != nil {
		return nil, fmt.Errorf("trisatransport: hmac secret: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("trisatransport: nonce: %w", err)
	}
	sealedPayload := gcm.Seal(nonce, nonce, payload, nil) // nonce || ciphertext

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(sealedPayload)
	tag := mac.Sum(nil)

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipientPub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("trisatransport: seal aes key: %w", err)
	}
	encSecret, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipientPub, hmacSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("trisatransport: seal hmac secret: %w", err)
	}

	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, fmt.Errorf("trisatransport: id: %w", err)
	}

	return &SecureEnvelope{
		ID:                  hex.EncodeToString(idRaw),
		Payload:             sealedPayload,
		EncryptionKey:       encKey,
		EncryptionAlgorithm: EncryptionAESGCM,
		HMAC:                tag,
		HMACSecret:          encSecret,
		HMACAlgorithm:       HMACSHA256,
		SealAlgorithm:       SealRSAOAEP,
		Sealed:              true,
		PublicKeyID:         publicKeyID,
	}, nil
}

// Open reverses Seal with the recipient's RSA private key. It unseals the keys,
// verifies the HMAC (constant-time) BEFORE decrypting, then AES-256-GCM-decrypts.
func Open(env *SecureEnvelope, recipientPriv *rsa.PrivateKey) ([]byte, error) {
	if env == nil || recipientPriv == nil {
		return nil, errors.New("trisatransport: nil envelope or key")
	}
	if !env.Sealed {
		return nil, ErrNotSealed
	}
	if env.EncryptionAlgorithm != EncryptionAESGCM || env.HMACAlgorithm != HMACSHA256 || env.SealAlgorithm != SealRSAOAEP {
		return nil, ErrBadAlgorithm
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipientPriv, env.EncryptionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("trisatransport: unseal aes key: %w", err)
	}
	hmacSecret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipientPriv, env.HMACSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("trisatransport: unseal hmac secret: %w", err)
	}

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(env.Payload)
	if !hmac.Equal(mac.Sum(nil), env.HMAC) {
		return nil, ErrHMACMismatch
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(env.Payload) < gcm.NonceSize() {
		return nil, ErrShortPayload
	}
	nonce := env.Payload[:gcm.NonceSize()]
	ct := env.Payload[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("trisatransport: gcm open: %w", err)
	}
	return pt, nil
}
