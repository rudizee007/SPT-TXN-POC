// Package trisatransport implements the TRISA Secure Envelope sealing scheme for
// carrying SPT-Txn Travel Rule payloads, plus the transport interface the gRPC /
// GDS / mTLS network layer plugs into.
//
// Why sealing matters: plain TRP delivers IVMS101 identity in the (TLS-encrypted)
// clear, so the counterparty holds the full PII. TRISA seals the payload — it is
// encrypted at rest and crypto-erasable by destroying the keys. SPT-Txn already
// minimises *what* is shared (selective disclosure + ZK), so running an SPT-Txn
// payload inside a sealed envelope is defence in depth: ZK for what the
// counterparty may compute, sealing for confidentiality and crypto-erasure.
//
// The sealing scheme here mirrors TRISA's SecureEnvelope:
//   - payload encrypted with AES-256-GCM (nonce prepended to the ciphertext),
//   - an HMAC-SHA256 over the ciphertext,
//   - the AES key and HMAC secret each sealed with the recipient's RSA public key
//     (RSA-OAEP/SHA-256) obtained via KeyExchange or the GDS directory.
//
// All of it is Go standard library, so it is testable with zero network and zero
// external dependencies.
package trisatransport

const (
	// EncryptionAESGCM is the payload cipher.
	EncryptionAESGCM = "AES256-GCM"
	// HMACSHA256 is the envelope MAC algorithm.
	HMACSHA256 = "HMAC-SHA256"
	// SealRSAOAEP is the key-sealing algorithm.
	SealRSAOAEP = "RSA-OAEP-SHA256"
)

// SecureEnvelope is the sealed wire object, shaped after TRISA's SecureEnvelope.
// Field names use JSON tags so it can also be marshalled for a non-gRPC carrier.
type SecureEnvelope struct {
	ID                  string `json:"id"`
	Payload             []byte `json:"payload"`              // nonce || AES-256-GCM ciphertext
	EncryptionKey       []byte `json:"encryption_key"`       // AES key, RSA-OAEP sealed to recipient
	EncryptionAlgorithm string `json:"encryption_algorithm"` // EncryptionAESGCM
	HMAC                []byte `json:"hmac"`                 // HMAC-SHA256(Payload, hmacSecret)
	HMACSecret          []byte `json:"hmac_secret"`          // HMAC secret, RSA-OAEP sealed to recipient
	HMACAlgorithm       string `json:"hmac_algorithm"`       // HMACSHA256
	SealAlgorithm       string `json:"seal_algorithm"`       // SealRSAOAEP
	Sealed              bool   `json:"sealed"`
	PublicKeyID         string `json:"public_key_id,omitempty"` // which recipient key was used
}
