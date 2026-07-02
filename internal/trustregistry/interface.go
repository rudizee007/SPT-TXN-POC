// Package trustregistry defines the abstraction over issuer key resolution
// for the SPT-Txn POC. Per draft-coetzee-oauth-spt-txn-tokens Section 8.1,
// all CT signatures MUST be verified against the issuer's public key
// retrieved from the Trust Registry — not from URLs in the token, not from
// JWKS endpoints. This package is the only API surface that knows where
// keys come from.
//
// Three implementations are provided:
//
//   - MockRegistry: in-memory, in-process. Ephemeral (lives only for the
//     process lifetime). Suitable for unit tests and throwaway demos.
//   - PersistentRegistry: file-backed (atomic JSON, pure Go, no CGo).
//     Durable across restarts. This is what the trsvc service uses so that
//     registered issuers are not lost on restart.
//   - ChainRegistry (v2): EVM-backed, queries the on-chain Trust Registry
//     contract. Suitable for production-realistic demonstrations.
//
// All implement the Registry interface and are functionally
// interchangeable from a caller's perspective.
package trustregistry

import (
	"context"
	"errors"
	"time"
)

// Role identifies what a registered key is authorised to do. Per Section
// 8.1 and Section 9.6.3 ESC-3, a single key MUST NOT be accepted for
// multiple roles even if cryptographically capable of producing valid
// signatures for both.
type Role string

const (
	// RoleCTIssuer signs Compliance Attestation Tokens and Capability
	// Tokens.
	RoleCTIssuer Role = "ct_issuer"

	// RoleTTSIssuer signs SPT-Txn Tokens issued via Token Exchange.
	RoleTTSIssuer Role = "tts_issuer"

	// RoleEscrow is the public key used to encrypt Escrow Envelopes per
	// Section 9.6.2. MUST NOT be accepted for token signature verification.
	RoleEscrow Role = "escrow"

	// RoleEscrowReq is a key authorised to sign Deanonymization Requests
	// per Section 9.6.5. Distinct from any signing key used for tokens.
	RoleEscrowReq Role = "escrow_req"

	// RoleAudit signs audit log Merkle roots.
	RoleAudit Role = "audit"
)

// Key types accepted in a Record.KeyType. Classical roles use a single
// 32-byte key; the escrow role MAY instead use the hybrid type, which pairs
// the 32-byte X25519 key (in PublicKey) with the ML-KEM-768 encapsulation key
// (in MlkemEncapKey) so escrow envelopes can be sealed with the post-quantum
// hybrid KEM (see internal/escrow, Scheme 2).
const (
	KeyTypeEd25519        = "Ed25519"
	KeyTypeX25519         = "X25519"
	KeyTypeX25519MLKEM768 = "X25519+ML-KEM-768"
)

// MlkemEncapKeySize is the byte length of an ML-KEM-768 encapsulation key
// (FIPS 203).
const MlkemEncapKeySize = 1184

// IsValid reports whether r is a recognised role.
func (r Role) IsValid() bool {
	switch r {
	case RoleCTIssuer, RoleTTSIssuer, RoleEscrow, RoleEscrowReq, RoleAudit:
		return true
	}
	return false
}

// RecordStatus tracks the lifecycle state of a registry entry.
type RecordStatus string

const (
	// StatusActive indicates the key is currently valid for use.
	StatusActive RecordStatus = "active"

	// StatusRevoked indicates the key has been revoked. Tokens issued
	// before revocation may still verify per Section 9.6.8 ("compromise
	// affects only the escrow recoverability, not the integrity of the
	// authorization chain") — but new issuance under a revoked key MUST
	// be refused.
	StatusRevoked RecordStatus = "revoked"

	// StatusSuperseded indicates the key was rotated. Same as Revoked
	// for verification purposes but indicates orderly rotation rather
	// than compromise.
	StatusSuperseded RecordStatus = "superseded"
)

// Record is a single registry entry binding an issuer identity and role
// to a public key with a validity period.
type Record struct {
	// Iss is the issuer identifier (e.g., "domain-a", "did:web:authorg",
	// or a similar canonical form).
	Iss string

	// Role is the capability bound to this key.
	Role Role

	// PublicKey is the raw key material. For Ed25519, 32 bytes. For
	// X25519 (escrow), 32 bytes. For the hybrid escrow type this holds the
	// X25519 half; the ML-KEM half is in MlkemEncapKey.
	PublicKey []byte

	// MlkemEncapKey is the ML-KEM-768 encapsulation key (1184 bytes) for a
	// hybrid escrow record (KeyType == KeyTypeX25519MLKEM768). It is empty for
	// every other record. An issuer rebuilds the hybrid escrow public key from
	// PublicKey (X25519) + this field via escrow.NewPublicKey, then seals a
	// Scheme 2 envelope. Persisted as base64 JSON; omitted when empty so
	// classical records are unchanged on disk.
	MlkemEncapKey []byte `json:"MlkemEncapKey,omitempty"`

	// KeyType identifies the algorithm: KeyTypeEd25519, KeyTypeX25519, or
	// KeyTypeX25519MLKEM768 (hybrid escrow).
	KeyType string

	// ValidFrom is the inclusive start of the validity period.
	ValidFrom time.Time

	// ValidUntil is the exclusive end of the validity period.
	ValidUntil time.Time

	// Status is the lifecycle state. See RecordStatus.
	Status RecordStatus

	// Metadata is implementation-defined annotation. For example, a chain
	// implementation might include block number and transaction hash for
	// the registration event.
	Metadata map[string]string
}

// IsCurrentlyValid reports whether the record is active and the given
// timestamp falls within the validity period.
func (r *Record) IsCurrentlyValid(at time.Time) bool {
	if r.Status != StatusActive {
		return false
	}
	if at.Before(r.ValidFrom) || !at.Before(r.ValidUntil) {
		return false
	}
	return true
}

// Registry is the abstraction over issuer key lookup. Implementations
// MUST satisfy the requirement of Section 8.1: lookups return only keys
// whose registration was validated against the registry's trust anchor
// (multi-sig for chain; signify signature for mock).
type Registry interface {
	// Lookup returns the active record for (iss, role), or
	// ErrNotFound if no active record exists.
	//
	// "Active" means Status == StatusActive AND now is within
	// [ValidFrom, ValidUntil). If multiple records satisfy this,
	// implementations MUST return the most recently registered one and
	// SHOULD log a warning (multiple active records is an operational
	// anomaly indicating either rotation in progress or a registry
	// integrity issue).
	Lookup(ctx context.Context, iss string, role Role) (*Record, error)

	// List returns all records matching the role filter, including
	// revoked and superseded ones. Used for transparency reporting and
	// for verifying historical tokens whose issuance key has since been
	// rotated.
	//
	// Pass an empty role to return all roles.
	List(ctx context.Context, role Role) ([]*Record, error)

	// Close releases any resources held by the registry implementation.
	Close() error
}

// Mutable extends Registry with write operations. The mock implementation
// satisfies Mutable; the chain implementation will not (writes go through
// the chain transaction layer, not this interface).
type Mutable interface {
	Registry

	// Register adds a new active record. Returns ErrConflict if an active
	// record already exists for (iss, role) — the caller must explicitly
	// Revoke or Supersede the existing record first.
	Register(ctx context.Context, rec *Record) error

	// Replace atomically supersedes any existing active record for
	// (rec.Iss, rec.Role) and installs rec as the new active record. The
	// revoke-of-old and append-of-new happen under a SINGLE lock and a
	// SINGLE persisted save, so a crash or failed save can never leave the
	// issuer with no active key (security review SVC-1). On a save failure
	// BOTH in-memory edits are rolled back, leaving the prior active record
	// intact. Unlike Register, Replace never returns ErrConflict — it is the
	// caller's explicit intent to rotate.
	Replace(ctx context.Context, rec *Record) error

	// Revoke marks an active record as revoked. Returns ErrNotFound if no
	// active record exists for (iss, role).
	Revoke(ctx context.Context, iss string, role Role, at time.Time) error

	// Supersede marks an active record as superseded (orderly rotation).
	// Equivalent to Revoke for verification purposes but signals intent.
	Supersede(ctx context.Context, iss string, role Role, at time.Time) error
}

// Errors returned by Registry implementations.
var (
	// ErrNotFound indicates no record matched the query.
	ErrNotFound = errors.New("trustregistry: record not found")

	// ErrConflict indicates an active record already exists for (iss, role).
	ErrConflict = errors.New("trustregistry: active record already exists")

	// ErrInvalidRecord indicates the record failed validation
	// (e.g., wrong key length, invalid role, ValidUntil before ValidFrom).
	ErrInvalidRecord = errors.New("trustregistry: invalid record")
)
