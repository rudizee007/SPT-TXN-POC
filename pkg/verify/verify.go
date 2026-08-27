// Package verify is the public, embeddable entry point to the SPT-Txn eight-step
// offline verifier. Import it to verify an SPT-Txn presentation INSIDE your own
// service — no network call to SPT-Txn, no issuer contact, no chain read in the
// hot path. Verification needs only the presented tokens and a locally-held Trust
// Registry snapshot. This is the literal form of the "embed, don't depend on our
// server" model.
//
//	import "github.com/rudizee007/spt-txn-poc/pkg/verify"
//
// The types here are public mirrors, so embedders never import SPT-Txn internal
// packages. The optional zero-knowledge N-hop chain mode is intentionally not
// exposed by this facade (it pulls in the proving backend); use the internal
// engine directly if you need it.
package verify

import (
	"context"
	"crypto/ed25519"

	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

// TxnContext is the concrete transaction the authorization is bound to.
type TxnContext struct {
	Chain       string
	Originator  string
	Beneficiary string
	Amount      string
	Currency    string
	Timestamp   int64
	Extra       map[string]string
}

// Input is a presentation to verify: the SPT-Txn token, its DPoP proof, the
// CAT→CT chain it was minted under, the transaction, and this domain's audience.
type Input struct {
	TxnToken  string
	DPoPProof string
	HTM, HTU  string   // HTTP method + URI the DPoP proof binds
	CT        string   // single parent CT (one-hop; optional if CTChain is set)
	CTChain   []string // ordered CT delegation chain, root→leaf
	CAT       string   // root CAT
	Txn       TxnContext
	Audience  string // this domain's identifier (expected aud)
}

// Decision is the verification result: ALLOW/DENY plus the failing step.
type Decision struct {
	Allow    bool
	Step     int
	StepName string
	Reason   string
}

// Verifier runs the offline eight-step enforcement engine against a locally held
// Trust Registry snapshot. Safe for concurrent use.
type Verifier struct {
	eng *verifier.Engine
	reg trustregistry.Registry
}

// SnapshotOptions configures how a snapshot is verified before it becomes a root
// of trust. It is a straight alias of the trustsnapshot options so an embedder
// configures one thing, not two.
type SnapshotOptions = trustsnapshot.Options

// FromSignedSnapshot loads a Trust Registry snapshot and returns a ready
// Verifier — but only after checking that the snapshot is the one the publisher
// signed.
//
// It takes TWO files. The manifest is the signed head; the body is the record
// set. Both are required, because the body alone carries no authenticity: a
// verifier handed only a body has no root of trust and must fail closed
// (docs/spec/TRUST-REGISTRY-SNAPSHOT.md §2).
//
// opts.PinnedKeys is the publication-key set. It is a SET so a key rotation has
// an overlap window, and an empty set is refused — accepting whatever key turns
// up is trust-on-first-use, which the spec forbids (§6). opts.MaxAge bounds
// staleness (§7); a snapshot older than it is refused unless the operator has
// explicitly set AllowStale for a disconnected segment.
//
// There is deliberately no unverified alternative. An earlier FromSnapshot took
// a body alone and read it with os.ReadFile + json.Unmarshal, which made the
// root of trust for every offline verification a matter of file permissions.
// Replacing it rather than deprecating it is the point: a constructor that
// builds a Verifier from unchecked bytes should not be an expressible operation,
// because a deprecated one is a check a refactor can quietly re-adopt.
func FromSignedSnapshot(manifestPath, bodyPath string, opts SnapshotOptions) (*Verifier, error) {
	reg, err := trustregistry.OpenVerified(manifestPath, bodyPath, opts)
	if err != nil {
		return nil, err
	}
	return &Verifier{eng: verifier.New(reg), reg: reg}, nil
}

// IssuerKeys returns the Ed25519 public keys of every token-issuance authority
// in the snapshot — all CT-issuer and TTS-issuer records, active or not.
// Rotated, revoked and superseded keys are included on purpose: a receipt/log
// signing key MUST NOT reuse an issuance key, not even a retired one.
//
// This exists so a PEP that emits signed Transaction Receipts can cross-check
// its dedicated log key against the issuance keys — the draft requires the log
// signing key to be SEPARATE from the token issuance key. Escrow (encryption)
// keys and audit keys are deliberately excluded: escrow keys are X25519, not
// signing keys, and the audit role is exactly what a log/receipt key legitimately
// is. The returned slice is freshly allocated; callers may retain it.
func (v *Verifier) IssuerKeys(ctx context.Context) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, role := range []trustregistry.Role{trustregistry.RoleCTIssuer, trustregistry.RoleTTSIssuer} {
		recs, err := v.reg.List(ctx, role)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			// Any 32-byte key in an issuer role, regardless of the KeyType label: a
			// reused Ed25519 key carrying a wrong or blank KeyType would still be 32
			// bytes, and the key-separation guard must still catch it. (Records are
			// validated at load now, so a malformed record no longer reaches here —
			// but this guard does not depend on that, and should not start to.)
			// Issuer roles are Ed25519 today; a future PQC
			// issuance key would not be 32 bytes and would need a matching change
			// here and in the receipt key type.
			if len(rec.PublicKey) == ed25519.PublicKeySize {
				out = append(out, ed25519.PublicKey(append([]byte(nil), rec.PublicKey...)))
			}
		}
	}
	return out, nil
}

// Verify runs the eight steps and returns the decision.
func (v *Verifier) Verify(ctx context.Context, in Input) Decision {
	d := v.eng.Verify(ctx, verifier.Input{
		TxnToken:  in.TxnToken,
		DPoPProof: in.DPoPProof,
		HTM:       in.HTM,
		HTU:       in.HTU,
		CT:        in.CT,
		CTChain:   in.CTChain,
		CAT:       in.CAT,
		Audience:  in.Audience,
		Txn: ledger.TxnContext{
			Chain:       in.Txn.Chain,
			Originator:  in.Txn.Originator,
			Beneficiary: in.Txn.Beneficiary,
			Amount:      in.Txn.Amount,
			Currency:    in.Txn.Currency,
			Timestamp:   in.Txn.Timestamp,
			Extra:       in.Txn.Extra,
		},
	})
	return Decision{Allow: d.Allow, Step: d.Step, StepName: d.StepName, Reason: d.Reason}
}

// Facts are the authorization facts a settler derives from the signed tokens
// rather than from any summary: who is accountable, and the ceiling that was
// granted.
type Facts struct {
	HumanAnchor string // CAT human_anchor, hex
	MaxAmount   string // leaf CT max_amount ceiling, decimal
	Currency    string // leaf CT currency, if pinned
}

// VerifyForSettlement verifies a presented CAT→CT→SPT-Txn chain for a concrete
// transaction WITHOUT proof-of-possession and returns the signed facts.
//
// It is the settler's entry point: the payer-side gate proves possession when
// it decides; the settler checks that the delegation is authentic (issuer
// signatures, revocation, chain, scope) and binds THIS payment (the context
// hash the settler derived independently), then reads the ceiling and anchor
// from the verified tokens. Settlement still needs the payer's on-chain
// signature, so omitting proof-of-possession here grants a settler nothing —
// see verifier.VerifyForSettlement for the full argument.
//
// A non-ALLOW Decision means the chain is not a valid authorization for this
// transaction; the Facts are then zero and must not be used.
func (v *Verifier) VerifyForSettlement(ctx context.Context, in Input) (Facts, Decision) {
	f, d := v.eng.VerifyForSettlement(ctx, verifier.Input{
		TxnToken: in.TxnToken,
		CT:       in.CT,
		CTChain:  in.CTChain,
		CAT:      in.CAT,
		Audience: in.Audience,
		Txn: ledger.TxnContext{
			Chain:       in.Txn.Chain,
			Originator:  in.Txn.Originator,
			Beneficiary: in.Txn.Beneficiary,
			Amount:      in.Txn.Amount,
			Currency:    in.Txn.Currency,
			Timestamp:   in.Txn.Timestamp,
			Extra:       in.Txn.Extra,
		},
	})
	return Facts{HumanAnchor: f.HumanAnchor, MaxAmount: f.MaxAmount, Currency: f.Currency},
		Decision{Allow: d.Allow, Step: d.Step, StepName: d.StepName, Reason: d.Reason}
}
