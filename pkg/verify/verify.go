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

// FromSnapshot loads a Trust Registry snapshot (the locally-cached JSON
// distributed to verifiers) and returns a ready Verifier. Verification then runs
// fully offline.
func FromSnapshot(path string) (*Verifier, error) {
	reg, err := trustregistry.NewPersistentRegistry(path)
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
			// bytes, and the key-separation guard must still catch it (the snapshot
			// is loaded without per-record validation, so a malformed-but-trusted
			// record is possible). Issuer roles are Ed25519 today; a future PQC
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
