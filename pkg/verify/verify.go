// Package verify is the public, embeddable entry point to the SPT-Txn eight-step
// offline verifier. Import it to verify an SPT-Txn presentation INSIDE your own
// service — no network call to SPT-Txn, no issuer contact, no chain read in the
// hot path. Verification needs only the presented tokens and a locally-held Trust
// Registry snapshot. This is the literal form of the "embed, don't depend on our
// server" model.
//
//	import "github.com/violetskysecurity/spt-txn-poc/pkg/verify"
//
// The types here are public mirrors, so embedders never import SPT-Txn internal
// packages. The optional zero-knowledge N-hop chain mode is intentionally not
// exposed by this facade (it pulls in the proving backend); use the internal
// engine directly if you need it.
package verify

import (
	"context"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
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
type Verifier struct{ eng *verifier.Engine }

// FromSnapshot loads a Trust Registry snapshot (the locally-cached JSON
// distributed to verifiers) and returns a ready Verifier. Verification then runs
// fully offline.
func FromSnapshot(path string) (*Verifier, error) {
	reg, err := trustregistry.NewPersistentRegistry(path)
	if err != nil {
		return nil, err
	}
	return &Verifier{eng: verifier.New(reg)}, nil
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
