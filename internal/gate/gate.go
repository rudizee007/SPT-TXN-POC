// Package gate encapsulates the SPT-Txn x402 payer-side authorization decision:
// given an agent's standing capability (a ceiling) and a specific payment
// requirement, it mints the CAT -> CT -> SPT-Txn chain for that exact payment and
// runs the eight-step offline verifier, returning ALLOW/DENY plus the on-ledger
// stamp fields (Destination, Amount, SourceTag, Memo = humanAnchor, context hash)
// and the attestation token.
//
// This is the reusable core behind cmd/gatesvc (the gate service in the x402
// loop) and mirrors the logic proven in cmd/x402gate. It is OFFLINE: it never
// contacts a network or a ledger — settlement is a separate concern
// (clients/xrpl-pay), which only runs after the gate says ALLOW.
package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/escrow"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

const (
	issOrg = "domain-a.authorg"
	issTTS = "domain-a.tts"
	aud    = "domain-b.execorg"
	htm    = "POST"
	htu    = "https://foss.violetskysecurity.com/b/verify"
)

// Request is a single x402 payment requirement the agent wants to satisfy.
type Request struct {
	Price     string // amount in the ledger's base unit (XRP drops)
	Currency  string // "XRP"
	PayTo     string // merchant classic r-address
	SourceTag string // x402 SourceTag
}

// Decision is the gate's ruling. On Allow, the stamp fields are what the payer
// must put on the XRPL Payment; Attestation is the SPT-Txn token the merchant
// can verify offline (P2). On deny, Step/StepName/Reason explain why.
type Decision struct {
	Allow       bool   `json:"allow"`
	Reason      string `json:"reason,omitempty"`
	Step        int    `json:"step,omitempty"`
	StepName    string `json:"step_name,omitempty"`
	Destination string `json:"destination,omitempty"`
	Amount      string `json:"amount,omitempty"`
	Currency    string `json:"currency,omitempty"`
	SourceTag   string `json:"source_tag,omitempty"`
	Memo        string `json:"memo,omitempty"` // humanAnchor (zero-knowledge commitment)
	ContextHash string `json:"context_hash,omitempty"`
	Attestation string `json:"attestation,omitempty"` // SPT-Txn token

	// Verification bundle (P2): everything a merchant needs to independently
	// re-run the eight-step verifier on the attestation. The bundle is safe to
	// pass through the untrusted agent: the signed token pins the context hash
	// (step 8) and issuer signature (step 1), so a tampered bundle fails to
	// verify. Issuer public keys come separately from a trusted channel.
	CAT      string             `json:"cat,omitempty"`
	CTChain  []string           `json:"ct_chain,omitempty"`
	DPoP     string             `json:"dpop,omitempty"`
	HTM      string             `json:"htm,omitempty"`
	HTU      string             `json:"htu,omitempty"`
	Audience string             `json:"audience,omitempty"`
	Txn      *ledger.TxnContext `json:"txn,omitempty"`
}

// Gate holds an agent's standing authority (a CAT -> CT chain bounded by a
// ceiling) and the issuer keys/registry needed to mint and verify per-payment
// SPT-Txn tokens. Construct once (New); call Authorize per payment.
type Gate struct {
	reg        *trustregistry.MockRegistry
	l          ledger.Ledger
	chain      string
	agentAddr  string
	orgPub     ed25519.PublicKey
	ttsPub     ed25519.PublicKey
	ttsPriv    ed25519.PrivateKey
	holderPub  ed25519.PublicKey
	holderPriv ed25519.PrivateKey
	catToken   string
	ctToken    string
	anchor     string
}

// New provisions an agent: registers issuer keys and mints the standing
// CAT -> CT capability bounded by ceiling (max spend) in the given currency.
// The ceiling is a canonical decimal STRING, not a float64. A float64 ceiling
// above 2^53 seals as the nearest double — 999999999999999999 wei becomes
// 1000000000000000000, i.e. WIDENED by rounding — and the signature then commits
// to a number nobody chose. It is carried as json.Number so tbac compares it
// with big.Rat precision, and validated through ledger.ParseAmount so it obeys
// the same grammar as the amounts it will be compared against.
func New(chain, agentAddr string, ceiling string, currency string) (*Gate, error) {
	if _, err := ledger.ParseAmount(ceiling); err != nil {
		return nil, fmt.Errorf("ceiling: %w", err)
	}
	l, err := ledger.Get(chain)
	if err != nil {
		return nil, fmt.Errorf("%s adapter: %w", chain, err)
	}
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		return nil, err
	}
	orgPub, orgPriv := genKey()
	ttsPub, ttsPriv := genKey()
	holderPub, holderPriv := genKey()
	if err := reg.Register(context.Background(), rec(issOrg, trustregistry.RoleCTIssuer, orgPub)); err != nil {
		return nil, err
	}
	if err := reg.Register(context.Background(), rec(issTTS, trustregistry.RoleTTSIssuer, ttsPub)); err != nil {
		return nil, err
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issOrg, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": json.Number(ceiling), "currency": currency},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		return nil, fmt.Errorf("CAT: %w", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issOrg, ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": json.Number(ceiling), "currency": currency},
		HolderPublicKey: holderPub,
	}, orgPriv)
	if err != nil {
		return nil, fmt.Errorf("CT: %w", err)
	}

	return &Gate{
		reg: reg, l: l, chain: chain, agentAddr: agentAddr,
		orgPub: orgPub, ttsPub: ttsPub, ttsPriv: ttsPriv,
		holderPub: holderPub, holderPriv: holderPriv,
		catToken: cat.Token, ctToken: ct.Token, anchor: cat.HumanAnchor.String(),
	}, nil
}

// IssuerRecords returns the issuer public-key records (CT-issuer + TTS-issuer)
// so a verifier such as the merchant can build a trust registry and check the
// attestations this gate produced. In production these come from the shared
// Trust Registry (trsvc); exposing them from the gate is the demo stand-in for
// that trusted channel — issuer keys must reach the verifier out-of-band, never
// via the untrusted agent.
func (g *Gate) IssuerRecords() []*trustregistry.Record {
	return []*trustregistry.Record{
		rec(issOrg, trustregistry.RoleCTIssuer, g.orgPub),
		rec(issTTS, trustregistry.RoleTTSIssuer, g.ttsPub),
	}
}

// Anchor returns the agent's humanAnchor (the zero-knowledge commitment carried
// on-ledger in the Memo).
func (g *Gate) Anchor() string { return g.anchor }

// SealIdentity seals the real human identity behind this agent's humanAnchor
// into a PQ-hybrid escrow envelope, encrypted to the escrow authority's public
// key — what an issuer does at CAT issuance. The envelope is keyed by the
// humanAnchor; the identity is recoverable only by the escrow authority under a
// signed, lawful-basis deanonymization request (see cmd/deanonsvc). In
// production the envelope is POSTed to the escrow vault (deanonsvc /escrow/store).
func (g *Gate) SealIdentity(escrowPub *escrow.PublicKey, identity string) (*escrow.Envelope, error) {
	return escrow.Seal([]byte(identity), escrowPub, g.anchor, issOrg, time.Now().Unix())
}

// AgentAddress returns the payer agent's XRPL address.
func (g *Gate) AgentAddress() string { return g.agentAddr }

// Authorize mints an SPT-Txn for the specific payment and runs the eight-step
// verifier. An over-ceiling payment fails at mint (DENY); a mint that verifies
// yields ALLOW plus the stamp fields the payer must apply.
func (g *Gate) Authorize(req Request) (Decision, error) {
	tc := ledger.TxnContext{
		Chain: g.chain, Originator: g.agentAddr, Beneficiary: req.PayTo,
		Amount: req.Price, Currency: req.Currency, Timestamp: time.Now().Unix(),
		Extra: map[string]string{"DestinationTag": req.SourceTag, "Memo": g.anchor},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: g.ctToken, ParentIssuerKey: g.orgPub,
		HolderPublicKey: g.holderPub, Ledger: g.l, Txn: tc,
	}, g.ttsPriv)
	if err != nil {
		// Scope is enforced at mint: an over-ceiling / wrong-currency payment is
		// refused here. That is the gate saying NO before anything is signed.
		return Decision{Allow: false, Reason: "payment outside agent capability scope: " + err.Error()}, nil
	}

	proof, err := dpop.Proof(g.holderPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		return Decision{}, fmt.Errorf("dpop: %w", err)
	}
	d := verifier.New(g.reg).Verify(context.Background(), verifier.Input{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{g.ctToken}, CAT: g.catToken, Txn: tc, Audience: aud,
	})
	if !d.Allow {
		return Decision{Allow: false, Step: d.Step, StepName: d.StepName, Reason: d.Reason}, nil
	}

	_, ctxHash, err := ledger.ContextHash(g.l, tc)
	if err != nil {
		return Decision{}, fmt.Errorf("context hash: %w", err)
	}
	tcCopy := tc
	return Decision{
		Allow: true, Destination: req.PayTo, Amount: req.Price, Currency: req.Currency,
		SourceTag: req.SourceTag, Memo: g.anchor, ContextHash: ctxHash, Attestation: txn.Token,
		CAT: g.catToken, CTChain: []string{g.ctToken}, DPoP: proof, HTM: htm, HTU: htu,
		Audience: aud, Txn: &tcCopy,
	}, nil
}

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("gate: ed25519 keygen: " + err.Error())
	}
	return pub, priv
}

func rec(iss string, role trustregistry.Role, pub ed25519.PublicKey) *trustregistry.Record {
	return &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	}
}
