package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

const (
	issCT  = "domain-a.authorg"
	issTTS = "domain-a.tts"
	aud    = "domain-b.execorg"
	htm    = "POST"
	htu    = "https://foss.violetskysecurity.com/agent/verify"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func register(t *testing.T, reg *trustregistry.PersistentRegistry, iss string, role trustregistry.Role, pub ed25519.PublicKey) {
	t.Helper()
	if err := reg.Register(context.Background(), &trustregistry.Record{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour),
		ValidUntil: time.Now().Add(time.Hour),
		Status:     trustregistry.StatusActive,
	}); err != nil {
		t.Fatalf("register %s/%s: %v", iss, role, err)
	}
}

// buildValid wires a file-backed registry snapshot and a CAT→CT→SPT-Txn chain,
// returning the engine and a ready verifyRequest that should ALLOW.
func buildValid(t *testing.T) (*verifier.Engine, verifyRequest) {
	t.Helper()
	reg, err := trustregistry.NewPersistentRegistry(filepath.Join(t.TempDir(), "registry.snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	ctPub, ctPriv := genKey(t)
	ttsPub, ttsPriv := genKey(t)
	agentPub, agentPriv := genKey(t)
	register(t, reg, issCT, trustregistry.RoleCTIssuer, ctPub)
	register(t, reg, issTTS, trustregistry.RoleTTSIssuer, ttsPub)

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issCT, Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CAT: %v", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issCT, ParentCAT: cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		t.Fatalf("CT: %v", err)
	}

	l, err := ledger.Get("xrpl")
	if err != nil {
		t.Fatal(err)
	}
	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "5000", Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: ct.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: agentPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		t.Fatalf("SPT-Txn: %v", err)
	}
	proof, err := dpop.Proof(agentPriv, htm, htu, dpop.ATH(txn.Token))
	if err != nil {
		t.Fatal(err)
	}

	req := verifyRequest{
		TxnToken: txn.Token, DPoPProof: proof, HTM: htm, HTU: htu,
		CTChain: []string{ct.Token}, CAT: cat.Token,
		Txn: txnBody{
			Chain: tc.Chain, Originator: tc.Originator, Beneficiary: tc.Beneficiary,
			Amount: tc.Amount, Currency: tc.Currency, Timestamp: tc.Timestamp, Extra: tc.Extra,
		},
	}
	return verifier.New(reg), req
}

func post(t *testing.T, eng *verifier.Engine, req verifyRequest) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/agent/verify", bytes.NewReader(body))
	handleVerify(eng, aud)(rec, r)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response (%d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, out
}

func TestHandleVerify_AllowsValidChain(t *testing.T) {
	eng, req := buildValid(t)
	code, out := post(t, eng, req)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if allow, _ := out["allow"].(bool); !allow {
		t.Fatalf("valid chain must be allowed; got %v", out)
	}
}

// The audience is the service's configured identity. A token minted for another
// domain is denied at step 3 against THAT configuration, and a body that
// carries an audience of its own is refused outright rather than honoured.
func TestHandleVerify_AudienceIsConfiguration(t *testing.T) {
	eng, req := buildValid(t)
	body, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/agent/verify", bytes.NewReader(body))
	handleVerify(eng, "domain-x.other")(rec, r)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if allow, _ := out["allow"].(bool); allow {
		t.Fatal("a token for another domain must be denied under this service's audience")
	}
	if step, _ := out["step"].(float64); int(step) != 3 {
		t.Fatalf("expected deny at step 3 (audience), got step %v (%v)", out["step"], out["step_name"])
	}

	req.Audience = aud // even the RIGHT value: the field is not accepted
	if code, _ := post(t, eng, req); code != http.StatusBadRequest {
		t.Fatalf("a body carrying an audience must be refused with 400, got %d", code)
	}
}

func TestHandleVerify_RequiresRequestDescription(t *testing.T) {
	eng, req := buildValid(t)
	req.HTM = ""
	if code, _ := post(t, eng, req); code != http.StatusBadRequest {
		t.Fatalf("missing htm must be refused with 400, got %d", code)
	}
}

func TestHandleVerify_RejectsBadBody(t *testing.T) {
	eng, _ := buildValid(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/agent/verify", bytes.NewReader([]byte("{not json")))
	handleVerify(eng, aud)(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body status = %d, want 400", rec.Code)
	}
}

func TestHandleVerify_MethodNotAllowed(t *testing.T) {
	eng, _ := buildValid(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/agent/verify", nil)
	handleVerify(eng, aud)(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}
