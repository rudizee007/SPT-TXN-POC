package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/escrow"
)

// testSetup wires an in-memory vault + handler with one authorized escrow_req
// signer, and returns the signer's key material.
func testSetup(t *testing.T) (*escrow.Vault, *escrow.Handler, *escrow.Key, ed25519.PrivateKey, string) {
	t.Helper()
	esk, err := escrow.NewEscrowKey()
	if err != nil {
		t.Fatalf("NewEscrowKey: %v", err)
	}
	vault := escrow.NewVault()
	h := escrow.NewHandler(vault, esk)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	const requester = "authority-x.gov"
	h.AddSigner(requester, pub)
	return vault, h, esk, priv, requester
}

func storeEnvelope(t *testing.T, vault *escrow.Vault, env *escrow.Envelope) {
	t.Helper()
	body, _ := json.Marshal(env)
	req := httptest.NewRequest(http.MethodPost, "/escrow/store", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleStore(vault)(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("store: status = %d, want 201 (%s)", rr.Code, rr.Body.String())
	}
}

func TestDeanonymize_HappyPath(t *testing.T) {
	vault, h, esk, priv, requester := testSetup(t)

	identity := []byte("Jane Q. Public, passport X12345")
	env, err := escrow.Seal(identity, esk.PublicKey(), "anchor-1", "domain-a.authorg", time.Now().Unix())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	storeEnvelope(t, vault, env)

	// Build and sign a well-formed request.
	r := &escrow.Request{
		HumanAnchor: "anchor-1",
		Requester:   requester,
		LawfulBasis: "warrant 2026-0042",
		IssuedAt:    time.Now().Unix(),
	}
	r.Sign(priv)
	body, _ := json.Marshal(deanonRequest{
		HumanAnchor: r.HumanAnchor,
		Requester:   r.Requester,
		LawfulBasis: r.LawfulBasis,
		IssuedAt:    r.IssuedAt,
		Sig:         hex.EncodeToString(r.Sig),
	})

	req := httptest.NewRequest(http.MethodPost, "/escrow/deanonymize", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleDeanonymize(h)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("deanonymize: status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	var got struct {
		IdentityHex string `json:"identity_hex"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	recovered, _ := hex.DecodeString(got.IdentityHex)
	if !bytes.Equal(recovered, identity) {
		t.Fatalf("recovered %q, want %q", recovered, identity)
	}
}

func TestDeanonymize_UnauthorizedRequester(t *testing.T) {
	vault, h, esk, _, _ := testSetup(t)
	env, _ := escrow.Seal([]byte("id"), esk.PublicKey(), "anchor-1", "iss", time.Now().Unix())
	storeEnvelope(t, vault, env)

	// A requester not in the signer set, signed with a stranger key.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	r := &escrow.Request{HumanAnchor: "anchor-1", Requester: "nobody", LawfulBasis: "x", IssuedAt: time.Now().Unix()}
	r.Sign(stranger)
	body, _ := json.Marshal(deanonRequest{
		HumanAnchor: r.HumanAnchor, Requester: r.Requester, LawfulBasis: r.LawfulBasis,
		IssuedAt: r.IssuedAt, Sig: hex.EncodeToString(r.Sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/escrow/deanonymize", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleDeanonymize(h)(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unauthorized requester: status = %d, want 403 (%s)", rr.Code, rr.Body.String())
	}
}

func TestDeanonymize_NoLawfulBasisRejected(t *testing.T) {
	vault, h, esk, priv, requester := testSetup(t)
	env, _ := escrow.Seal([]byte("id"), esk.PublicKey(), "anchor-1", "iss", time.Now().Unix())
	storeEnvelope(t, vault, env)

	r := &escrow.Request{HumanAnchor: "anchor-1", Requester: requester, LawfulBasis: "", IssuedAt: time.Now().Unix()}
	r.Sign(priv)
	body, _ := json.Marshal(deanonRequest{
		HumanAnchor: r.HumanAnchor, Requester: r.Requester, LawfulBasis: r.LawfulBasis,
		IssuedAt: r.IssuedAt, Sig: hex.EncodeToString(r.Sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/escrow/deanonymize", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handleDeanonymize(h)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no lawful basis: status = %d, want 400 (%s)", rr.Code, rr.Body.String())
	}
}
