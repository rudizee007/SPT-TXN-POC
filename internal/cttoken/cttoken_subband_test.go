package cttoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

func sbKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return pub, priv
}

// End-to-end issuance: a CAT commits to a division of its $100 cumulative budget;
// IssueSubbands mints the three slice CTs, each carrying membership in the CAT's
// committed root. Every slice verifies, and its membership claims round-trip.
func TestIssueSubbands_MintsCommittedSlices(t *testing.T) {
	issuerPub, issuerPriv := sbKeypair(t)
	holderPub, _ := sbKeypair(t)

	now := time.Now().Unix()
	divNbf, divExp := now, now+24*3600
	h := 8 * 3600
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "currency": "USD"}
	bands := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now, Expiry: now + int64(h)},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now + int64(h), Expiry: now + int64(2*h)},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now + int64(2*h), Expiry: divExp},
	}

	root, _, _, err := tbac.CommitBandDivision(tbac.SuiteSHA3_256, tbac.Scope(budget), divNbf, divExp, bands)
	if err != nil {
		t.Fatalf("CommitBandDivision: %v", err)
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: 48 * time.Hour, HolderPublicKey: holderPub,
		SubbandGroupRoot: root[:], SubbandGroupSize: 3, SubbandHashSuite: tbac.SuiteSHA3_256,
	}, issuerPriv)
	if err != nil {
		t.Fatalf("issue CAT: %v", err)
	}

	slices, err := cttoken.IssueSubbands(cttoken.SubbandIssueRequest{
		Issuer: "domain-a.authorg", ParentCAT: cat.Token, ParentIssuerKey: issuerPub,
		HashSuite: tbac.SuiteSHA3_256, DivisionNbf: divNbf, DivisionExp: divExp,
		Bands: bands, HolderPublicKeys: []ed25519.PublicKey{holderPub},
	}, issuerPriv)
	if err != nil {
		t.Fatalf("IssueSubbands: %v", err)
	}
	if len(slices) != 3 {
		t.Fatalf("expected 3 slices, got %d", len(slices))
	}

	wantRoot := hex.EncodeToString(root[:])
	for i, ct := range slices {
		if got, _ := ct.Claims["subband_group_root"].(string); got != wantRoot {
			t.Fatalf("slice %d group_root = %q, want %q", i, got, wantRoot)
		}
		// Each slice's scope carries its cumulative portion.
		scope, _ := ct.Claims["capability_scope"].(map[string]any)
		if scope["max_cumulative"] == nil {
			t.Fatalf("slice %d scope missing max_cumulative: %v", i, scope)
		}
		// Membership claims survive a verify round-trip (the signature covers them).
		claims, err := cttoken.Verify(ct.Token, issuerPub)
		if err != nil {
			t.Fatalf("verify slice %d: %v", i, err)
		}
		if claims["subband_group_root"] != wantRoot {
			t.Fatalf("slice %d: group_root did not survive verify", i)
		}
		if legF, ok := claims["subband_leg_index"].(float64); !ok || int(legF) != i {
			t.Fatalf("slice %d: subband_leg_index = %v, want %d", i, claims["subband_leg_index"], i)
		}
		if _, ok := claims["subband_merkle_path"]; !ok {
			t.Fatalf("slice %d: missing subband_merkle_path", i)
		}
		if gsF, ok := claims["subband_group_size"].(float64); !ok || int(gsF) != 3 {
			t.Fatalf("slice %d: subband_group_size = %v, want 3", i, claims["subband_group_size"])
		}
	}
}

// IssueSubbands refuses bands that do not reproduce the CAT's committed root —
// a caller cannot mint slices for a division the human's authority never signed.
func TestIssueSubbands_RefusesBandsOutsideCommitment(t *testing.T) {
	issuerPub, issuerPriv := sbKeypair(t)
	holderPub, _ := sbKeypair(t)

	now := time.Now().Unix()
	divNbf, divExp := now, now+24*3600
	h := 8 * 3600
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "currency": "USD"}
	committed := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now, Expiry: now + int64(h)},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now + int64(h), Expiry: now + int64(2*h)},
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now + int64(2*h), Expiry: divExp},
	}
	root, _, _, err := tbac.CommitBandDivision(tbac.SuiteSHA3_256, tbac.Scope(budget), divNbf, divExp, committed)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: 48 * time.Hour, HolderPublicKey: holderPub,
		SubbandGroupRoot: root[:], SubbandGroupSize: 3, SubbandHashSuite: tbac.SuiteSHA3_256,
	}, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Different bands (inflated budgets) — a different root than the CAT committed.
	tampered := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 30, "currency": "USD"}, NotBefore: now, Expiry: now + int64(h)},
		{Scope: tbac.Scope{"max_cumulative": 30, "currency": "USD"}, NotBefore: now + int64(h), Expiry: now + int64(2*h)},
		{Scope: tbac.Scope{"max_cumulative": 30, "currency": "USD"}, NotBefore: now + int64(2*h), Expiry: divExp},
	}
	_, err = cttoken.IssueSubbands(cttoken.SubbandIssueRequest{
		Issuer: "domain-a.authorg", ParentCAT: cat.Token, ParentIssuerKey: issuerPub,
		HashSuite: tbac.SuiteSHA3_256, DivisionNbf: divNbf, DivisionExp: divExp,
		Bands: tampered, HolderPublicKeys: []ed25519.PublicKey{holderPub},
	}, issuerPriv)
	if err == nil {
		t.Fatal("IssueSubbands minted slices for bands that do not match the CAT's committed root")
	}
}

// A CAT with no committed division cannot be sub-banded.
func TestIssueSubbands_RefusesUncommittedCAT(t *testing.T) {
	issuerPub, issuerPriv := sbKeypair(t)
	holderPub, _ := sbKeypair(t)
	now := time.Now().Unix()
	budget := cattoken.CapabilityScope{"max_cumulative": 100, "currency": "USD"}
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "domain-a.authorg", Subject: "alice", PrincipalName: "alice",
		Scope: budget, DelegationDepthMax: 3, TTL: 48 * time.Hour, HolderPublicKey: holderPub,
	}, issuerPriv) // no subband commitment
	if err != nil {
		t.Fatal(err)
	}
	bands := []tbac.Band{
		{Scope: tbac.Scope{"max_cumulative": 10, "currency": "USD"}, NotBefore: now, Expiry: now + 3600},
	}
	_, err = cttoken.IssueSubbands(cttoken.SubbandIssueRequest{
		Issuer: "domain-a.authorg", ParentCAT: cat.Token, ParentIssuerKey: issuerPub,
		HashSuite: tbac.SuiteSHA3_256, DivisionNbf: now, DivisionExp: now + 24*3600,
		Bands: bands, HolderPublicKeys: []ed25519.PublicKey{holderPub},
	}, issuerPriv)
	if err == nil {
		t.Fatal("IssueSubbands must refuse a CAT that carries no subband_group_root")
	}
}
