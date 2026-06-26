package main

import (
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ivms101"
)

// fullReq is a FATF-complete attestation request: originator with full name,
// account/wallet and a national identifier; beneficiary with name and account.
func fullReq() *attestReq {
	return &attestReq{
		Originator: partyJSON{
			NamePrimary: "Mokoena", NameSecondary: "Thabo", Country: "ZA",
			Account: "rOriginatorWallet123", NationalID: "7901015800087", NationalIDType: "NIDN",
		},
		Beneficiary: partyJSON{
			NamePrimary: "Chen", NameSecondary: "Wei", Country: "SG",
			Account: "rBeneficiaryWallet456",
		},
		Amount: 5000, Currency: "USD",
	}
}

// TestBuildTransfer_ConveysFATFMinimum confirms the wired demo path produces an
// IVMS101 payload that satisfies the FATF Rec-16 minimum data set and exposes
// the required fields (name + account + identifier) as disclosable SD-JWT keys.
func TestBuildTransfer_ConveysFATFMinimum(t *testing.T) {
	transfer, _ := buildTransfer(fullReq())

	if err := transfer.Identity.Validate(); err != nil {
		t.Fatalf("FATF-complete request must validate: %v", err)
	}

	flat := transfer.Identity.Flatten()
	for _, k := range []string{
		"originator.name.primary", "originator.name.secondary", "originator.account",
		"originator.natId.id", "beneficiary.name.primary", "beneficiary.account",
	} {
		if _, ok := flat[k]; !ok {
			t.Errorf("flattened payload missing FATF field %q", k)
		}
	}
	if flat["originator.natId.id"] != "7901015800087" {
		t.Errorf("originator.natId.id = %v, want the supplied national-ID", flat["originator.natId.id"])
	}
}

// TestNatIDOf_DefaultsTypeAndOmitsWhenEmpty: no identifier → nil; an identifier
// without an explicit type defaults to NIDN (national identity number).
func TestNatIDOf_DefaultsTypeAndOmitsWhenEmpty(t *testing.T) {
	if natIDOf(partyJSON{}) != nil {
		t.Fatal("no national_id supplied must yield nil")
	}
	id := natIDOf(partyJSON{NationalID: "X123", Country: "ZA"})
	if id == nil || id.NationalIdentifier != "X123" {
		t.Fatalf("expected populated national identification, got %+v", id)
	}
	if id.NationalIdentifierType != ivms101.IDNational {
		t.Errorf("default type = %q, want NIDN", id.NationalIdentifierType)
	}
}

// TestDefaultDiscloseFATF_CoversRequiredFields: the default disclosure set names
// the FATF-required originator and beneficiary fields.
func TestDefaultDiscloseFATF_CoversRequiredFields(t *testing.T) {
	have := map[string]bool{}
	for _, k := range defaultDiscloseFATF {
		have[k] = true
	}
	for _, k := range []string{
		"originator.name.primary", "originator.account", "originator.natId.id",
		"beneficiary.name.primary", "beneficiary.account",
	} {
		if !have[k] {
			t.Errorf("defaultDiscloseFATF missing required key %q", k)
		}
	}
}
