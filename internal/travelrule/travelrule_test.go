package travelrule_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/ivms101"
	"github.com/rudizee007/spt-txn-poc/internal/travelrule"
	"github.com/rudizee007/spt-txn-poc/internal/zkproof"
)

// Trusted setup is expensive, so run it once for the whole test binary and
// share the artifacts (read-only for prove/verify). Issuer and verifier share
// them, which is correct: proofs only verify against the vk from the same setup.
var (
	once                       sync.Once
	gCommit, gThreshold, gVASP *zkproof.Artifacts
)

func arts(t *testing.T) (*zkproof.Artifacts, *zkproof.Artifacts, *zkproof.Artifacts) {
	t.Helper()
	once.Do(func() {
		var err error
		if gCommit, err = zkproof.Setup(zkproof.CircuitCommitment); err != nil {
			panic(err)
		}
		if gThreshold, err = zkproof.Setup(zkproof.CircuitThreshold); err != nil {
			panic(err)
		}
		if gVASP, err = zkproof.Setup(zkproof.CircuitVASP); err != nil {
			panic(err)
		}
	})
	return gCommit, gThreshold, gVASP
}

const benVASP = "vasp:beneficiary-bank"

func registryWith(t *testing.T, id string) *zkproof.MerkleTree {
	t.Helper()
	n := 1 << zkproof.VASPTreeDepth
	members := make([][]byte, n)
	for i := range members {
		members[i] = []byte(fmt.Sprintf("vasp:member:%d", i))
	}
	members[7] = []byte(id) // register the beneficiary VASP
	tree, err := zkproof.BuildVASPRegistry(members)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func newIssuerVerifier(t *testing.T, reg *zkproof.MerkleTree) (*travelrule.Issuer, *travelrule.Verifier) {
	t.Helper()
	c, th, v := arts(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := &travelrule.Issuer{
		Name: "did:web:authorg", Signer: priv,
		Commit: c, Threshold: th, VASP: v, Registry: reg,
	}
	ver := &travelrule.Verifier{
		IssuerPub: pub, Commit: c, Threshold: th, VASP: v, KnownRoot: reg.Root(),
	}
	return iss, ver
}

func sampleTransfer(amount uint64) (travelrule.Transfer, travelrule.Secrets) {
	tr := travelrule.Transfer{
		Identity: ivms101.IdentityPayload{
			Originator: ivms101.Originator{
				OriginatorPersons: []ivms101.Person{ivms101.PersonOf("Smith", "Alice", "KY", nil)},
				AccountNumber:     []string{"rAlice"},
			},
			Beneficiary: ivms101.Beneficiary{
				BeneficiaryPersons: []ivms101.Person{ivms101.PersonOf("Jones", "Bob", "US", nil)},
				AccountNumber:      []string{"rBob"},
			},
		},
		Amount: amount, Currency: "USD",
	}
	se := travelrule.Secrets{
		OriginatorID: []byte("alice-biometric-template"), OriginatorRand: []byte("anchor-rand-1"),
		AmountBlinding: []byte("amount-blinding-1"), BeneficiaryVASPID: []byte(benVASP),
	}
	return tr, se
}

func TestTravelRule_EndToEnd(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, ver := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(5000)
	const ctxHash = "deadbeefcafe0001"

	att, err := iss.Build(tr, se, ctxHash, time.Hour)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// The beneficiary VASP is entitled to the beneficiary's surname + currency
	// only — IVMS101 fields are addressed by dotted path.
	disclosed, err := ver.Verify(att, ctxHash, []string{"beneficiary.name.primary", "beneficiary.account", "currency"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if disclosed["beneficiary.name.primary"] != "Jones" || disclosed["currency"] != "USD" {
		t.Errorf("expected disclosed beneficiary fields, got %v", disclosed)
	}
	// Originator PII and the beneficiary's given name stay hidden; the amount is
	// never in the attestation at all.
	for _, hidden := range []string{"originator.account", "originator.name.primary", "beneficiary.name.secondary", "amount"} {
		if _, ok := disclosed[hidden]; ok {
			t.Errorf("%q must not be disclosed", hidden)
		}
	}
	// Binding claims are always present.
	if disclosed["txn_context_hash"] != ctxHash {
		t.Error("payment binding claim missing")
	}
}

func TestTravelRule_WrongPaymentRejected(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, ver := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(5000)
	att, err := iss.Build(tr, se, "payment-A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(att, "payment-B", []string{"currency"}); err == nil {
		t.Error("attestation bound to a different payment must be rejected")
	}
}

func TestTravelRule_SubThresholdFailsToBuild(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, _ := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(500) // below the 1000 reporting threshold
	if _, err := iss.Build(tr, se, "p", time.Hour); err == nil {
		t.Error("a sub-threshold transfer must not produce a reportable proof")
	}
}

func TestTravelRule_UnregisteredBeneficiaryFailsToBuild(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, _ := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(5000)
	se.BeneficiaryVASPID = []byte("vasp:NOT-REGISTERED")
	if _, err := iss.Build(tr, se, "p", time.Hour); err == nil {
		t.Error("an unregistered beneficiary VASP must fail to build a membership proof")
	}
}

func TestTravelRule_WrongRegistryRootRejected(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, ver := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(5000)
	att, err := iss.Build(tr, se, "p", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Verifier trusts a different registry root than the attestation references.
	other := registryWith(t, "vasp:some-other-bank")
	ver.KnownRoot = other.Root()
	if _, err := ver.Verify(att, "p", []string{"currency"}); err == nil {
		t.Error("attestation referencing an untrusted registry root must be rejected")
	}
}

// TR-1: the amount commitment is bound into the signed SD-JWT. Swapping in a
// different AmountCommitment after issuance must be caught by Verify's binding
// check (before the ZK threshold proof is even reached).
func TestTravelRule_AmountCommitmentBindingTamperRejected(t *testing.T) {
	reg := registryWith(t, benVASP)
	iss, ver := newIssuerVerifier(t, reg)
	tr, se := sampleTransfer(5000)
	const ctxHash = "deadbeefcafe0002"
	att, err := iss.Build(tr, se, ctxHash, time.Hour)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	att.AmountCommitment = "999999999999"
	if _, err := ver.Verify(att, ctxHash, []string{"currency"}); err == nil {
		t.Error("a swapped amount commitment must be rejected by the SD-JWT binding check")
	}
}
