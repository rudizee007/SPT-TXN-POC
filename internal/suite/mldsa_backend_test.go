//go:build mldsa

package suite

// Real-backend hybrid tests. Run with:
//
//	go get filippo.io/mldsa && go test -tags mldsa ./internal/suite/

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"filippo.io/mldsa"
)

func TestHybridRealRoundTrip(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	env, err := Seal(SuiteHybrid65, []byte("payload"), PrivateKeySet{Ed25519: edPriv, PQ: sk})
	if err != nil {
		t.Fatal(err)
	}
	keys := PublicKeySet{Ed25519: edPub, PQ: sk.PublicKey()}

	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := Verify(env, keys, m, nil, ""); err != nil {
			t.Fatalf("mode %v: valid hybrid rejected: %v", m, err)
		}
	}

	// Tamper with payload → both modes reject.
	bad := *env
	bad.Payload = []byte("payl0ad")
	for _, m := range []Mode{ModeVerifyEither, ModeVerifyBoth} {
		if err := Verify(&bad, keys, m, nil, ""); err == nil {
			t.Fatalf("mode %v: tampered hybrid verified", m)
		}
	}

	// Downgrade: rewriting the outer suite to classical must fail — the
	// signing input committed to the hybrid identifier, and shape (2 sigs)
	// no longer matches EdDSA.
	down := *env
	down.Suite = SuiteEdDSA
	if err := Verify(&down, keys, ModeVerifyEither, nil, ""); err == nil {
		t.Fatal("downgraded envelope verified")
	}

	// Wrong parameter set rejected.
	sk44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(SuiteHybrid65, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk44}); err == nil {
		t.Fatal("ML-DSA-44 key accepted by an ML-DSA-65 suite")
	}
	// And the same guard holds in the other direction: the parameter set is per
	// suite, so an ML-DSA-65 key must not satisfy the ML-DSA-87 suite either.
	// Without this, adding a parameter set is one missing case away from a suite
	// that silently accepts the weaker key it was created to exclude.
	if _, err := Seal(SuiteHybrid87, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk}); err == nil {
		t.Fatal("ML-DSA-65 key accepted by an ML-DSA-87 suite")
	}
}

// A floor named CNSA2 must contain suites that actually meet CNSA 2.0.
//
// This previously read `Floors{"CNSA2": {SuiteHybrid}}` with the ML-DSA-65
// hybrid. The floor mechanism worked; the name was a false claim. CNSA 2.0
// mandates ML-DSA-87 at all classification levels, so a floor admitting
// ML-DSA-65 asserts a compliance property the deployment does not have — and a
// test is the worst place for that, because it reads as verification.
func TestHybridRealFloorStrict(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(nil)
	sk87, _ := mldsa.GenerateKey(mldsa.MLDSA87())
	sk65, _ := mldsa.GenerateKey(mldsa.MLDSA65())

	// Hybrid-87 is admitted as a transition suite; pure ML-DSA-87 is the end
	// state. Nothing weaker belongs under this name.
	floors := Floors{"CNSA2": {SuiteHybrid87, SuiteMLDSA87}}

	env, err := Seal(SuiteHybrid87, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk87})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, PublicKeySet{Ed25519: edPub, PQ: sk87.PublicKey()}, ModeVerifyBoth, floors, "CNSA2"); err != nil {
		t.Fatalf("hybrid-87 under the CNSA2 floor rejected: %v", err)
	}

	// The end state verifies under the same floor with no classical component.
	pure, err := Seal(SuiteMLDSA87, []byte("p"), PrivateKeySet{PQ: sk87})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pure, PublicKeySet{PQ: sk87.PublicKey()}, ModeVerifyBoth, floors, "CNSA2"); err != nil {
		t.Fatalf("pure ML-DSA-87 under the CNSA2 floor rejected: %v", err)
	}

	// Classical is below the floor.
	classical, _ := Seal(SuiteEdDSA, []byte("p"), PrivateKeySet{Ed25519: edPriv})
	if err := Verify(classical, PublicKeySet{Ed25519: edPub}, ModeVerifyBoth, floors, "CNSA2"); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("classical under CNSA2 floor: %v", err)
	}

	// AND SO IS THE ML-DSA-65 HYBRID. This is the assertion the old test could
	// not make, and the one that matters: post-quantum is not the same as CNSA
	// 2.0 compliant. A deployment that migrated to hybrid-65 and believes it has
	// met the federal bar has not.
	weak, err := Seal(SuiteHybrid65, []byte("p"), PrivateKeySet{Ed25519: edPriv, PQ: sk65})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(weak, PublicKeySet{Ed25519: edPub, PQ: sk65.PublicKey()}, ModeVerifyBoth, floors, "CNSA2"); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("ML-DSA-65 hybrid accepted under a CNSA2 floor: %v", err)
	}
}
