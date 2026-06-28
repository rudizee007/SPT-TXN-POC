package zkproof_test

// eddsa_probe_test.go — a standalone probe that pins the gnark v0.15 in-circuit
// EdDSA (Baby Jubjub) API before it is folded into ChainCircuit (F1 phase 2).
// It generates a Baby Jubjub key, signs one field element NATIVELY (MiMC
// challenge hash), and verifies that signature IN-CIRCUIT. If this passes, the
// exact API — NewEdCurve, eddsa.Verify, PublicKey/Signature.Assign, and the
// native/circuit hash match — is correct for this gnark/gnark-crypto version.
//
// Delete once ChainCircuit's per-hop signature check is in and tested.

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	gchash "github.com/consensys/gnark-crypto/hash"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

type eddsaProbe struct {
	PubKey eddsa.PublicKey `gnark:",public"`
	Sig    eddsa.Signature
	Msg    frontend.Variable
}

func (c *eddsaProbe) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	mh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return eddsa.Verify(curve, c.Sig, c.Msg, c.PubKey, &mh)
}

func TestEdDSA_InCircuit_Probe(t *testing.T) {
	// Native: keygen + sign a single field element (MiMC challenge hash).
	priv, err := eddsabn254.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var msg fr.Element
	msg.SetUint64(123456789)
	msgBytes := msg.Marshal()

	sigBytes, err := priv.Sign(msgBytes, gchash.MIMC_BN254.New())
	if err != nil {
		t.Fatalf("native sign: %v", err)
	}
	// Sanity: the signature verifies natively.
	ok, err := priv.PublicKey.Verify(sigBytes, msgBytes, gchash.MIMC_BN254.New())
	if err != nil || !ok {
		t.Fatalf("native verify failed: ok=%v err=%v", ok, err)
	}

	msgBig := new(big.Int)
	msg.BigInt(msgBig)

	// Valid witness solves the circuit.
	good := &eddsaProbe{Msg: msgBig}
	good.PubKey.Assign(tedwards.BN254, priv.PublicKey.Bytes())
	good.Sig.Assign(tedwards.BN254, sigBytes)
	if err := test.IsSolved(&eddsaProbe{}, good, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("valid in-circuit EdDSA not solved: %v", err)
	}

	// Tampered message must NOT solve (the signature is over the real message).
	bad := &eddsaProbe{Msg: new(big.Int).Add(msgBig, big.NewInt(1))}
	bad.PubKey.Assign(tedwards.BN254, priv.PublicKey.Bytes())
	bad.Sig.Assign(tedwards.BN254, sigBytes)
	if err := test.IsSolved(&eddsaProbe{}, bad, ecc.BN254.ScalarField()); err == nil {
		t.Error("in-circuit EdDSA accepted a tampered message")
	}
}
