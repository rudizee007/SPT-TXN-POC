//go:build mldsa

package suite

// mldsa_backend.go — real ML-DSA (FIPS 204) backend via filippo.io/mldsa,
// a pure-Go audited-lineage implementation (no cgo — CLAUDE.md §2 memory
// safety holds). Enable with:
//
//	go get filippo.io/mldsa
//	go build -tags mldsa ./...
//
// When crypto/mldsa lands in the Go standard library (public API targeted
// for Go 1.27) this file swaps imports without touching call sites.
//
// PARAMETER SET AND CONTEXT ARE PER-BACKEND-INSTANCE, not global. Each suite
// binds its own: ML-DSA-65 for SuiteHybrid65, ML-DSA-87 for SuiteHybrid87 and
// SuiteMLDSA87. The context is the suite identifier, so the suite name is
// cryptographically bound inside the signature and suite confusion is
// structurally impossible rather than checked. That is also why renaming a
// suite identifier is an ENCODING change and not a rename.

import (
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

type pqReal struct {
	params *mldsa.Parameters
	name   string // for error text; the parameter set's own name
	ctx    string // domain-separation context == the suite identifier
}

func (pqReal) Available() bool { return true }

func (p pqReal) Sign(signer any, input []byte) ([]byte, error) {
	sk, ok := signer.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.New("ml-dsa: signer is not *mldsa.PrivateKey")
	}
	if sk.PublicKey().Parameters() != p.params {
		return nil, fmt.Errorf("ml-dsa: suite requires %s, key is %s",
			p.name, sk.PublicKey().Parameters())
	}
	return sk.Sign(nil, input, &mldsa.Options{Context: p.ctx})
}

func (p pqReal) Verify(pub any, input []byte, sig []byte) error {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return errors.New("ml-dsa: public key is not *mldsa.PublicKey")
	}
	if pk.Parameters() != p.params {
		return fmt.Errorf("ml-dsa: suite requires %s, key is %s", p.name, pk.Parameters())
	}
	return mldsa.Verify(pk, input, sig, &mldsa.Options{Context: p.ctx})
}

func newPQ(p pqParamSet, ctx string) pqBackend {
	switch p {
	case pqMLDSA65:
		return pqReal{params: mldsa.MLDSA65(), name: p.String(), ctx: ctx}
	case pqMLDSA87:
		return pqReal{params: mldsa.MLDSA87(), name: p.String(), ctx: ctx}
	default:
		// Unreachable while the two constants above are the only members, and
		// deliberately present: a new parameter set added without a case here
		// must fail closed rather than silently binding the wrong curve.
		return pqStubUnknown{}
	}
}

// pqStubUnknown fails closed for an unhandled parameter set.
type pqStubUnknown struct{}

func (pqStubUnknown) Available() bool                  { return false }
func (pqStubUnknown) Sign(any, []byte) ([]byte, error) { return nil, errNoPQBackend }
func (pqStubUnknown) Verify(any, []byte, []byte) error { return errNoPQBackend }

func init() {
	Register(hybridSuite{id: SuiteHybrid65, pq: newPQ(pqMLDSA65, SuiteHybrid65)})
	Register(hybridSuite{id: SuiteHybrid87, pq: newPQ(pqMLDSA87, SuiteHybrid87)})
	Register(mldsaSuite{id: SuiteMLDSA87, pq: newPQ(pqMLDSA87, SuiteMLDSA87)})
}
