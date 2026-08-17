//go:build !mldsa

package suite

// mldsa_stub.go — default build: every PQ suite is REGISTERED (so its
// identifier is allowlisted and its envelope shape parses and tests) but all
// PQ operations fail closed with ErrSuiteUnavailable. Callers map this to
// decision class `unavailable` — never a silent fallback to classical.
//
// Registering the identifiers here rather than only in the tagged build is
// deliberate: an unregistered suite and an unavailable one are different
// operational facts. "I do not know this suite" and "I know it and cannot
// perform it in this build" send an operator to different places.
//
// Build with -tags mldsa (and `go get filippo.io/mldsa`) for the real
// backend; see mldsa_backend.go.

type pqStub struct{ params pqParamSet }

func (pqStub) Available() bool { return false }

func (pqStub) Sign(any, []byte) ([]byte, error) { return nil, errNoPQBackend }

func (pqStub) Verify(any, []byte, []byte) error { return errNoPQBackend }

func newPQ(p pqParamSet, _ string) pqBackend { return pqStub{params: p} }

func init() {
	Register(hybridSuite{id: SuiteHybrid65, pq: newPQ(pqMLDSA65, SuiteHybrid65)})
	Register(hybridSuite{id: SuiteHybrid87, pq: newPQ(pqMLDSA87, SuiteHybrid87)})
	Register(mldsaSuite{id: SuiteMLDSA87, pq: newPQ(pqMLDSA87, SuiteMLDSA87)})
}
