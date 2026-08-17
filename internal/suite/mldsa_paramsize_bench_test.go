//go:build mldsa

package suite

// Sizing and latency for the ML-DSA parameter sets, measured rather than quoted.
//
// THIS IS A DECISION INPUT, NOT A PERMANENT TEST. It exists to answer one
// question before the hybrid suite's parameter set is fixed: does ML-DSA-87 fit
// through the transport this system actually uses, and does it fit inside the
// decision-path latency budget?
//
// Why it matters here specifically. SPT-Txn tokens are transaction-scoped and
// travel in HTTP headers alongside a DPoP proof. Many proxies and gateways cap
// total header bytes around 8 KB. And the decision path holds a p99 under ~10ms
// as a SECURITY requirement, not a performance one — a PEP that is too slow gets
// bypassed by platform teams, and a bypassed PEP is worse than no PEP because it
// creates the false belief that enforcement exists.
//
// CNSA 2.0 mandates ML-DSA-87 for National Security Systems. The commercial
// ecosystem has no such constraint. If 87 does not fit the header budget, that
// is not a reason to refuse it — it is a reason for the NSS profile to carry
// tokens somewhere other than a header, and to know that before promising it.
//
// Delete this file once the numbers are recorded in the parameter-set decision.
//
//	go test -tags mldsa -run '^$' -bench BenchmarkMLDSAParams -benchmem ./internal/suite/
//	go test -tags mldsa -run TestMLDSASizes -v ./internal/suite/

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/mldsa"
)

func paramSets() []struct {
	name string
	p    *mldsa.Parameters
} {
	return []struct {
		name string
		p    *mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	}
}

// TestMLDSASizes reports the numbers the pairing decision depends on: the
// signature and public key sizes per parameter set, and what a hybrid envelope
// costs once Ed25519 and base64url expansion are included.
func TestMLDSASizes(t *testing.T) {
	const b64Expansion = 4.0 / 3.0 // JWS/JWT carry base64url, not raw bytes
	msg := []byte("spt-txn parameter sizing probe")

	t.Logf("%-12s %10s %10s %14s %14s", "params", "sig", "pubkey", "hybrid raw", "hybrid b64")
	for _, ps := range paramSets() {
		sk, err := mldsa.GenerateKey(ps.p)
		if err != nil {
			t.Fatalf("%s: keygen: %v", ps.name, err)
		}
		sig, err := sk.Sign(nil, msg, &mldsa.Options{Context: "sizing"})
		if err != nil {
			t.Fatalf("%s: sign: %v", ps.name, err)
		}
		pk := sk.PublicKey().Bytes()

		// A hybrid envelope carries BOTH signatures. Ed25519 is 64 bytes.
		hybridRaw := len(sig) + ed25519.SignatureSize
		hybridB64 := int(float64(hybridRaw) * b64Expansion)

		t.Logf("%-12s %10d %10d %14d %14d", ps.name, len(sig), len(pk), hybridRaw, hybridB64)

		// The header budget is the decision. 8 KB is the common proxy cap, and a
		// request carries more than one token plus a DPoP proof.
		if hybridB64 > 8192 {
			t.Logf("  ^ %s hybrid EXCEEDS a bare 8KB header budget before any other header",
				ps.name)
		} else if hybridB64 > 4096 {
			t.Logf("  ^ %s hybrid uses over half an 8KB budget; check it against a real request",
				ps.name)
		}
	}
}

// BenchmarkMLDSAParams measures sign and verify per parameter set. Verify is the
// one that matters: it runs on the decision path, on every request, inside the
// p99 budget. Signing happens at issuance and is not in that path.
func BenchmarkMLDSAParams(b *testing.B) {
	msg := []byte("spt-txn parameter sizing probe")
	opts := &mldsa.Options{Context: "sizing"}

	for _, ps := range paramSets() {
		sk, err := mldsa.GenerateKey(ps.p)
		if err != nil {
			b.Fatalf("%s: keygen: %v", ps.name, err)
		}
		sig, err := sk.Sign(nil, msg, opts)
		if err != nil {
			b.Fatalf("%s: sign: %v", ps.name, err)
		}
		pk := sk.PublicKey()

		b.Run(ps.name+"/Sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := sk.Sign(nil, msg, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(ps.name+"/Verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := mldsa.Verify(pk, msg, sig, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
