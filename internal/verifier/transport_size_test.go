package verifier_test

// What a real request actually costs on the wire, measured rather than estimated.
//
// THIS IS A DECISION INPUT for the PQC suite work, not a permanent test. The
// question it answers: how much header budget does a delegation chain consume
// today under EdDSA, and therefore how much headroom exists for a
// post-quantum suite whose signatures are 50-100x larger?
//
// Why headers are the constraint. Tokens are transaction-scoped and travel in
// HTTP request headers alongside a DPoP proof. Proxies, gateways and load
// balancers commonly cap total header bytes around 8 KB, and that cap is
// enforced by infrastructure the deployment does not control. A chain that
// exceeds it fails at the edge, before the PEP sees it, in a way that looks
// like a network problem rather than an authorization one.
//
// Measured 2026-08-15 for the ML-DSA sizing decision:
//   ML-DSA-87 hybrid signature, base64url: 6,254 B  (verify 60us)
//   ML-DSA-65 hybrid signature, base64url: 4,497 B  (verify 40us)
//   ML-DSA-44 hybrid signature, base64url: 3,312 B  (verify 29us)
//
// Latency is not the constraint — 60us against a 10ms p99 budget is 0.6%.
// Size is. Multiply any of those by the number of tokens below.
//
// Delete once the numbers are recorded in the parameter-set decision.

import (
	"testing"
)

func TestTransportSize_RealRequest(t *testing.T) {
	h := build(t)

	parts := []struct {
		name string
		s    string
	}{
		{"CAT", h.in.CAT},
		{"CT (leaf)", h.in.CT},
		{"SPT-Txn", h.in.TxnToken},
		{"DPoP proof", h.in.DPoPProof},
	}

	total := 0
	t.Logf("%-14s %8s", "part", "bytes")
	for _, p := range parts {
		t.Logf("%-14s %8d", p.name, len(p.s))
		total += len(p.s)
	}
	for i, ct := range h.in.CTChain {
		t.Logf("%-14s %8d", "CT chain hop", len(ct))
		total += len(ct)
		_ = i
	}
	t.Logf("%-14s %8d  (EdDSA, this chain depth)", "TOTAL", total)

	// Ed25519 signatures are 64 bytes raw, ~88 base64url. Every token above
	// carries exactly one. Substituting a hybrid suite replaces that 88 with the
	// figures in the file header, per token.
	const edSigB64 = 88
	tokens := len(parts) - 1 + len(h.in.CTChain) // DPoP is signed too, but by the agent key
	t.Logf("")
	t.Logf("tokens carrying a signature: %d", tokens+1)
	for _, sw := range []struct {
		name string
		size int
	}{
		{"HYBRID-Ed25519-ML-DSA-44", 3312},
		{"HYBRID-Ed25519-ML-DSA-65", 4497},
		{"HYBRID-Ed25519-ML-DSA-87", 6254},
	} {
		projected := total + (tokens+1)*(sw.size-edSigB64)
		verdict := "fits an 8KB budget"
		if projected > 8192 {
			verdict = "EXCEEDS an 8KB budget"
		}
		t.Logf("  %-26s projected total %7d B  — %s", sw.name, projected, verdict)
	}
	t.Logf("")
	t.Logf("Projection substitutes the signature only; headers, claims and the")
	t.Logf("ML-DSA public keys (1312/1952/2592 B raw) are NOT included, so these")
	t.Logf("are floors rather than estimates. If a key must travel with the token,")
	t.Logf("add it per token.")
}
