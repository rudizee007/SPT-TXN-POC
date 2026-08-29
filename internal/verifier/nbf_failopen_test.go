package verifier

import (
	"math"
	"strings"
	"testing"
	"time"
)

// A present but unparseable nbf must be DENIED, never skipped. Before the fix,
// `intClaim` returning !ok for a garbled nbf skipped the whole window block, so a
// token could carry a junk nbf (NaN, Inf, out-of-range, or a non-number) and
// bypass its validity window entirely — a fail-open hole.
func TestCheckTemporal_PresentUnparseableNbf_Denied(t *testing.T) {
	now := float64(time.Now().Unix())
	for name, bad := range map[string]any{
		"string":     "garbage",
		"NaN":        math.NaN(),
		"+Inf":       math.Inf(1),
		"over-int64": 1e30,
		"bool":       true,
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"iat": now - 100, "exp": now + 10000, "nbf": bad}
			if err := checkChainTokenTemporal("CT", claims); err == nil {
				t.Fatalf("a present-but-unparseable nbf (%v) must be denied, not skipped", bad)
			}
		})
	}
}

// §1.3: the opening no longer gets an iatSkew grace, so a back-to-back sub-band
// cannot open early and overlap its predecessor (which would double the
// per-window cap). An nbf 30s out — inside the old 60s skew — must read as
// not-yet-valid, not opened early.
func TestCheckTemporal_NoSkewOnOpening(t *testing.T) {
	now := float64(time.Now().Unix())
	claims := map[string]any{"iat": now - 100, "exp": now + 10000, "nbf": now + 30}
	err := checkChainTokenTemporal("CT", claims)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("nbf 30s out must be not-yet-valid (no early open), got %v", err)
	}
}

// An absent nbf and an already-open nbf still pass — the fix only tightens the
// malformed and boundary cases, so ordinary windows are unaffected.
func TestCheckTemporal_ValidNbfStillPasses(t *testing.T) {
	now := float64(time.Now().Unix())
	if err := checkChainTokenTemporal("CT", map[string]any{"iat": now - 100, "exp": now + 100}); err != nil {
		t.Fatalf("absent nbf must pass: %v", err)
	}
	if err := checkChainTokenTemporal("CT", map[string]any{"iat": now - 100, "exp": now + 100, "nbf": now - 10}); err != nil {
		t.Fatalf("an open window must pass: %v", err)
	}
}

// nbfAttenuates: a parent whose nbf is present but unparseable is denied, not
// treated as windowless (which would let a child open at any time).
func TestNbfAttenuates_ParentUnparseableNbf_Denied(t *testing.T) {
	if err := nbfAttenuates(map[string]any{"nbf": "garbage"}, map[string]any{"nbf": float64(100)}); err == nil {
		t.Fatal("a parent with a present-but-unparseable nbf must be denied")
	}
	if err := nbfAttenuates(map[string]any{"nbf": math.Inf(1)}, map[string]any{"nbf": float64(100)}); err == nil {
		t.Fatal("a parent with an Inf nbf must be denied")
	}
}
