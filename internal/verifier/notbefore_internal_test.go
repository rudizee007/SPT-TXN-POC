package verifier

import (
	"strings"
	"testing"
	"time"
)

// tclaims mimics a signature-verified token: numeric claims arrive as float64
// (JSON), which is what intClaim expects. nbf is optional.
func tclaims(iat, exp int64, nbf *int64) map[string]any {
	m := map[string]any{"iat": float64(iat), "exp": float64(exp)}
	if nbf != nil {
		m["nbf"] = float64(*nbf)
	}
	return m
}
func pnbf(v int64) *int64 { return &v }

// -- checkChainTokenTemporal: the per-hop window (now < nbf -> not yet valid) --

func TestCheckTemporal_NoNbf_Unchanged(t *testing.T) {
	now := time.Now().Unix()
	if err := checkChainTokenTemporal("CT", tclaims(now-10, now+100, nil)); err != nil {
		t.Errorf("a token with no nbf must pass exactly as before: %v", err)
	}
}

func TestCheckTemporal_NbfOpen_Passes(t *testing.T) {
	now := time.Now().Unix()
	// opened 10s ago, closes in 100s
	if err := checkChainTokenTemporal("CT", tclaims(now-20, now+100, pnbf(now-10))); err != nil {
		t.Errorf("an open window must pass: %v", err)
	}
}

func TestCheckTemporal_NbfFuture_NotYetValid(t *testing.T) {
	now := time.Now().Unix()
	// opens in an hour, well beyond iatSkew
	err := checkChainTokenTemporal("CT", tclaims(now-10, now+7200, pnbf(now+3600)))
	if err == nil {
		t.Fatal("a not-yet-open window must be refused")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("want 'not yet valid', got: %v", err)
	}
}

func TestCheckTemporal_NbfEmptyWindow_Refused(t *testing.T) {
	now := time.Now().Unix()
	// nbf at exp -> empty window
	if err := checkChainTokenTemporal("CT", tclaims(now-10, now+50, pnbf(now+50))); err == nil {
		t.Fatal("an empty window (nbf >= exp) must be refused")
	}
}

// -- nbfAttenuates: a child may not open before its parent --

func TestNbfAttenuates_ParentNoNbf_ChildFree(t *testing.T) {
	// parent unbounded: a child may introduce a window, or have none
	if err := nbfAttenuates(tclaims(0, 100, nil), tclaims(0, 100, pnbf(50))); err != nil {
		t.Errorf("a child may introduce a window under an unbounded parent: %v", err)
	}
	if err := nbfAttenuates(tclaims(0, 100, nil), tclaims(0, 100, nil)); err != nil {
		t.Errorf("no windows anywhere must pass: %v", err)
	}
}

func TestNbfAttenuates_ChildOpensBeforeParent_Refused(t *testing.T) {
	err := nbfAttenuates(tclaims(0, 100, pnbf(50)), tclaims(0, 100, pnbf(49)))
	if err == nil {
		t.Fatal("a child opening before its parent must be refused")
	}
	if !strings.Contains(err.Error(), "opens before") {
		t.Errorf("want 'opens before', got: %v", err)
	}
}

// The subtle malicious case: a child that DROPS the parent's window would be
// valid during a time the parent's had not opened. Must be refused.
func TestNbfAttenuates_ChildDropsParentWindow_Refused(t *testing.T) {
	err := nbfAttenuates(tclaims(0, 100, pnbf(50)), tclaims(0, 100, nil))
	if err == nil {
		t.Fatal("a child dropping its parent's window (widening the opening) must be refused")
	}
	if !strings.Contains(err.Error(), "drops the nbf window") {
		t.Errorf("want 'drops the nbf window', got: %v", err)
	}
}

func TestNbfAttenuates_ChildOpensLaterOrEqual_Passes(t *testing.T) {
	if err := nbfAttenuates(tclaims(0, 100, pnbf(50)), tclaims(0, 100, pnbf(50))); err != nil {
		t.Errorf("an equal opening must pass: %v", err)
	}
	if err := nbfAttenuates(tclaims(0, 100, pnbf(50)), tclaims(0, 100, pnbf(60))); err != nil {
		t.Errorf("a later (narrower) opening must pass: %v", err)
	}
}
