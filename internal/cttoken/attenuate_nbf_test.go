package cttoken

import (
	"math"
	"testing"
	"time"
)

// attenuateNotBefore must deny a parent whose nbf is present but unparseable,
// rather than silently treating the parent window as absent (parentNbf = 0),
// which would let a child open before a parent whose opening was merely garbled.
func TestAttenuateNotBefore_ParentUnparseableNbf_Denied(t *testing.T) {
	for name, bad := range map[string]any{
		"string":     "x",
		"NaN":        math.NaN(),
		"+Inf":       math.Inf(1),
		"over-int64": 1e30,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attenuateNotBefore(map[string]any{"nbf": bad}, time.Time{}, 1000); err == nil {
				t.Fatalf("issuance under a parent with a garbled nbf (%v) must be refused", bad)
			}
		})
	}
}

// A parent with a valid nbf still works: an unset requested opening inherits it,
// and a later requested opening is accepted.
func TestAttenuateNotBefore_ValidParentUnchanged(t *testing.T) {
	nbf, err := attenuateNotBefore(map[string]any{"nbf": float64(50)}, time.Time{}, 1000)
	if err != nil || nbf != 50 {
		t.Fatalf("a valid parent nbf must inherit: got nbf=%d err=%v", nbf, err)
	}
	// No parent nbf at all → no window, still fine.
	nbf, err = attenuateNotBefore(map[string]any{}, time.Time{}, 1000)
	if err != nil || nbf != 0 {
		t.Fatalf("no parent nbf must yield 0: got nbf=%d err=%v", nbf, err)
	}
}
