package oidc

// Regression test for the stale-JWKS fail-open (adversarial review 8, fix 4).
//
// tryRefresh returns (false, nil) when the minimum-interval limiter refuses --
// a refusal, deliberately not an error. Verify's stale branch discarded that
// bool, so a throttled refusal fell through and the EXPIRED key set was
// consulted anyway.
//
// Why no existing test caught it: TestJWKS_StaleKeySetIsRefetchedBeforeUse sets
// BOTH maxAge and minInterval to a nanosecond, so the limiter never refuses and
// the throttled path is never entered. The bug lives in the combination the
// suite never built -- a short maxAge with a long minInterval, which is the
// SHIPPING default shape (15 min / 30 s) once the provider stops answering.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestJWKS_StaleKeySetIsNotUsedWhenTheRefreshIsThrottled(t *testing.T) {
	i := newIDP(t)
	defer i.srv.Close()

	// maxAge tiny, minInterval long: the key set goes stale immediately and the
	// limiter refuses every refresh after the first.
	v, err := NewVerifier(context.Background(), i.issuer,
		WithJWKSMaxAge(time.Nanosecond), WithJWKSMinRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// NewVerifier calls refreshJWKS directly, so attemptedAt is still zero and
	// the limiter has nothing to compare against. Burn it with one verify: this
	// one legitimately refetches and must succeed.
	time.Sleep(2 * time.Millisecond)
	if _, err := v.Verify(context.Background(), i.mint(t, i.stdClaims(nil))); err != nil {
		t.Fatalf("the first verify should refetch and succeed: %v", err)
	}

	// From here the limiter refuses for an hour, and the key set is past maxAge.
	fetchedBefore := v.fetchedAt
	time.Sleep(2 * time.Millisecond)

	_, err = v.Verify(context.Background(), i.mint(t, i.stdClaims(nil)))
	if err == nil {
		t.Fatal("FAIL-OPEN: a key set older than maxAge verified a token while the refresh was throttled")
	}
	if !strings.Contains(err.Error(), "maxAge") {
		t.Fatalf("refused, but not as a staleness refusal -- the test may be passing for an unrelated reason: %v", err)
	}
	if !v.fetchedAt.Equal(fetchedBefore) {
		t.Fatal("the limiter did not actually throttle; this test is not exercising the path it claims")
	}
}
