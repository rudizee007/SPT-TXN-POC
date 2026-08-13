package decision

// Latency is a security requirement (CLAUDE.md §2): a PEP too slow to tolerate
// gets bypassed, and a bypassed PEP is worse than none. These benchmarks put a
// hard number on the decision-core hot path and assert the p99 stays within the
// ~10ms budget so a regression that blows the budget fails CI, not production.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

func benchEngine(b *testing.B) (*Engine, Input) {
	b.Helper()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	in := Input{
		Token: "bench-token",
		Intent: intent.Intent{
			Tool:   "payments.transfer",
			Params: json.RawMessage(`{"amount":"100.00","beneficiary":"acct-9","currency":"USD"}`),
			Target: "mcp://payments",
		},
	}
	digest, err := in.Intent.Digest()
	if err != nil {
		b.Fatal(err)
	}
	eng, err := New(Config{
		PEP:        "bench.pep",
		PolicyHash: receipt.TokenHash("policy-v1"),
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			// Model the real cost: return claims with a fresh jti each call so
			// the replay cache admits every iteration (mirrors distinct tokens).
			return map[string]any{"jti": token, intent.Claim: digest,
				"exp": float64(time.Now().Add(30 * time.Second).Unix()),
				"aud": "aud.bench"}, nil
		},
		Emit: func(r *receipt.Receipt) (string, error) {
			// Sign (the real emitter's dominant cost) but skip disk I/O — the
			// benchmark isolates the decision path, not the log's fsync.
			if err := r.Sign(logKey); err != nil {
				return "", err
			}
			return r.Hash()
		},
		Audience:       "aud.bench",
		MaxTokenTTL:    time.Minute,
		ReplayCapacity: 1 << 20,
	})
	if err != nil {
		b.Fatal(err)
	}
	return eng, in
}

// BenchmarkDecide measures the full decision path (verify → replay → intent →
// receipt sign + hash) with a unique token per iteration.
func BenchmarkDecide(b *testing.B) {
	eng, in := benchEngine(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.Token = "tok-" + itoa(i)
		d := eng.Decide(ctx, in)
		if !d.Permit() {
			b.Fatalf("bench decision denied: %s", d.Rule())
		}
	}
}

// TestDecideP99Budget runs a fixed sample and asserts p99 < 10ms. It is a test
// (not a benchmark) so it runs in the normal suite and fails on a regression.
// The budget is generous headroom over the measured path (sign+hash dominate).
func TestDecideP99Budget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency budget check skipped in -short")
	}
	_, logKey, _ := ed25519.GenerateKey(nil)
	digestIntent := intent.Intent{Tool: "t", Params: json.RawMessage(`{"a":"1"}`), Target: "x"}
	digest, _ := digestIntent.Digest()
	eng, err := New(Config{
		PEP: "p", PolicyHash: "h",
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			return map[string]any{"jti": token, intent.Claim: digest,
				"exp": float64(time.Now().Add(30 * time.Second).Unix()),
				"aud": "aud.bench"}, nil
		},
		Emit:           func(r *receipt.Receipt) (string, error) { _ = r.Sign(logKey); return r.Hash() },
		Audience:       "aud.bench",
		MaxTokenTTL:    time.Minute,
		ReplayCapacity: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const n = 5000
	lat := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		d := eng.Decide(ctx, Input{Token: "t-" + itoa(i), Intent: digestIntent})
		lat[i] = time.Since(start)
		if !d.Permit() {
			t.Fatalf("denied at i=%d: %s", i, d.Rule())
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[int(float64(n)*0.99)]
	p50 := lat[n/2]
	t.Logf("decision path latency: p50=%v p99=%v (n=%d)", p50, p99, n)
	if p99 > 10*time.Millisecond {
		t.Fatalf("p99 %v exceeds the 10ms security budget", p99)
	}
}

// itoa avoids strconv in the hot loop's import set churn.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
