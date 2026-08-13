package decision

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// harness wires an Engine with a stub verifier and an in-memory emitter that
// records every receipt, so tests can assert on the evidence as well as the
// decision.
type harness struct {
	engine    *Engine
	receipts  []*receipt.Receipt
	logKey    ed25519.PrivateKey
	logPub    ed25519.PublicKey
	claims    map[string]any // returned by the stub verifier on success
	verifyErr error
	emitErr   error
}

// The executing domain these fixtures answer for.
const audTest = "aud.test"

func newHarness(t *testing.T) *harness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{logKey: priv, logPub: pub}
	eng, err := New(Config{
		PEP:          "pep.test",
		PolicyHash:   receipt.TokenHash("policy-v1"),
		Jurisdiction: "TEST",
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			if h.verifyErr != nil {
				return nil, h.verifyErr
			}
			return h.claims, nil
		},
		Emit: func(r *receipt.Receipt) (string, error) {
			if h.emitErr != nil {
				return "", h.emitErr
			}
			if err := r.Sign(h.logKey); err != nil {
				return "", err
			}
			h.receipts = append(h.receipts, r)
			return mustHash(r), nil
		},
		Audience:       audTest,
		MaxTokenTTL:    time.Minute,
		ReplayWindow:   time.Minute,
		ReplayCapacity: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.engine = eng
	return h
}

// exp is a valid, in-bounds expiry for the harness's MaxTokenTTL. Claims
// without one are refused (token.exp-absent), so a fixture meaning to exercise
// a LATER check must carry a plausible expiry to reach it.
func (h *harness) exp() float64 { return float64(time.Now().Add(30 * time.Second).Unix()) }

func mustHash(r *receipt.Receipt) string {
	s, err := r.Hash()
	if err != nil {
		panic(err)
	}
	return s
}

func declaredIntent() intent.Intent {
	return intent.Intent{Tool: "payments.transfer", Params: json.RawMessage(`{"amount":"10.00"}`), Target: "mcp://pay"}
}

func (h *harness) bindClaims(t *testing.T, jti string, in intent.Intent) {
	t.Helper()
	d, err := in.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.claims = map[string]any{"jti": jti, intent.Claim: d, "exp": h.exp(), "aud": audTest}
}

func (h *harness) lastReceipt(t *testing.T) *receipt.Receipt {
	t.Helper()
	if len(h.receipts) == 0 {
		t.Fatal("no receipt emitted")
	}
	return h.receipts[len(h.receipts)-1]
}

func TestPermitPath(t *testing.T) {
	h := newHarness(t)
	h.bindClaims(t, "jti-1", declaredIntent())
	d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if !d.Permit() || d.Class() != receipt.ClassOK || d.Rule() != "authorize.ok" {
		t.Fatalf("permit path: %+v", d)
	}
	r := h.lastReceipt(t)
	if r.Decision != receipt.DecisionPermit {
		t.Fatalf("receipt decision %s", r.Decision)
	}
	if err := r.Verify(h.logPub); err != nil {
		t.Fatalf("receipt does not verify: %v", err)
	}
	if d.ReceiptHash() != mustHash(r) {
		t.Fatal("decision does not reference the emitted receipt")
	}
}

func TestEveryDenyPathEmitsReceiptAndClassifies(t *testing.T) {
	type tc struct {
		name      string
		setup     func(h *harness, t *testing.T)
		input     func(h *harness, t *testing.T) Input
		wantRule  string
		wantClass string
	}
	cases := []tc{
		{"absent token", func(h *harness, t *testing.T) {}, func(h *harness, t *testing.T) Input {
			return Input{Token: "", Intent: declaredIntent()}
		}, "token.absent", receipt.ClassViolation},
		{"verify violation", func(h *harness, t *testing.T) { h.verifyErr = errors.New("bad signature") }, func(h *harness, t *testing.T) Input {
			return Input{Token: "tok", Intent: declaredIntent()}
		}, "token.verify", receipt.ClassViolation},
		{"verify unavailable", func(h *harness, t *testing.T) { h.verifyErr = UnavailableError{errors.New("status list unreachable")} }, func(h *harness, t *testing.T) Input {
			return Input{Token: "tok", Intent: declaredIntent()}
		}, "token.verify-unavailable", receipt.ClassUnavailable},
		{"missing jti", func(h *harness, t *testing.T) { h.claims = map[string]any{intent.Claim: "x"} }, func(h *harness, t *testing.T) Input {
			return Input{Token: "tok", Intent: declaredIntent()}
		}, "token.jti-absent", receipt.ClassViolation},
		{"intent mismatch", func(h *harness, t *testing.T) { h.bindClaims(t, "jti-x", declaredIntent()) }, func(h *harness, t *testing.T) Input {
			other := declaredIntent()
			other.Tool = "payments.drain"
			return Input{Token: "tok", Intent: other}
		}, "intent.digest-mismatch", receipt.ClassViolation},
		{"no intent claim", func(h *harness, t *testing.T) {
			h.claims = map[string]any{"jti": "jti-y", "exp": h.exp(), "aud": audTest}
		}, func(h *harness, t *testing.T) Input {
			return Input{Token: "tok", Intent: declaredIntent()}
		}, "intent.digest-mismatch", receipt.ClassViolation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.claims = map[string]any{}
			c.setup(h, t)
			d := h.engine.Decide(context.Background(), c.input(h, t))
			if d.Permit() {
				t.Fatal("denied path permitted")
			}
			if d.Rule() != c.wantRule || d.Class() != c.wantClass {
				t.Fatalf("rule/class = %s/%s, want %s/%s", d.Rule(), d.Class(), c.wantRule, c.wantClass)
			}
			r := h.lastReceipt(t)
			if r.Decision != receipt.DecisionDeny || r.Class != c.wantClass || r.RulePath != c.wantRule {
				t.Fatalf("receipt %s/%s/%s does not match decision", r.Decision, r.Class, r.RulePath)
			}
		})
	}
}

func TestReplaySingleUse(t *testing.T) {
	h := newHarness(t)
	h.bindClaims(t, "jti-replay", declaredIntent())
	in := Input{Token: "tok", Intent: declaredIntent()}
	if d := h.engine.Decide(context.Background(), in); !d.Permit() {
		t.Fatalf("first use denied: %s", d.Rule())
	}
	d := h.engine.Decide(context.Background(), in)
	if d.Permit() || d.Rule() != "replay.duplicate" || d.Class() != receipt.ClassViolation {
		t.Fatalf("replay accepted: %+v", d)
	}
}

func TestReplayCacheFullDeniesUnavailable(t *testing.T) {
	h := newHarness(t) // capacity 4
	for i := 0; i < 4; i++ {
		h.bindClaims(t, fmt.Sprintf("jti-%d", i), declaredIntent())
		if d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()}); !d.Permit() {
			t.Fatalf("fill %d denied: %s", i, d.Rule())
		}
	}
	h.bindClaims(t, "jti-overflow", declaredIntent())
	d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if d.Permit() || d.Class() != receipt.ClassUnavailable || d.Rule() != "replay.cache-unavailable" {
		t.Fatalf("full cache did not deny-unavailable: %+v", d)
	}
}

// TestReceiptEmissionFailureDeniesEvenValidRequests: enforcement without
// evidence is not enforcement.
func TestReceiptEmissionFailureDenies(t *testing.T) {
	h := newHarness(t)
	h.bindClaims(t, "jti-e", declaredIntent())
	h.emitErr = errors.New("log unreachable")
	d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if d.Permit() {
		t.Fatal("permit granted without a logged receipt")
	}
	if d.Class() != receipt.ClassUnavailable || d.Rule() != "receipt.emit-failed" {
		t.Fatalf("got %s/%s", d.Class(), d.Rule())
	}
}

// TestZeroValueDenies: a Decision that never went through the engine denies
// with class unavailable — the structural fail-closed property.
func TestZeroValueDenies(t *testing.T) {
	var d Decision
	if d.Permit() {
		t.Fatal("zero-value Decision permits")
	}
	if d.Class() != receipt.ClassUnavailable {
		t.Fatalf("zero-value class %s", d.Class())
	}
	if d.Rule() != "decision.unset" {
		t.Fatalf("zero-value rule %s", d.Rule())
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{
		PEP:        "p",
		PolicyHash: "h",
		Verify:     func(context.Context, string) (map[string]any, error) { return nil, nil },
		Emit:       func(*receipt.Receipt) (string, error) { return "", nil },
		// Also required. Its own cases live in
		// TestNewRefusesAnUnboundedOrUnmemorableLifetime, which explains what
		// each refusal prevents — this table only asserts that absence is
		// rejected, which is not the interesting half.
		Audience:    audTest,
		MaxTokenTTL: time.Minute,
	}
	broken := []func(Config) Config{
		func(c Config) Config { c.PEP = ""; return c },
		func(c Config) Config { c.PolicyHash = ""; return c },
		func(c Config) Config { c.Verify = nil; return c },
		func(c Config) Config { c.Emit = nil; return c },
	}
	for i, b := range broken {
		if _, err := New(b(base)); err == nil {
			t.Errorf("config %d accepted; want error", i)
		}
	}
	if _, err := New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// ── lifetime bound (adversarial review #3, F3) ───────────────────────────────

// The construction-time guards. Both are refusals rather than warnings because
// the failures they prevent are silent: nothing reports that single use has
// stopped being single use.
func TestNewRefusesAnUnboundedOrUnmemorableLifetime(t *testing.T) {
	base := func() Config {
		return Config{
			PEP: "pep.test", PolicyHash: receipt.TokenHash("p"), Jurisdiction: "T",
			Verify:   func(context.Context, string) (map[string]any, error) { return nil, nil },
			Emit:     func(*receipt.Receipt) (string, error) { return "", nil },
			Audience: audTest,
		}
	}
	t.Run("MaxTokenTTL is required", func(t *testing.T) {
		if _, err := New(base()); err == nil {
			t.Fatal("constructed an engine with no declared lifetime bound: a PEP that " +
				"does not walk the chain would accept whatever lifetime the issuer chose")
		}
	})
	t.Run("ReplayWindow must cover MaxTokenTTL", func(t *testing.T) {
		c := base()
		c.MaxTokenTTL = time.Hour
		c.ReplayWindow = time.Minute
		if _, err := New(c); err == nil {
			t.Fatal("constructed an engine whose tokens outlive the memory of their own " +
				"jti — the slot is pruned while the token is still valid and it replays")
		}
	})
	t.Run("the default ReplayWindow does not silently under-cover", func(t *testing.T) {
		c := base()
		c.MaxTokenTTL = 20 * time.Minute // > the 10-minute default
		if _, err := New(c); err == nil {
			t.Fatal("defaulted ReplayWindow to 10m under a 20m MaxTokenTTL: a default " +
				"that quietly violates the invariant is worse than no default")
		}
	})
}

// The regression for the bypass itself. Before this bound existed, a token
// legitimately issued with a 24h TTL under a 24h capability was accepted by
// every shipped gateway skin, its jti was forgotten after the replay window,
// and the same token then replayed — every window, for 24 hours.
func TestOverLongTokenIsRefusedBeforeItCanBurnAReplaySlot(t *testing.T) {
	h := newHarness(t) // MaxTokenTTL = 1m
	h.bindClaims(t, "jti-long", declaredIntent())
	h.claims["exp"] = float64(time.Now().Add(24 * time.Hour).Unix())

	d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if d.Permit() {
		t.Fatal("a 24h token was permitted by a PEP that declared a 1m bound")
	}
	if d.Rule() != "token.ttl-excessive" || d.Class() != receipt.ClassViolation {
		t.Fatalf("rule/class = %s/%s, want token.ttl-excessive/%s", d.Rule(), d.Class(), receipt.ClassViolation)
	}

	// The refusal must NOT have consumed the jti. Otherwise an attacker with a
	// supply of over-long tokens fills a bounded cache with tokens that were
	// never acceptable, and a full cache denies everything as unavailable.
	h.claims["exp"] = h.exp()
	d2 := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if !d2.Permit() {
		t.Fatalf("the same jti was refused after an over-long presentation (%s/%s): "+
			"the rejected token burned a replay slot", d2.Rule(), d2.Class())
	}
}

// A verifier that does not surface exp leaves the lifetime unbounded and
// unknowable, so the engine must not proceed on trust.
func TestMissingExpIsRefused(t *testing.T) {
	h := newHarness(t)
	h.bindClaims(t, "jti-noexp", declaredIntent())
	delete(h.claims, "exp")

	d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
	if d.Permit() || d.Rule() != "token.exp-absent" {
		t.Fatalf("rule = %s, permit = %v; want token.exp-absent and a deny", d.Rule(), d.Permit())
	}
}

// ── audience binding (adversarial review #3, found alongside F3) ─────────────

// A gateway PEP does not run step 3 of the eight-step engine, so without this
// check any validly-signed, unexpired token from the same TTS is accepted —
// including one minted for a different executing domain. Every deployment under
// one issuer would collapse into a single audience.
func TestAudienceMustNameThisDeployment(t *testing.T) {
	for _, c := range []struct {
		name string
		aud  any
	}{
		{"another domain", "someone-else.execorg"},
		{"absent", nil},
		{"empty string", ""},
		{"non-string", 42.0},
		{"near miss", audTest + " "},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.bindClaims(t, "jti-aud-"+c.name, declaredIntent())
			if c.aud == nil {
				delete(h.claims, "aud")
			} else {
				h.claims["aud"] = c.aud
			}
			d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()})
			if d.Permit() {
				t.Fatal("permitted a token not minted for this domain")
			}
			if d.Rule() != "token.audience-mismatch" {
				t.Fatalf("rule = %s, want token.audience-mismatch", d.Rule())
			}
		})
	}

	// And the permit direction, so this is not satisfied by an engine that
	// denies everything.
	t.Run("matching audience is accepted", func(t *testing.T) {
		h := newHarness(t)
		h.bindClaims(t, "jti-aud-ok", declaredIntent())
		if d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()}); !d.Permit() {
			t.Fatalf("correct audience denied: %s", d.Rule())
		}
	})
}

// An empty expected audience matches a token that omits aud, so a PEP
// configured by omission would accept tokens minted for any domain. That is a
// fail-open reachable by forgetting a field, which is why it is refused at
// construction rather than at decision time.
func TestNewRefusesAnEmptyAudience(t *testing.T) {
	_, err := New(Config{
		PEP: "p", PolicyHash: "h",
		Verify:      func(context.Context, string) (map[string]any, error) { return nil, nil },
		Emit:        func(*receipt.Receipt) (string, error) { return "", nil },
		MaxTokenTTL: time.Minute,
	})
	if err == nil {
		t.Fatal("constructed a PEP with no expected audience")
	}
}

// The audience check must not consume the replay slot: a token for another
// domain can never be accepted here, so letting it burn a jti would let an
// attacker fill a bounded cache with tokens that were never acceptable — and a
// full cache denies every token as unavailable.
func TestAudienceMismatchDoesNotBurnAReplaySlot(t *testing.T) {
	h := newHarness(t)
	h.bindClaims(t, "jti-shared", declaredIntent())
	h.claims["aud"] = "someone-else.execorg"
	if d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()}); d.Permit() {
		t.Fatal("wrong audience permitted")
	}
	h.claims["aud"] = audTest
	if d := h.engine.Decide(context.Background(), Input{Token: "tok", Intent: declaredIntent()}); !d.Permit() {
		t.Fatalf("the rejected presentation burned the jti: %s", d.Rule())
	}
}
