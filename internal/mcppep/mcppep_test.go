package mcppep

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// testRig wires a Middleware over a stub verifier/emitter/server.
type testRig struct {
	mw        *Middleware
	forwarded [][]byte // raw requests that reached the wrapped server
	receipts  []*receipt.Receipt
	claims    map[string]map[string]any // token -> claims
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rig := &testRig{claims: map[string]map[string]any{}}
	eng, err := decision.New(decision.Config{
		PEP:        "mcp-pep.test",
		PolicyHash: receipt.TokenHash("policy-v1"),
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			c, ok := rig.claims[token]
			if !ok {
				return nil, fmt.Errorf("unknown token")
			}
			return c, nil
		},
		MaxTokenTTL: time.Minute,
		Emit: func(r *receipt.Receipt) (string, error) {
			if err := r.Sign(logKey); err != nil {
				return "", err
			}
			rig.receipts = append(rig.receipts, r)
			return r.Hash()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mw, err := New(eng, "mcp://payments.test", func(ctx context.Context, raw []byte) ([]byte, error) {
		rig.forwarded = append(rig.forwarded, raw)
		return []byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.mw = mw
	return rig
}

// mint registers a token whose intent binding matches the given call.
func (r *testRig) mint(t *testing.T, token, jti, tool, argsJSON string) {
	t.Helper()
	d, err := intent.Intent{Tool: tool, Params: json.RawMessage(argsJSON), Target: "mcp://payments.test"}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Every real token carries exp; a fixture without one is refused
	// (token.exp-absent) and never reaches the check under test.
	r.claims[token] = map[string]any{"jti": jti, intent.Claim: d,
		"exp": float64(time.Now().Add(30 * time.Second).Unix())}
}

func callMsg(token, tool, argsJSON string) []byte {
	meta := ""
	if token != "" {
		meta = fmt.Sprintf(`,"_meta":{"spt-txn/token":%q}`, token)
	}
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s%s}}`, tool, argsJSON, meta))
}

func lastRule(t *testing.T, rig *testRig) string {
	t.Helper()
	if len(rig.receipts) == 0 {
		t.Fatal("no receipts")
	}
	return rig.receipts[len(rig.receipts)-1].RulePath
}

func assertDenied(t *testing.T, resp []byte, rig *testRig) {
	t.Helper()
	if len(rig.forwarded) != 0 {
		t.Fatal("denied call was forwarded to the server")
	}
	var e struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp, &e); err != nil || e.Error == nil {
		t.Fatalf("expected error response, got %s", resp)
	}
	// Uniform denial: never leak which check failed.
	if e.Error.Message != "spt-txn: denied" && e.Error.Code != CodeParse {
		t.Fatalf("non-uniform denial message %q", e.Error.Message)
	}
}

func TestAuthorizedCallForwardedWithTokenStripped(t *testing.T) {
	rig := newRig(t)
	args := `{"amount":"25.00","beneficiary":"acct-9"}`
	rig.mint(t, "tok-1", "jti-1", "payments.transfer", args)

	resp := rig.mw.Handle(context.Background(), callMsg("tok-1", "payments.transfer", args))
	if len(rig.forwarded) != 1 {
		t.Fatal("authorized call not forwarded")
	}
	if strings.Contains(string(rig.forwarded[0]), "tok-1") || strings.Contains(string(rig.forwarded[0]), TokenMetaKey) {
		t.Fatalf("credential leaked to wrapped server: %s", rig.forwarded[0])
	}
	if !strings.Contains(string(resp), `"ok":true`) {
		t.Fatalf("server result not returned: %s", resp)
	}
	if lastRule(t, rig) != "authorize.ok" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
	// Arguments must survive stripping untouched.
	var fwd struct {
		Params struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(rig.forwarded[0], &fwd); err != nil {
		t.Fatal(err)
	}
	if fwd.Params.Arguments["amount"] != "25.00" {
		t.Fatalf("arguments mutated in flight: %v", fwd.Params.Arguments)
	}
}

func TestHijackedCallDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-h", "jti-h", "files.read", `{"path":"/report.pdf"}`)
	// Same valid token, different tool — the goal-hijack case.
	resp := rig.mw.Handle(context.Background(), callMsg("tok-h", "files.delete", `{"path":"/report.pdf"}`))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "intent.digest-mismatch" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestMutatedArgumentsDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-m", "jti-m", "payments.transfer", `{"amount":"10.00"}`)
	resp := rig.mw.Handle(context.Background(), callMsg("tok-m", "payments.transfer", `{"amount":"999999.00"}`))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "intent.digest-mismatch" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestMissingTokenDenied(t *testing.T) {
	rig := newRig(t)
	resp := rig.mw.Handle(context.Background(), callMsg("", "payments.transfer", `{"amount":"1.00"}`))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "token.absent" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestUnknownTokenDenied(t *testing.T) {
	rig := newRig(t)
	resp := rig.mw.Handle(context.Background(), callMsg("tok-forged", "payments.transfer", `{"amount":"1.00"}`))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "token.verify" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestReplayDenied(t *testing.T) {
	rig := newRig(t)
	args := `{"amount":"5.00"}`
	rig.mint(t, "tok-r", "jti-r", "payments.transfer", args)
	if resp := rig.mw.Handle(context.Background(), callMsg("tok-r", "payments.transfer", args)); resp == nil {
		t.Fatal("first call failed")
	}
	rig.forwarded = nil
	resp := rig.mw.Handle(context.Background(), callMsg("tok-r", "payments.transfer", args))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "replay.duplicate" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestDuplicateParamsMembersDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-d", "jti-d", "safe.tool", `{}`)
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe.tool","name":"evil.tool","arguments":{},"_meta":{"spt-txn/token":"tok-d"}}}`)
	resp := rig.mw.Handle(context.Background(), raw)
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "rpc.params-ambiguous" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestUnknownParamsMemberDenied(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-u", "jti-u", "safe.tool", `{}`)
	// An extra top-level params member ("injected") is not covered by the
	// intent digest; forwarding it would hand the server un-authorized input.
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe.tool","arguments":{},"injected":{"evil":true},"_meta":{"spt-txn/token":"tok-u"}}}`)
	resp := rig.mw.Handle(context.Background(), raw)
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "rpc.params-ambiguous" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestMalformedDenied(t *testing.T) {
	rig := newRig(t)
	for _, raw := range []string{`{`, `[]`, `{"jsonrpc":"1.0","id":1,"method":"x"}`, `{"jsonrpc":"2.0","id":1}`} {
		rig.mw.Handle(context.Background(), []byte(raw))
		if len(rig.forwarded) != 0 {
			t.Fatalf("malformed %q reached the server", raw)
		}
	}
	if lastRule(t, rig) != "rpc.malformed" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

func TestNonCallTrafficPassesThroughWithObservationReceipt(t *testing.T) {
	rig := newRig(t)
	raw := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	resp := rig.mw.Handle(context.Background(), raw)
	if len(rig.forwarded) != 1 || resp == nil {
		t.Fatal("tools/list did not pass through")
	}
	if lastRule(t, rig) != "observe.passthrough.tools/list" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

// TestFloatArgumentsRejected: the accepted canonicalization subset excludes
// non-integer numbers; a declared-intent tool call using floats must be
// denied rather than approximated (amounts are decimal strings by profile).
func TestFloatArgumentsRejected(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-f", "jti-f", "pay", `{"amount":"1.50"}`)
	resp := rig.mw.Handle(context.Background(), callMsg("tok-f", "pay", `{"amount":1.50}`))
	assertDenied(t, resp, rig)
	if lastRule(t, rig) != "intent.digest-mismatch" {
		t.Fatalf("rule %s", lastRule(t, rig))
	}
}

// TestKeyOrderIrrelevant: reordering JSON members must not break a match —
// that is the entire point of canonicalization.
func TestKeyOrderIrrelevant(t *testing.T) {
	rig := newRig(t)
	rig.mint(t, "tok-o", "jti-o", "pay", `{"a":"1","b":"2"}`)
	resp := rig.mw.Handle(context.Background(), callMsg("tok-o", "pay", `{"b":"2","a":"1"}`))
	if len(rig.forwarded) != 1 {
		t.Fatalf("reordered-but-identical call denied: %s", resp)
	}
}
