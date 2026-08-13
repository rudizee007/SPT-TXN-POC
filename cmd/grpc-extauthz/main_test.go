//go:build envoygrpc

package main

// Run with: go test -tags envoygrpc ./cmd/grpc-extauthz/
// (needs github.com/envoyproxy/go-control-plane and google.golang.org/grpc)

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// stubEngine builds a decision engine whose verifier permits a fixed token and
// binds the HTTP intent the skin derives (tool=method, params={"path":...},
// target=upstream), so a well-formed Check() request is permitted.
func stubEngine(t *testing.T, upstream, method, path, token string) *decision.Engine {
	t.Helper()
	_, logKey, _ := ed25519.GenerateKey(nil)
	digest, err := intent.Intent{
		Tool:   method,
		Params: json.RawMessage(`{"path":` + jsonString(path) + `}`),
		Target: upstream,
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := decision.New(decision.Config{
		PEP: "grpc.test", PolicyHash: receipt.TokenHash("policy"),
		Verify: func(ctx context.Context, tok string) (map[string]any, error) {
			if tok != token {
				return nil, errBad
			}
			return map[string]any{"jti": tok, intent.Claim: digest}, nil
		},
		Audience:    "aud.test",
		MaxTokenTTL: time.Minute,
		Emit:        func(r *receipt.Receipt) (string, error) { _ = r.Sign(logKey); return r.Hash() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

var errBad = &stubErr{"bad token"}

type stubErr struct{ s string }

func (e *stubErr) Error() string { return e.s }

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func checkReq(method, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: method, Path: path, Headers: headers,
				},
			},
		},
	}
}

func TestCheck_PermitStripsTokenHeader(t *testing.T) {
	const upstream, method, path, token = "mcp://payments", "POST", "/transfer", "tok-1"
	s := &server{engine: stubEngine(t, upstream, method, path, token), upstream: upstream}

	resp, err := s.Check(context.Background(), checkReq(method, path, map[string]string{tokenHeader: token}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus().GetCode() != int32(rpccode.Code_OK) {
		t.Fatalf("expected OK, got status %d", resp.GetStatus().GetCode())
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("no OkResponse on a permit")
	}
	found := false
	for _, h := range ok.GetHeadersToRemove() {
		if h == tokenHeader {
			found = true
		}
	}
	if !found {
		t.Fatalf("permit did not instruct Envoy to strip %q (credential passthrough risk)", tokenHeader)
	}
}

func TestCheck_DenyOnBadToken(t *testing.T) {
	const upstream, method, path = "mcp://payments", "POST", "/transfer"
	s := &server{engine: stubEngine(t, upstream, method, path, "the-real-token"), upstream: upstream}

	resp, err := s.Check(context.Background(), checkReq(method, path, map[string]string{tokenHeader: "forged"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus().GetCode() != int32(rpccode.Code_PERMISSION_DENIED) {
		t.Fatalf("expected PERMISSION_DENIED, got %d", resp.GetStatus().GetCode())
	}
	if resp.GetDeniedResponse() == nil {
		t.Fatal("no DeniedResponse on a deny")
	}
}

func TestCheck_DenyOnMissingHttpAttributes(t *testing.T) {
	s := &server{engine: stubEngine(t, "mcp://payments", "POST", "/x", "t"), upstream: "mcp://payments"}
	resp, err := s.Check(context.Background(), &authv3.CheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus().GetCode() != int32(rpccode.Code_PERMISSION_DENIED) {
		t.Fatal("malformed request (no HTTP attributes) was not denied")
	}
}
