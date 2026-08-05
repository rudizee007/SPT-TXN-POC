//go:build envoygrpc

// Command grpc-extauthz is the Envoy external authorization gRPC service
// (envoy.service.auth.v3) over the SPT-Txn decision core — the gRPC sibling of
// cmd/extauthz (HTTP mode). Most production Istio/Envoy deployments use the
// gRPC ext_authz API, so this is the higher-fidelity adoption path.
// Spec: docs/spec/GATEWAY-PROFILES.md §2.
//
// BUILD (requires two dependencies not in the default module graph, so this
// file is behind the `envoygrpc` build tag and never affects `go build ./...`).
// Fetch by package path so Go resolves whichever module version provides them:
//
//	go get github.com/envoyproxy/go-control-plane/envoy/service/auth/v3@latest
//	go get google.golang.org/grpc@latest
//	go build -tags envoygrpc ./cmd/grpc-extauthz/
//	go test  -tags envoygrpc ./cmd/grpc-extauthz/
//
// The skin holds no keys and contains no decision logic: it can deny on its
// own (malformed request) but only the engine returns a permit. On a permit it
// instructs Envoy to strip the token header so the credential never reaches the
// upstream (no passthrough). A decision is always an authz answer — the gRPC
// status is OK or PERMISSION_DENIED, never an internal error for a normal deny.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"github.com/rudizee007/spt-txn-poc/internal/audit"
	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
)

const tokenHeader = "x-spt-txn-token"

type server struct {
	authv3.UnimplementedAuthorizationServer
	engine   *decision.Engine
	upstream string
}

func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return denied("spt-txn: denied"), nil
	}
	token := httpReq.GetHeaders()[tokenHeader]

	d := s.engine.Decide(ctx, decision.Input{
		Token: token,
		Intent: intent.Intent{
			Tool:   httpReq.GetMethod(),
			Params: []byte(fmt.Sprintf(`{"path":%q}`, httpReq.GetPath())),
			Target: s.upstream,
		},
	})
	if d.Permit() {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(rpccode.Code_OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					// Strip the credential before it reaches the upstream.
					HeadersToRemove: []string{tokenHeader},
					Headers: []*corev3.HeaderValueOption{{
						Header: &corev3.HeaderValue{Key: "x-spt-txn-receipt", Value: d.ReceiptHash()},
					}},
				},
			},
		}, nil
	}
	return denied("spt-txn: denied"), nil
}

func denied(msg string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(rpccode.Code_PERMISSION_DENIED)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   msg,
			},
		},
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9193", "gRPC listen address")
	pep := flag.String("pep", "grpc-extauthz.spt-txn", "PEP identity")
	upstream := flag.String("upstream", "", "upstream service identity — the intent target (required)")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "grpc-extauthz-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	flag.Parse()

	if *upstream == "" || *ttsPubHex == "" || *logKeyFile == "" || *policyHash == "" {
		flag.Usage()
		os.Exit(2)
	}
	ttsPub, err := hex.DecodeString(*ttsPubHex)
	if err != nil || len(ttsPub) != ed25519.PublicKeySize {
		log.Fatalf("tts-pub must be %d hex bytes", ed25519.PublicKeySize)
	}
	keyRaw, err := os.ReadFile(*logKeyFile)
	if err != nil {
		log.Fatalf("log-key-file: %v", err)
	}
	logKey, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil || len(logKey) != ed25519.PrivateKeySize {
		log.Fatalf("log key must be %d hex bytes", ed25519.PrivateKeySize)
	}

	auditLog, err := audit.Open(*auditPath)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()
	emitter, err := receiptlog.NewLogEmitter(auditLog, ed25519.PrivateKey(logKey))
	if err != nil {
		log.Fatalf("emitter: %v", err)
	}

	engine, err := decision.New(decision.Config{
		PEP:          *pep,
		PolicyHash:   *policyHash,
		Jurisdiction: *jurisdiction,
		Verify: func(ctx context.Context, token string) (map[string]any, error) {
			return txntoken.Verify(token, ed25519.PublicKey(ttsPub))
		},
		Emit: emitter.Emit,
	})
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.ConnectionTimeout(5 * time.Second))
	authv3.RegisterAuthorizationServer(gs, &server{engine: engine, upstream: *upstream})
	log.Printf("spt-txn gRPC ext_authz listening on %s (upstream %s)", *listen, *upstream)
	log.Fatal(gs.Serve(lis))
}
