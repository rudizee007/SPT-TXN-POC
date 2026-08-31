// Command mcp-pep is the SPT-Txn MCP policy-enforcement point as a runnable
// stdio proxy — docs/spec/DELEGATION-INTENT-MCP.md §3, the MCP form factor of
// the gateway profiles in docs/spec/GATEWAY-PROFILES.md.
//
// It sits between an MCP client (Claude Code, Claude Desktop, Cursor, any agent
// runtime) and a wrapped MCP server that it spawns as a child process. Every
// tools/call the agent makes must present a transaction-scoped SPT-Txn token in
// params._meta["spt-txn/token"] whose intent binding matches the invocation.
// A prompt-injected or hijacked call — different tool, mutated arguments, a
// token minted for another server — is denied before the wrapped server sees
// it, and a signed receipt is written for every decision, permit or deny.
//
// # What this process holds
//
// No signing keys for authorization, and no custody of anything it authorizes.
// It holds one PUBLIC key (the TTS issuer's, to verify presented tokens) and
// one log key (to sign receipts, which is evidence, not authority). It cannot
// mint a token, it cannot move value, and it is not in the settlement path.
// Its entire job is to decide whether the call proceeds. The middleware strips
// the credential before forwarding, so the wrapped server never sees, stores or
// re-presents it — the MCP token-passthrough gap is closed here rather than
// reproduced (docs/THREAT-MODEL.md §4.6).
//
// # Why this binary exists
//
// internal/mcppep was the enforcement point with no way to run it; the decision
// core, the intent binding and the receipt log were all reachable only from
// tests. This wires them to a real stdio transport without adding trust-boundary
// code: every check still happens in decision.Engine and internal/mcppep.
//
// Run it as an MCP server that wraps another MCP server:
//
//	{ "mcpServers": { "guarded": {
//	    "command": "mcp-pep",
//	    "args": ["-server-identity", "payments.example",
//	             "-audience", "payments.example",
//	             "-tts-pub", "<hex>", "-log-key-file", "log.key",
//	             "-policy-hash", "<hash>",
//	             "--", "the-real-mcp-server", "--its", "--flags"] } } }
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/mcppep"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
)

// maxMessageBytes bounds a single JSON-RPC line in either direction. An
// unbounded scanner on a pipe an adversary can write to is a memory-exhaustion
// primitive; MCP messages carrying inline resource content are large but not
// this large.
const maxMessageBytes = 4 << 20

func main() {
	pepName := flag.String("pep", "mcp-pep.spt-txn", "PEP identity (trust registry name)")
	serverIdentity := flag.String("server-identity", "",
		"identity of the wrapped MCP server — the intent `target`. A token minted for "+
			"another server MUST NOT verify here (required).")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "mcp-pep-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	audience := flag.String("audience", "",
		"executing-domain identity this PEP answers for, matched against the token's aud "+
			"(required). Distinct from -pep (a registry identity) and -server-identity (a "+
			"resource): this is the domain the token was minted FOR.")
	maxTTL := flag.Duration("max-token-ttl", 60*time.Second,
		"longest remaining token lifetime this PEP accepts. An MCP PEP does not walk the "+
			"chain, so this IS the revocation latency (GATEWAY-PROFILES.md 1.1).")
	flag.Parse()

	wrapped := flag.Args()
	if missing := missingRequired(*serverIdentity, *audience, *ttsPubHex,
		*logKeyFile, *policyHash, wrapped); len(missing) > 0 {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\nUsage: mcp-pep [flags] -- <wrapped-server-command> [args...]")
		fmt.Fprintf(os.Stderr, "\nnot set: %s\n", strings.Join(missing, ", "))
		fmt.Fprintln(os.Stderr, "Each of these must be set explicitly. This PEP has no mode that "+
			"skips verification, and no default that would let it answer for any audience: an "+
			"empty expected audience matches a token that omits aud, so a PEP configured by "+
			"omission would accept tokens minted for any domain.")
		os.Exit(2)
	}

	engine, closeAudit, err := buildEngine(pepConfig{
		pepName:      *pepName,
		ttsPubHex:    *ttsPubHex,
		logKeyFile:   *logKeyFile,
		auditPath:    *auditPath,
		policyHash:   *policyHash,
		jurisdiction: *jurisdiction,
		audience:     *audience,
		maxTTL:       *maxTTL,
	})
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer closeAudit()

	// Diagnostics go to stderr — stdout carries the MCP protocol and nothing else.
	log.SetOutput(os.Stderr)

	child := exec.Command(wrapped[0], wrapped[1:]...)
	childIn, err := child.StdinPipe()
	if err != nil {
		log.Fatalf("wrapped server stdin: %v", err)
	}
	childOut, err := child.StdoutPipe()
	if err != nil {
		log.Fatalf("wrapped server stdout: %v", err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		log.Fatalf("wrapped server: %v", err)
	}

	out := newLineWriter(os.Stdout)
	conn := newChildConn(childIn, childOut, out.write)

	mw, err := mcppep.New(engine, *serverIdentity, conn.forward)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	fmt.Fprintf(os.Stderr, "spt-txn mcp-pep ready (stdio) — guarding %q as %q, audience %q\n",
		wrapped[0], *serverIdentity, *audience)

	if err := serve(os.Stdin, mw, out); err != nil {
		log.Printf("client stream: %v", err)
	}

	_ = childIn.Close()
	if err := child.Wait(); err != nil {
		log.Printf("wrapped server exited: %v", err)
	}
}

// handler is the enforcement surface serve drives. It is an interface rather
// than the concrete *mcppep.Middleware for one reason: the nil-response branch
// below is unreachable through the real middleware, and a branch that cannot be
// reached in a test is a branch that cannot be shown to work.
type handler interface {
	Handle(ctx context.Context, raw []byte) []byte
}

// serve reads newline-delimited JSON-RPC from r and drives the middleware.
func serve(r io.Reader, mw handler, out *lineWriter) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	ctx := context.Background()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		raw := append([]byte(nil), line...)
		resp := mw.Handle(ctx, raw)
		if resp != nil {
			out.write(resp)
			continue
		}
		// Handle's contract is that a request always produces a response and
		// only notifications produce none. This is a belt-and-braces on that
		// contract rather than a check the PEP relies on: if a future change
		// ever returned nil for a request, silently dropping it would look to
		// the agent like a hung tool rather than a refusal. Answer with the
		// same uniform denial the middleware itself emits.
		if id, isRequest := rpcID(raw); isRequest {
			out.write(denial(id))
		}
	}
	return sc.Err()
}

// lineWriter serializes newline-delimited writes to a single stream. Both the
// main loop and the child-connection's out-of-band relay write to stdout, so
// the framing has to be guarded or two messages can interleave into one
// unparseable line.
type lineWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newLineWriter(w io.Writer) *lineWriter {
	return &lineWriter{w: bufio.NewWriterSize(w, 64*1024)}
}

func (l *lineWriter) write(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(bytes.TrimSpace(b))
	l.w.WriteByte('\n')
	l.w.Flush()
}

// childConn is the framed stdio link to the wrapped MCP server.
type childConn struct {
	mu  sync.Mutex
	in  io.Writer
	out *bufio.Scanner
	oob func([]byte)
}

func newChildConn(in io.Writer, out io.Reader, oob func([]byte)) *childConn {
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	return &childConn{in: in, out: sc, oob: oob}
}

// forward writes one (already token-stripped) message to the wrapped server and
// returns its matching response. Notifications get no response, matching
// mcppep.Forward's contract.
//
// The lock makes one exchange atomic. A stdio pipe carries no multiplexing of
// its own, so two concurrent forwards could otherwise read each other's
// replies — which would hand the agent a response that was authorized for a
// different call.
func (c *childConn) forward(_ context.Context, raw []byte) ([]byte, error) {
	id, isRequest := rpcID(raw)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.in.Write(append(bytes.TrimSpace(raw), '\n')); err != nil {
		return nil, err
	}
	if !isRequest {
		return nil, nil
	}
	for c.out.Scan() {
		line := bytes.TrimSpace(c.out.Bytes())
		if len(line) == 0 {
			continue
		}
		msg := append([]byte(nil), line...)
		if rid, ok := rpcID(msg); ok && bytes.Equal(bytes.TrimSpace(rid), bytes.TrimSpace(id)) {
			return msg, nil
		}
		// A server-initiated notification, or a response to something else,
		// arriving mid-exchange. Relay it to the client untouched rather than
		// dropping it — but never treat it as this call's answer.
		c.oob(msg)
	}
	if err := c.out.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("wrapped server closed its stream before answering")
}

// rpcID reports a message's JSON-RPC id and whether the message is a request.
// A missing or null id is a notification (JSON-RPC 2.0 §4.1).
//
// Ids are compared as raw JSON bytes: the client chooses the id and a
// conforming server echoes it back unchanged, so 1 matches 1 and "a" matches
// "a". A server that re-encoded 1 as 1.0 would not match, and this would time
// out rather than mis-pair — the failure direction is refusal, not confusion.
func rpcID(raw []byte) (json.RawMessage, bool) {
	var m struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	if len(m.ID) == 0 || string(bytes.TrimSpace(m.ID)) == "null" {
		return nil, false
	}
	return m.ID, true
}

// denial is the same uniform refusal internal/mcppep puts on the wire: the
// failing check stays in the receipt, not in the error the agent reads.
func denial(id json.RawMessage) []byte {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": mcppep.CodeDenied, "message": "spt-txn: denied"},
	})
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"spt-txn: denied"}}`)
	}
	return b
}

// pepConfig is the resolved startup configuration.
type pepConfig struct {
	pepName      string
	ttsPubHex    string
	logKeyFile   string
	auditPath    string
	policyHash   string
	jurisdiction string
	audience     string
	maxTTL       time.Duration
}

// buildEngine loads the key material and assembles the decision core. Every
// failure here is a startup failure by design: there is no verification-less
// mode and no evidence-less mode to fall back to, so a bad key, an unreadable
// key file or an unopenable audit log must stop the process rather than
// produce a PEP that answers anyway. It returns a closer for the audit log.
func buildEngine(c pepConfig) (*decision.Engine, func() error, error) {
	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("tts-pub: %w", err)
	}
	logKeyHex, err := os.ReadFile(c.logKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("log-key-file: %w", err)
	}
	logKey, err := parseHexKey(string(bytes.TrimSpace(logKeyHex)), ed25519.PrivateKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("log key: %w", err)
	}
	auditLog, err := audit.Open(c.auditPath)
	if err != nil {
		return nil, nil, fmt.Errorf("audit log: %w", err)
	}
	emitter, err := receiptlog.NewLogEmitter(auditLog, ed25519.PrivateKey(logKey))
	if err != nil {
		auditLog.Close()
		return nil, nil, fmt.Errorf("emitter: %w", err)
	}
	engine, err := decision.New(decision.Config{
		PEP:          c.pepName,
		PolicyHash:   c.policyHash,
		Jurisdiction: c.jurisdiction,
		Verify: func(_ context.Context, token string) (map[string]any, error) {
			return txntoken.Verify(token, ed25519.PublicKey(ttsPub))
		},
		Emit:        emitter.Emit,
		Audience:    c.audience,
		MaxTokenTTL: c.maxTTL,
	})
	if err != nil {
		auditLog.Close()
		return nil, nil, fmt.Errorf("engine: %w", err)
	}
	return engine, auditLog.Close, nil
}

// missingRequired names the settings that have no safe default, in the order an
// operator would fix them. Each one is required rather than defaulted because
// the natural default is the empty string and the empty string is a fail-open:
// an absent audience matches a token that omits `aud`, an absent tts-pub means
// nothing to verify against, and an absent wrapped command means there is
// nothing being guarded. Returning the list rather than a bool exists so the
// operator is told which, instead of re-reading the whole usage block.
func missingRequired(serverIdentity, audience, ttsPub, logKeyFile, policyHash string, wrapped []string) []string {
	var missing []string
	for _, f := range []struct {
		name  string
		value string
	}{
		{"-server-identity", serverIdentity},
		{"-audience", audience},
		{"-tts-pub", ttsPub},
		{"-log-key-file", logKeyFile},
		{"-policy-hash", policyHash},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(wrapped) == 0 {
		missing = append(missing, "-- <wrapped-server-command>")
	}
	return missing
}

func parseHexKey(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d bytes, got %d", size, len(b))
	}
	return b, nil
}
