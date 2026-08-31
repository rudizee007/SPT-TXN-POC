package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/mcppep"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

const testTarget = "mcp://payments.test"

// ── rig ───────────────────────────────────────────────────────────────────

type rig struct {
	mw        *mcppep.Middleware
	engine    *decision.Engine
	forwarded [][]byte
	receipts  []*receipt.Receipt
	claims    map[string]map[string]any
	reply     []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{
		claims: map[string]map[string]any{},
		reply:  []byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`),
	}
	eng, err := decision.New(decision.Config{
		PEP:        "mcp-pep.test",
		PolicyHash: receipt.TokenHash("policy-v1"),
		Verify: func(_ context.Context, token string) (map[string]any, error) {
			c, ok := r.claims[token]
			if !ok {
				return nil, fmt.Errorf("unknown token")
			}
			return c, nil
		},
		Audience:    "aud.test",
		MaxTokenTTL: time.Minute,
		Emit: func(rc *receipt.Receipt) (string, error) {
			if err := rc.Sign(logKey); err != nil {
				return "", err
			}
			r.receipts = append(r.receipts, rc)
			return rc.Hash()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mw, err := mcppep.New(eng, testTarget, func(_ context.Context, raw []byte) ([]byte, error) {
		r.forwarded = append(r.forwarded, append([]byte(nil), raw...))
		return r.reply, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r.mw = mw
	r.engine = eng
	return r
}

func (r *rig) mint(t *testing.T, token, jti, tool, argsJSON string) {
	t.Helper()
	d, err := intent.Intent{Tool: tool, Params: json.RawMessage(argsJSON), Target: testTarget}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.claims[token] = map[string]any{
		"jti": jti, intent.Claim: d, "aud": "aud.test",
		"exp": float64(time.Now().Add(30 * time.Second).Unix()),
	}
}

func callMsg(token, tool, argsJSON string) string {
	meta := ""
	if token != "" {
		meta = fmt.Sprintf(`,"_meta":{"spt-txn/token":%q}`, token)
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s%s}}`,
		tool, argsJSON, meta)
}

// ── rpcID ─────────────────────────────────────────────────────────────────

func TestRPCID(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		request bool
	}{
		{"numeric id is a request", `{"jsonrpc":"2.0","id":7,"method":"ping"}`, "7", true},
		{"string id is a request", `{"jsonrpc":"2.0","id":"a","method":"ping"}`, `"a"`, true},
		{"absent id is a notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "", false},
		{"null id is a notification", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, "", false},
		{"malformed json is not a request", `{not json`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, isReq := rpcID([]byte(c.raw))
			if isReq != c.request {
				t.Fatalf("isRequest = %v, want %v", isReq, c.request)
			}
			if c.request && string(id) != c.want {
				t.Fatalf("id = %s, want %s", id, c.want)
			}
		})
	}
}

// A notification MUST NOT be treated as a request: if it were, forward would
// block waiting for a reply that a conforming server never sends, and the whole
// stdio link would wedge behind the exchange lock.
func TestChildConn_NotificationGetsNoReplyAndDoesNotBlock(t *testing.T) {
	var in bytes.Buffer
	c := newChildConn(&in, strings.NewReader(""), func([]byte) {
		t.Fatal("a notification must not produce out-of-band relay")
	})
	resp, err := c.forward(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if resp != nil {
		t.Fatalf("notification returned a response: %s", resp)
	}
	if !strings.Contains(in.String(), "notifications/initialized") {
		t.Fatalf("notification was not written to the wrapped server: %q", in.String())
	}
}

func TestChildConn_RequestGetsItsMatchingResponse(t *testing.T) {
	var in bytes.Buffer
	out := strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` + "\n")
	c := newChildConn(&in, out, func([]byte) { t.Fatal("no out-of-band traffic expected") })
	resp, err := c.forward(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !bytes.Contains(resp, []byte(`"ok":true`)) {
		t.Fatalf("wrong response: %s", resp)
	}
}

// The security-relevant case: a message arriving mid-exchange that is NOT this
// call's answer must be relayed to the client, never returned as the answer.
// Returning it would hand the agent a result authorized for a different call.
func TestChildConn_UnrelatedMessageIsRelayedNotReturned(t *testing.T) {
	var in bytes.Buffer
	out := strings.NewReader(
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"p":1}}` + "\n" +
			`{"jsonrpc":"2.0","id":99,"result":{"other":true}}` + "\n" +
			`{"jsonrpc":"2.0","id":1,"result":{"mine":true}}` + "\n")
	var relayed [][]byte
	c := newChildConn(&in, out, func(b []byte) { relayed = append(relayed, append([]byte(nil), b...)) })

	resp, err := c.forward(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !bytes.Contains(resp, []byte(`"mine":true`)) {
		t.Fatalf("forward returned the wrong message as this call's answer: %s", resp)
	}
	if len(relayed) != 2 {
		t.Fatalf("relayed %d messages, want 2 (the progress notification and the id:99 response)", len(relayed))
	}
	for _, r := range relayed {
		if bytes.Contains(r, []byte(`"mine":true`)) {
			t.Fatal("this call's own answer was relayed out-of-band as well as returned")
		}
	}
}

func TestChildConn_ClosedStreamIsAnErrorNotASilentNil(t *testing.T) {
	var in bytes.Buffer
	c := newChildConn(&in, strings.NewReader(""), func([]byte) {})
	resp, err := c.forward(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err == nil {
		t.Fatalf("closed stream returned no error (resp=%s); the caller would read that as a "+
			"notification and answer the agent with nothing", resp)
	}
	if resp != nil {
		t.Fatalf("closed stream returned a response: %s", resp)
	}
	if !strings.Contains(err.Error(), "closed its stream") {
		t.Fatalf("unhelpful diagnosis: %v", err)
	}
}

// ── framing ───────────────────────────────────────────────────────────────

// Two writers share stdout: the main loop and the child connection's
// out-of-band relay. If their writes interleave, the client receives one
// unparseable line and the session dies.
func TestLineWriter_ConcurrentWritesStayFramed(t *testing.T) {
	var buf bytes.Buffer
	lw := newLineWriter(&buf)

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lw.write([]byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"pad":%q}}`,
				i, strings.Repeat("x", 512))))
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d — writes interleaved", len(lines), n)
	}
	seen := map[float64]bool{}
	for _, ln := range lines {
		var m struct {
			ID float64 `json:"id"`
		}
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("line is not valid JSON (writes interleaved): %v", err)
		}
		if seen[m.ID] {
			t.Fatalf("id %v written twice", m.ID)
		}
		seen[m.ID] = true
	}
}

// ── serve ─────────────────────────────────────────────────────────────────

func serveString(t *testing.T, r *rig, in string) string {
	t.Helper()
	var out bytes.Buffer
	lw := newLineWriter(&out)
	if err := serve(strings.NewReader(in), r.mw, lw); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return out.String()
}

func TestServe_UnauthorizedCallIsDeniedAndNeverForwarded(t *testing.T) {
	r := newRig(t)
	got := serveString(t, r, callMsg("", "pay", `{"to":"alice"}`)+"\n")

	if len(r.forwarded) != 0 {
		t.Fatalf("an unauthorized tools/call reached the wrapped server: %s", r.forwarded[0])
	}
	if !strings.Contains(got, "spt-txn: denied") {
		t.Fatalf("no denial on the wire: %q", got)
	}
	if !strings.Contains(got, fmt.Sprintf("%d", mcppep.CodeDenied)) {
		t.Fatalf("denial did not carry the PEP's denied code: %q", got)
	}
}

func TestServe_AuthorizedCallIsForwardedWithTheTokenStripped(t *testing.T) {
	r := newRig(t)
	r.mint(t, "tok-1", "jti-1", "pay", `{"to":"alice"}`)
	got := serveString(t, r, callMsg("tok-1", "pay", `{"to":"alice"}`)+"\n")

	if len(r.forwarded) != 1 {
		t.Fatalf("authorized call was not forwarded (forwarded %d)", len(r.forwarded))
	}
	fwd := string(r.forwarded[0])
	if strings.Contains(fwd, "tok-1") {
		t.Fatalf("the credential reached the wrapped server — token passthrough: %s", fwd)
	}
	if strings.Contains(fwd, mcppep.TokenMetaKey) {
		t.Fatalf("the token meta key survived the strip: %s", fwd)
	}
	if !strings.Contains(fwd, `"to":"alice"`) {
		t.Fatalf("the strip damaged the authorized arguments: %s", fwd)
	}
	if !strings.Contains(got, `"ok":true`) {
		t.Fatalf("the wrapped server's reply did not reach the client: %q", got)
	}
}

// A token minted for one call must not authorize a different one. This is the
// prompt-injection case: the agent presents a real token and mutates the args.
func TestServe_MutatedArgumentsAreDenied(t *testing.T) {
	r := newRig(t)
	r.mint(t, "tok-1", "jti-1", "pay", `{"to":"alice"}`)
	got := serveString(t, r, callMsg("tok-1", "pay", `{"to":"attacker"}`)+"\n")

	if len(r.forwarded) != 0 {
		t.Fatalf("a mutated call reached the wrapped server: %s", r.forwarded[0])
	}
	if !strings.Contains(got, "spt-txn: denied") {
		t.Fatalf("mutated arguments were not denied: %q", got)
	}
}

func TestServe_ReplayOfASpentTokenIsDenied(t *testing.T) {
	r := newRig(t)
	r.mint(t, "tok-1", "jti-1", "pay", `{"to":"alice"}`)
	msg := callMsg("tok-1", "pay", `{"to":"alice"}`)
	got := serveString(t, r, msg+"\n"+msg+"\n")

	if len(r.forwarded) != 1 {
		t.Fatalf("a replayed token was forwarded %d times, want 1", len(r.forwarded))
	}
	if !strings.Contains(got, "spt-txn: denied") {
		t.Fatalf("the replay was not denied: %q", got)
	}
}

func TestServe_NonInvocationTrafficPassesThrough(t *testing.T) {
	r := newRig(t)
	got := serveString(t, r, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if len(r.forwarded) != 1 {
		t.Fatalf("tools/list was not passed through (forwarded %d)", len(r.forwarded))
	}
	if !strings.Contains(got, `"ok":true`) {
		t.Fatalf("passthrough reply did not reach the client: %q", got)
	}
}

func TestServe_BlankLinesAreSkippedNotDenied(t *testing.T) {
	r := newRig(t)
	got := serveString(t, r, "\n   \n")
	if strings.TrimSpace(got) != "" {
		t.Fatalf("blank input produced output: %q", got)
	}
	if len(r.receipts) != 0 {
		t.Fatalf("blank input produced %d receipts", len(r.receipts))
	}
}

// Every decision must leave evidence, including the refusals.
func TestServe_EveryDecisionLeavesAReceipt(t *testing.T) {
	r := newRig(t)
	r.mint(t, "tok-1", "jti-1", "pay", `{"to":"alice"}`)
	serveString(t, r,
		callMsg("", "pay", `{"to":"alice"}`)+"\n"+
			callMsg("tok-1", "pay", `{"to":"alice"}`)+"\n"+
			callMsg("tok-1", "pay", `{"to":"attacker"}`)+"\n")
	if len(r.receipts) != 3 {
		t.Fatalf("3 decisions produced %d receipts", len(r.receipts))
	}
}

// ── denial ────────────────────────────────────────────────────────────────

func TestDenial_IsWellFormedAndUniform(t *testing.T) {
	b := denial(json.RawMessage("7"))
	var m struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("denial is not valid JSON-RPC: %v (%s)", err, b)
	}
	if m.JSONRPC != "2.0" || m.ID != 7 {
		t.Fatalf("denial lost its envelope or id: %s", b)
	}
	if m.Error.Code != mcppep.CodeDenied {
		t.Fatalf("denial code = %d, want %d", m.Error.Code, mcppep.CodeDenied)
	}
	// Uniform on the wire: the failing check belongs in the receipt, not here.
	if m.Error.Message != "spt-txn: denied" {
		t.Fatalf("denial message leaked detail: %q", m.Error.Message)
	}
}

func TestParseHexKey_RejectsWrongLength(t *testing.T) {
	if _, err := parseHexKey(strings.Repeat("ab", 16), ed25519.PublicKeySize); err == nil {
		t.Fatal("a 16-byte key was accepted as a 32-byte public key")
	}
	if _, err := parseHexKey("zz", ed25519.PublicKeySize); err == nil {
		t.Fatal("non-hex input was accepted")
	}
	if _, err := parseHexKey(strings.Repeat("ab", ed25519.PublicKeySize), ed25519.PublicKeySize); err != nil {
		t.Fatalf("a correct key was rejected: %v", err)
	}
}

// ── required configuration ────────────────────────────────────────────────

// Every one of these is a fail-open if it defaults. The test names them
// individually so that deleting one from the required set fails here rather
// than being discovered by a PEP that answers for an audience it was never
// configured with.
func TestMissingRequired_NamesEachFailOpenSetting(t *testing.T) {
	full := func() (string, string, string, string, string, []string) {
		return "srv", "aud", "abcd", "key.hex", "phash", []string{"server"}
	}

	if got := mustCall(full()); len(got) != 0 {
		t.Fatalf("a fully-configured PEP reported missing settings: %v", got)
	}

	cases := []struct {
		name string
		want string
		mut  func(a *args)
	}{
		{"server identity", "-server-identity", func(a *args) { a.serverIdentity = "" }},
		{"audience", "-audience", func(a *args) { a.audience = "" }},
		{"tts public key", "-tts-pub", func(a *args) { a.ttsPub = "" }},
		{"log key file", "-log-key-file", func(a *args) { a.logKeyFile = "" }},
		{"policy hash", "-policy-hash", func(a *args) { a.policyHash = "" }},
		{"wrapped command", "-- <wrapped-server-command>", func(a *args) { a.wrapped = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newArgs(full())
			c.mut(&a)
			got := missingRequired(a.serverIdentity, a.audience, a.ttsPub, a.logKeyFile, a.policyHash, a.wrapped)
			if len(got) != 1 || got[0] != c.want {
				t.Fatalf("missingRequired = %v, want exactly [%s]", got, c.want)
			}
		})
	}
}

type args struct {
	serverIdentity, audience, ttsPub, logKeyFile, policyHash string
	wrapped                                                  []string
}

func newArgs(s, a, tp, lk, ph string, w []string) args {
	return args{serverIdentity: s, audience: a, ttsPub: tp, logKeyFile: lk, policyHash: ph, wrapped: w}
}

func mustCall(s, a, tp, lk, ph string, w []string) []string {
	return missingRequired(s, a, tp, lk, ph, w)
}

// ── a real wrapped subprocess ─────────────────────────────────────────────

// TestWrappedServerHelper is not a test: re-executed with the env var set, it
// acts as a minimal MCP server on stdio so the child-connection path is
// exercised against a real process and real pipes rather than a buffer.
func TestWrappedServerHelper(t *testing.T) {
	if os.Getenv("SPT_MCP_PEP_HELPER") != "1" {
		t.Skip("helper process; not run directly")
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Announce progress before answering, so the caller's out-of-band
		// relay path runs against a real stream too.
		fmt.Println(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"p":1}}`)
		id, isReq := rpcID(line)
		if !isReq {
			continue
		}
		var m struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
				Meta      json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		_ = json.Unmarshal(line, &m)
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"saw_meta":%v,"args":%s}}`+"\n",
			id, len(m.Params.Meta) > 0, orNull(m.Params.Arguments))
	}
	os.Exit(0)
}

func orNull(b json.RawMessage) string {
	if len(b) == 0 {
		return "null"
	}
	return string(b)
}

func TestChildConn_AgainstARealSubprocess(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=TestWrappedServerHelper")
	child.Env = append(os.Environ(), "SPT_MCP_PEP_HELPER=1")
	in, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = nil
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = in.Close()
		_ = child.Wait()
	}()

	var relayed [][]byte
	conn := newChildConn(in, out, func(b []byte) { relayed = append(relayed, append([]byte(nil), b...)) })

	r := newRig(t)
	r.mint(t, "tok-1", "jti-1", "pay", `{"to":"alice"}`)
	mw, err := mcppep.New(mustEngine(t, r), testTarget, conn.forward)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	lw := newLineWriter(&buf)
	input := callMsg("tok-1", "pay", `{"to":"alice"}`) + "\n" +
		callMsg("tok-1", "pay", `{"to":"attacker"}`) + "\n"
	if err := serve(strings.NewReader(input), mw, lw); err != nil {
		t.Fatalf("serve: %v", err)
	}

	got := buf.String()
	// The authorized call reached the real server, and the credential did not.
	if !strings.Contains(got, `"saw_meta":false`) {
		t.Fatalf("the wrapped subprocess saw the credential, or never answered: %q", got)
	}
	if strings.Contains(got, "tok-1") {
		t.Fatalf("the token appears in the client-visible stream: %q", got)
	}
	// The second call, with mutated arguments, was refused before the subprocess.
	if !strings.Contains(got, "spt-txn: denied") {
		t.Fatalf("the mutated call was not denied: %q", got)
	}
	if strings.Contains(got, "attacker") {
		t.Fatalf("the mutated arguments reached the subprocess: %q", got)
	}
	if len(relayed) == 0 {
		t.Fatal("the subprocess's progress notification was dropped instead of relayed")
	}
}

// mustEngine borrows the rig's already-validated decision engine so the
// subprocess test can put a different transport in front of the same core.
func mustEngine(t *testing.T, r *rig) *decision.Engine {
	t.Helper()
	if r.engine == nil {
		t.Fatal("rig has no engine")
	}
	return r.engine
}

// ── startup fails closed ──────────────────────────────────────────────────

func writeKey(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A PEP that starts anyway on bad configuration is a PEP that answers without
// verification or without evidence. Each of these must be a startup failure.
func TestBuildEngine_FailsClosedOnBadConfiguration(t *testing.T) {
	dir := t.TempDir()
	_, logKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	goodLogKey := writeKey(t, dir, "log.key", logKey)
	shortLogKey := writeKey(t, dir, "short.key", logKey[:16])
	ttsPub := strings.Repeat("ab", ed25519.PublicKeySize)

	base := func() pepConfig {
		return pepConfig{
			pepName:    "mcp-pep.test",
			ttsPubHex:  ttsPub,
			logKeyFile: goodLogKey,
			auditPath:  filepath.Join(dir, "audit.jsonl"),
			policyHash: "policy-hash",
			audience:   "aud.test",
			maxTTL:     time.Minute,
		}
	}

	cases := []struct {
		name string
		want string
		mut  func(c *pepConfig)
	}{
		{"tts key is not hex", "tts-pub", func(c *pepConfig) { c.ttsPubHex = "zzzz" }},
		{"tts key is the wrong length", "tts-pub", func(c *pepConfig) { c.ttsPubHex = "abcd" }},
		{"log key file is absent", "log-key-file", func(c *pepConfig) {
			c.logKeyFile = filepath.Join(dir, "nope.key")
		}},
		{"log key is the wrong length", "log key", func(c *pepConfig) { c.logKeyFile = shortLogKey }},
		{"audience is unset", "engine", func(c *pepConfig) { c.audience = "" }},
		{"max token ttl is unset", "engine", func(c *pepConfig) { c.maxTTL = 0 }},
		{"policy hash is unset", "engine", func(c *pepConfig) { c.policyHash = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mut(&cfg)
			eng, closer, err := buildEngine(cfg)
			if err == nil {
				if closer != nil {
					closer()
				}
				t.Fatalf("startup succeeded with %s; engine=%v", c.name, eng != nil)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name the failing setting %q", err, c.want)
			}
			if eng != nil {
				t.Fatal("a failed startup returned an engine anyway")
			}
		})
	}

	t.Run("a correct configuration starts", func(t *testing.T) {
		eng, closer, err := buildEngine(base())
		if err != nil {
			t.Fatalf("a correct configuration failed to start: %v", err)
		}
		if eng == nil {
			t.Fatal("no engine")
		}
		if err := closer(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})
}

// ── the nil-response backstop ─────────────────────────────────────────────

// nilHandler stands in for a middleware that returns no response where the
// contract says it must. The real middleware never does this; the point of the
// backstop is that if a future change ever did, the agent gets a refusal rather
// than a call that appears to hang forever.
type nilHandler struct{ seen int }

func (n *nilHandler) Handle(_ context.Context, _ []byte) []byte { n.seen++; return nil }

func TestServe_ARequestNeverGoesUnanswered(t *testing.T) {
	h := &nilHandler{}
	var buf bytes.Buffer
	lw := newLineWriter(&buf)
	in := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pay"}}` + "\n"
	if err := serve(strings.NewReader(in), h, lw); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if h.seen != 1 {
		t.Fatalf("handler saw %d messages, want 1", h.seen)
	}
	got := buf.String()
	if !strings.Contains(got, "spt-txn: denied") {
		t.Fatalf("a request went unanswered: %q", got)
	}
	if !strings.Contains(got, `"id":4`) {
		t.Fatalf("the backstop answer lost the request id: %q", got)
	}
}

// A notification that produces no response must produce no output either —
// answering one would be a protocol violation.
func TestServe_ANotificationStaysUnanswered(t *testing.T) {
	h := &nilHandler{}
	var buf bytes.Buffer
	lw := newLineWriter(&buf)
	in := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	if err := serve(strings.NewReader(in), h, lw); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Fatalf("a notification was answered: %q", buf.String())
	}
}
