package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubHandler stands in for the enforcement point. Transport tests are about
// what reaches the wrapped agent and what comes back, so the authorization
// decision is stubbed and internal/a2apep carries its own coverage.
type stubHandler struct {
	seen  [][]byte
	reply []byte
	fn    func(ctx context.Context, raw []byte) []byte
}

func (s *stubHandler) Handle(ctx context.Context, raw []byte) []byte {
	s.seen = append(s.seen, append([]byte(nil), raw...))
	if s.fn != nil {
		return s.fn(ctx, raw)
	}
	return s.reply
}

func newProxy(h handler, upstream, publicURL string) *proxy {
	return &proxy{
		mw:        h,
		rpcPath:   "/",
		cardPath:  defaultCardPath,
		publicURL: publicURL,
		upstream:  upstream,
		cardURL:   upstream + defaultCardPath,
		client:    newUpstreamClient(5 * time.Second),
	}
}

func jsonPost(target string, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// ── routing ───────────────────────────────────────────────────────────────

// An enforcement point that proxies whatever it is given is a general-purpose
// proxy with an authorization check bolted to one of its paths. Only two
// requests exist; everything else is a 404 that never reaches the handler.
func TestRoute_EverythingButTheTwoKnownRequestsIs404(t *testing.T) {
	h := &stubHandler{reply: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")

	for _, c := range []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodPut, "/"},
		{http.MethodDelete, "/"},
		{http.MethodPost, "/somewhere-else"},
		{http.MethodPost, "/a2a/v1"},
		{http.MethodPost, defaultCardPath},
		{http.MethodGet, "/anything"},
	} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(c.method, c.target, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.target, w.Code)
		}
	}
	if len(h.seen) != 0 {
		t.Fatalf("a refused route still reached the enforcement point (%d times)", len(h.seen))
	}
}

func TestServeRPC_RefusesANonJSONContentType(t *testing.T) {
	h := &stubHandler{reply: []byte(`{}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")

	for _, ct := range []string{"", "text/plain", "application/xml", "application/json-patch+json"} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0"}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q = %d, want 415", ct, w.Code)
		}
	}
	if len(h.seen) != 0 {
		t.Fatal("a body with the wrong media type reached the enforcement point")
	}
}

func TestServeRPC_AcceptsJSONWithParameters(t *testing.T) {
	h := &stubHandler{reply: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(h.seen) != 1 {
		t.Fatal("a well-formed request did not reach the enforcement point")
	}
}

// An unbounded read on a socket an adversary can write to is a memory
// exhaustion primitive, so the cap has to be refused BEFORE the enforcement
// point is asked to parse it.
func TestServeRPC_RefusesAnOversizeBody(t *testing.T) {
	h := &stubHandler{reply: []byte(`{}`)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	big := `{"jsonrpc":"2.0","id":1,"pad":"` + strings.Repeat("a", maxMessageBytes) + `"}`
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", big))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if len(h.seen) != 0 {
		t.Fatal("an oversize body reached the enforcement point")
	}
}

func TestServeRPC_ReturnsTheEnforcementPointsAnswerVerbatim(t *testing.T) {
	want := `{"jsonrpc":"2.0","id":1,"result":{"kind":"message"}}`
	h := &stubHandler{reply: []byte(want)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// A denial is HTTP 200 carrying a JSON-RPC error, not a 4xx. The refusal is
// uniform on purpose; a distinguishable status code would put back the oracle
// the uniform body exists to remove.
func TestServeRPC_ADenialIsA200NotAnHTTPError(t *testing.T) {
	denied := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"spt-txn: denied"}}`
	h := &stubHandler{reply: []byte(denied)}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("a denial answered with HTTP %d; the status code now distinguishes "+
			"a refusal from an answer", w.Code)
	}
	if w.Body.String() != denied {
		t.Fatalf("body = %s", w.Body.String())
	}
}

// ── the nil-response backstop ─────────────────────────────────────────────

type nilHandler struct{ seen int }

func (n *nilHandler) Handle(_ context.Context, _ []byte) []byte { n.seen++; return nil }

// The real middleware always answers a request. If a future change ever did
// not, an empty 204 would look to the caller like success rather than refusal.
func TestServeRPC_ARequestNeverGoesUnanswered(t *testing.T) {
	h := &nilHandler{}
	p := newProxy(h, "http://127.0.0.1:1", "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":7,"method":"message/send"}`))
	if h.seen != 1 {
		t.Fatal("the enforcement point was not consulted")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var e struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("unparseable backstop answer %s", w.Body.String())
	}
	if e.Error == nil || e.Error.Message != "spt-txn: denied" {
		t.Fatalf("backstop is not the uniform denial: %s", w.Body.String())
	}
	if string(e.ID) != "7" {
		t.Fatalf("backstop answered id %s, want 7", e.ID)
	}
}

// A refused notification has nothing to answer, and inventing an id would be
// a protocol violation.
func TestServeRPC_ANotificationStaysUnanswered(t *testing.T) {
	h := &nilHandler{}
	p := newProxy(h, "http://127.0.0.1:1", "")
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"message/send"}`,
		`{"jsonrpc":"2.0","id":null,"method":"message/send"}`,
	} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, jsonPost("/", body))
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s = %d, want 204", body, w.Code)
		}
		if w.Body.Len() != 0 {
			t.Fatalf("%s answered with a body: %s", body, w.Body.String())
		}
	}
}

// ── forwarding ────────────────────────────────────────────────────────────

// upstreamSpy records what the wrapped agent actually received.
type upstreamSpy struct {
	srv *httptest.Server

	// The upstream handler runs on the server's goroutine and the assertions
	// run on the test's, so the record is guarded. An unguarded counter here
	// is a data race the test would report as a flake.
	mu      sync.Mutex
	hits    int
	headers []http.Header
	bodies  []string
}

func newUpstreamSpy(t *testing.T, reply string) *upstreamSpy {
	t.Helper()
	s := &upstreamSpy{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hits++
		s.headers = append(s.headers, r.Header.Clone())
		s.bodies = append(s.bodies, string(b))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// record returns a snapshot of what the wrapped agent received.
func (s *upstreamSpy) record() (int, []http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, append([]http.Header(nil), s.headers...)
}

// The middleware strips the SPT-Txn credential out of the body. Forwarding the
// caller's Authorization or Cookie would hand the wrapped agent a different
// credential for the same caller: the same confused-deputy hole, one layer
// down. No client header is copied, so there is nothing to get wrong later.
func TestForward_NoClientHeaderReachesTheWrappedAgent(t *testing.T) {
	up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	var p *proxy
	h := &stubHandler{fn: func(ctx context.Context, raw []byte) []byte {
		out, err := p.forward(ctx, raw)
		if err != nil {
			t.Errorf("forward: %v", err)
			return []byte(`{}`)
		}
		return out
	}}
	p = newProxy(h, up.srv.URL, "")

	r := jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`)
	r.Header.Set("Authorization", "Bearer caller-secret")
	r.Header.Set("Cookie", "session=caller-secret")
	r.Header.Set("X-Api-Key", "caller-secret")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	hits, headers := up.record()
	if hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	got := headers[0]
	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if v := got.Get(name); v != "" {
			t.Errorf("CONFUSED DEPUTY: %s reached the wrapped agent as %q", name, v)
		}
	}
	for name, vals := range got {
		if strings.Contains(strings.Join(vals, " "), "caller-secret") {
			t.Errorf("caller credential leaked through header %s: %v", name, vals)
		}
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
}

func TestForward_ADeniedCallNeverReachesTheWrappedAgent(t *testing.T) {
	up := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	h := &stubHandler{reply: []byte(
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"spt-txn: denied"}}`)}
	p := newProxy(h, up.srv.URL, "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, jsonPost("/", `{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if hits, _ := up.record(); hits != 0 {
		t.Fatalf("a denied call reached the wrapped agent %d time(s)", hits)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// Relaying a stream would return content the enforcement point never saw.
func TestForward_RefusesAStreamedAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("a streamed answer was relayed")
	} else if !strings.Contains(err.Error(), "stream") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// A proxy that follows a redirect can be pointed at a host the operator never
// configured, which would send an authorized request to a different agent.
func TestForward_RefusesARedirect(t *testing.T) {
	elsewhere := newUpstreamSpy(t, `{"jsonrpc":"2.0","id":1,"result":{"stolen":true}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("the redirect was followed")
	}
	if hits, _ := elsewhere.record(); hits != 0 {
		t.Fatalf("an authorized request was delivered to the redirect target %d time(s)",
			hits)
	}
}

func TestForward_RefusesANon2xxAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"oops":true}`))
	}))
	defer srv.Close()
	p := newProxy(&stubHandler{}, srv.URL, "")
	if _, err := p.forward(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("a 500 from the wrapped agent was treated as an answer")
	}
}

// ── the agent card ────────────────────────────────────────────────────────

const upstreamCard = `{"protocolVersion":"0.3.0","name":"payments",` +
	`"url":"http://internal-agent.invalid:9000/a2a/v1","preferredTransport":"JSONRPC",` +
	`"additionalInterfaces":[{"url":"http://internal-agent.invalid:9000/a2a/grpc","transport":"GRPC"}],` +
	`"version":"1.0.0"}`

func newCardServer(t *testing.T, card string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultCardPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(card))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Relaying the wrapped agent's card unmodified publishes the address of the
// agent BEHIND the enforcement point. Without somewhere to point clients
// instead, the honest answer is to serve no card at all.
func TestCard_RelayIsOffWithoutAPublicURL(t *testing.T) {
	srv := newCardServer(t, upstreamCard, http.StatusOK)
	p := newProxy(&stubHandler{}, srv.URL, "")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "internal-agent.invalid") {
		t.Fatal("the refusal leaked the wrapped agent's address")
	}
}

func TestCard_RelayAdvertisesThePEPAndDropsAlternateInterfaces(t *testing.T) {
	srv := newCardServer(t, upstreamCard, http.StatusOK)
	const public = "https://guarded.example/"
	p := newProxy(&stubHandler{}, srv.URL, public)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "internal-agent.invalid") {
		t.Fatalf("BYPASS PUBLISHED: the relayed card still names the agent behind the "+
			"PEP: %s", body)
	}
	var card map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil {
		t.Fatalf("relayed card is not JSON: %v", err)
	}
	if card["url"] != public {
		t.Fatalf("url = %v, want %s", card["url"], public)
	}
	if _, ok := card["additionalInterfaces"]; ok {
		t.Fatal("additionalInterfaces survived: every entry is a second address on a " +
			"transport this PEP does not enforce")
	}
	if card["name"] != "payments" || card["version"] != "1.0.0" {
		t.Fatalf("the rest of the card did not survive: %s", body)
	}
	if card["protocolVersion"] != "0.3.0" {
		t.Fatalf("protocolVersion was lost: %s", body)
	}
}

func TestCard_UpstreamFailureIsABadGateway(t *testing.T) {
	srv := newCardServer(t, `{"url":"x"}`, http.StatusInternalServerError)
	p := newProxy(&stubHandler{}, srv.URL, "https://guarded.example/")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, defaultCardPath, nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
}

func TestRewriteCard_RejectsWhatIsNotAnObject(t *testing.T) {
	for _, bad := range []string{`[]`, `"a string"`, `null`, `not json`, ``} {
		if _, _, err := rewriteCard([]byte(bad), "https://guarded.example/"); err == nil {
			t.Errorf("rewriteCard accepted %q", bad)
		}
	}
}

// Dropping alternate interfaces silently degrades a multi-transport agent to
// JSON-RPC only, and the clients that stop discovering those transports have no
// way to learn why. The count is what lets the operator be told.
func TestRewriteCard_ReportsHowManyInterfacesItDropped(t *testing.T) {
	if _, n, err := rewriteCard([]byte(upstreamCard), "https://guarded.example/"); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("dropped = %d, want 1", n)
	}
	none := `{"name":"x","url":"http://a.invalid/"}`
	if _, n, err := rewriteCard([]byte(none), "https://guarded.example/"); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("dropped = %d on a card with no alternates, want 0", n)
	}
}

// -public-url is marshalled straight into the relayed card, so it is an address
// clients dial. It was previously taken on trust while -upstream was checked,
// which put the weakest validation on the value with the widest blast radius.
func TestPublicURLIsHeldToTheSameStandardAsUpstream(t *testing.T) {
	for _, bad := range []string{"banana", " ", "/relative/path", "ftp://x.invalid/", "http://"} {
		if u, err := validateAbsoluteURL(bad); err == nil {
			t.Errorf("a card would have advertised %q (parsed as %v)", bad, u)
		}
	}
}

// ── configuration ─────────────────────────────────────────────────────────

func TestValidateAbsoluteURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:9000/", "https://agent.example/a2a/v1"} {
		if _, err := validateAbsoluteURL(ok); err != nil {
			t.Errorf("validateAbsoluteURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/just/a/path", "agent.example:9000",
		"file:///etc/passwd", "ftp://agent.example/", "http://"} {
		if u, err := validateAbsoluteURL(bad); err == nil {
			t.Errorf("validateAbsoluteURL(%q) accepted it as %v", bad, u)
		}
	}
}

type args struct {
	upstream, agentIdentity, audience, ttsPub, logKeyFile, policyHash string
}

func TestMissingRequired_NamesEachFailOpenSetting(t *testing.T) {
	full := func() args {
		return args{upstream: "http://127.0.0.1:9000/", agentIdentity: "a2a://agent",
			audience: "aud", ttsPub: "abcd", logKeyFile: "key.hex", policyHash: "phash"}
	}
	a := full()
	if got := missingRequired(a.upstream, a.agentIdentity, a.audience, a.ttsPub,
		a.logKeyFile, a.policyHash); len(got) != 0 {
		t.Fatalf("a fully-configured PEP reported missing settings: %v", got)
	}

	cases := []struct {
		name string
		want string
		mut  func(a *args)
	}{
		{"upstream", "-upstream", func(a *args) { a.upstream = "" }},
		{"agent identity", "-agent-identity", func(a *args) { a.agentIdentity = "" }},
		{"audience", "-audience", func(a *args) { a.audience = "" }},
		{"tts public key", "-tts-pub", func(a *args) { a.ttsPub = "" }},
		{"log key file", "-log-key-file", func(a *args) { a.logKeyFile = "" }},
		{"policy hash", "-policy-hash", func(a *args) { a.policyHash = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := full()
			c.mut(&a)
			got := missingRequired(a.upstream, a.agentIdentity, a.audience, a.ttsPub,
				a.logKeyFile, a.policyHash)
			if len(got) != 1 || got[0] != c.want {
				t.Fatalf("missingRequired = %v, want exactly [%s]", got, c.want)
			}
		})
	}
}

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
			pepName:    "a2a-pep.test",
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

func TestParseHexKey_RejectsWrongLength(t *testing.T) {
	if _, err := parseHexKey("abcd", ed25519.PublicKeySize); err == nil {
		t.Fatal("a short key was accepted")
	}
	if _, err := parseHexKey("zz", ed25519.PublicKeySize); err == nil {
		t.Fatal("a non-hex key was accepted")
	}
	if _, err := parseHexKey(strings.Repeat("ab", ed25519.PublicKeySize),
		ed25519.PublicKeySize); err != nil {
		t.Fatalf("a correct key was rejected: %v", err)
	}
}

func TestRPCID(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want string
		is   bool
	}{
		{`{"jsonrpc":"2.0","id":7,"method":"m"}`, "7", true},
		{`{"jsonrpc":"2.0","id":"abc","method":"m"}`, `"abc"`, true},
		{`{"jsonrpc":"2.0","method":"m"}`, "", false},
		{`{"jsonrpc":"2.0","id":null,"method":"m"}`, "", false},
		{`not json`, "", false},
	} {
		id, is := rpcID([]byte(c.raw))
		if is != c.is {
			t.Errorf("%s: isRequest = %v, want %v", c.raw, is, c.is)
			continue
		}
		if is && string(id) != c.want {
			t.Errorf("%s: id = %s, want %s", c.raw, id, c.want)
		}
	}
}

func TestDenial_IsWellFormedAndUniform(t *testing.T) {
	var got struct {
		Jsonrpc string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(denial(json.RawMessage("7")), &got); err != nil {
		t.Fatal(err)
	}
	if got.Jsonrpc != "2.0" || got.ID != 7 {
		t.Fatalf("malformed denial: %+v", got)
	}
	if got.Error.Code != -32001 {
		t.Fatalf("code = %d, want the PEP's denied code", got.Error.Code)
	}
	if got.Error.Message != "spt-txn: denied" {
		t.Fatalf("message = %q; a denial must not name the failing check", got.Error.Message)
	}
}
