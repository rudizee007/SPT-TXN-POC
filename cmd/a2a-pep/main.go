// Command a2a-pep is the SPT-Txn A2A policy-enforcement point as a runnable
// HTTP proxy -- the A2A form factor of the gateway profiles in
// docs/spec/GATEWAY-PROFILES.md, and the sibling of cmd/mcp-pep.
//
// It sits in front of an Agent2Agent agent. Every message/send must present a
// transaction-scoped SPT-Txn token in params.message.metadata["spt-txn/token"]
// whose intent binding matches the message being delivered: its parts, its
// taskId and its contextId. A prompt-injected or hijacked send -- different
// content, redirected task, a token minted for another agent -- is denied
// before the wrapped agent sees it, and a signed receipt is written for every
// decision, permit or deny.
//
// # What this process holds
//
// No signing keys for authorization, and no custody of anything it authorizes.
// One PUBLIC key (the TTS issuer's, to verify presented tokens) and one log key
// (to sign receipts, which is evidence, not authority). It cannot mint a token,
// it cannot move value, and it is not in the settlement path.
//
// # Two transport-level properties that the middleware cannot provide
//
// internal/a2apep strips the credential out of the JSON-RPC body. That is not
// sufficient at this layer, and both gaps are closed here:
//
//   - No client header is copied upstream. Stripping the token from the body
//     and then forwarding the caller's Authorization or Cookie would hand the
//     wrapped agent a different credential for the same caller: the same
//     confused-deputy hole, one layer down (docs/THREAT-MODEL.md 4.6).
//
//   - The relayed agent card is rewritten to advertise this PEP. An agent card
//     names the endpoint clients should talk to. Relaying the wrapped agent's
//     card unmodified would publish the address of the agent BEHIND the
//     enforcement point, so the first thing any compliant client does with the
//     card is take the bypass. Card relay is therefore OFF unless -public-url
//     says what to advertise instead.
//
// # Why this binary exists
//
// internal/a2apep was an enforcement point with no way to run it. This wires it
// to a real HTTP transport without adding trust-boundary code: every
// authorization check still happens in decision.Engine and internal/a2apep.
//
//	a2a-pep -listen :8402 \
//	        -upstream http://127.0.0.1:9000/ \
//	        -public-url https://guarded.example/ \
//	        -agent-identity a2a://payments.example \
//	        -audience payments.example \
//	        -tts-pub <hex> -log-key-file log.key -policy-hash <hash>
//
// # Known duplication
//
// buildEngine, missingRequired and parseHexKey are near-copies of cmd/mcp-pep's.
// They belong in one package and will move there. They have not moved yet
// because scripts/mutate-mcp-pep-transport.sh anchors two mutations (M-I, M-J)
// on those exact lines in cmd/mcp-pep/main.go, and relocating them silently
// would leave that script reporting "killed" for mutations it no longer applies
// to the code that runs. The extraction is a change to BOTH binaries and their
// mutation scripts together, not a tidy-up to slip in beside a new feature.
package main

import (
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
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/a2apep"
	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
)

// maxMessageBytes bounds a single JSON-RPC body in either direction. An
// unbounded read on a socket an adversary can write to is a memory-exhaustion
// primitive; A2A messages carrying inline file parts are large but not this
// large.
const maxMessageBytes = 4 << 20

// defaultCardPath is where RFC 8615 says an agent card lives.
const defaultCardPath = "/.well-known/agent-card.json"

func main() {
	pepName := flag.String("pep", "a2a-pep.spt-txn", "PEP identity (trust registry name)")
	listen := flag.String("listen", ":8402", "address to listen on")
	upstream := flag.String("upstream", "",
		"JSON-RPC endpoint of the wrapped A2A agent, e.g. http://127.0.0.1:9000/ (required)")
	publicURL := flag.String("public-url", "",
		"the URL clients reach THIS PEP on. Required to relay the wrapped agent's card: "+
			"the relayed card is rewritten to advertise this address, because a card that "+
			"still names the agent behind the PEP is a published bypass.")
	agentIdentity := flag.String("agent-identity", "",
		"identity of the wrapped agent -- the intent `target`. A token minted for another "+
			"agent MUST NOT verify here (required).")
	rpcPath := flag.String("rpc-path", "/", "the single path that accepts JSON-RPC")
	cardPath := flag.String("card-path", defaultCardPath, "path the agent card is served on")
	ttsPubHex := flag.String("tts-pub", "", "hex Ed25519 public key of the tts_issuer (required)")
	logKeyFile := flag.String("log-key-file", "", "file with hex Ed25519 log signing key (required)")
	auditPath := flag.String("audit-log", "a2a-pep-audit.jsonl", "transparency log path")
	policyHash := flag.String("policy-hash", "", "hash of the policy bundle version (required)")
	jurisdiction := flag.String("jurisdiction", "", "jurisdiction profile identifier")
	audience := flag.String("audience", "",
		"executing-domain identity this PEP answers for, matched against the token's aud "+
			"(required). Distinct from -pep (a registry identity) and -agent-identity (a "+
			"resource): this is the domain the token was minted FOR.")
	maxTTL := flag.Duration("max-token-ttl", 60*time.Second,
		"longest remaining token lifetime this PEP accepts. An A2A PEP does not walk the "+
			"chain, so this IS the revocation latency (GATEWAY-PROFILES.md 1.1).")
	upstreamTimeout := flag.Duration("upstream-timeout", 30*time.Second,
		"how long to wait for the wrapped agent to answer")
	flag.Parse()

	if missing := missingRequired(*upstream, *agentIdentity, *audience, *ttsPubHex,
		*logKeyFile, *policyHash); len(missing) > 0 {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\nnot set: %s\n", strings.Join(missing, ", "))
		fmt.Fprintln(os.Stderr, "Each of these must be set explicitly. This PEP has no mode that "+
			"skips verification, and no default that would let it answer for any audience: an "+
			"empty expected audience matches a token that omits aud, so a PEP configured by "+
			"omission would accept tokens minted for any domain.")
		os.Exit(2)
	}

	upURL, err := validateAbsoluteURL(*upstream)
	if err != nil {
		log.Fatalf("upstream: %v", err)
	}
	if *publicURL != "" {
		if _, err := validateAbsoluteURL(*publicURL); err != nil {
			log.Fatalf("public-url: %v", err)
		}
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

	p := &proxy{
		rpcPath:   *rpcPath,
		cardPath:  *cardPath,
		publicURL: *publicURL,
		upstream:  upURL.String(),
		cardURL:   upURL.Scheme + "://" + upURL.Host + *cardPath,
		client:    newUpstreamClient(*upstreamTimeout),
	}

	mw, err := a2apep.New(engine, *agentIdentity, p.forward)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}
	p.mw = mw

	srv := &http.Server{
		Addr:              *listen,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 16,
	}

	fmt.Fprintf(os.Stderr, "spt-txn a2a-pep ready on %s -- guarding %s as %q, audience %q\n",
		*listen, upURL.Redacted(), *agentIdentity, *audience)
	if *publicURL == "" {
		fmt.Fprintf(os.Stderr, "agent card relay is OFF (no -public-url): %s returns 404 rather "+
			"than handing clients the address of the agent behind this PEP\n", *cardPath)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// handler is the enforcement surface the transport drives. It is an interface
// rather than the concrete *a2apep.Middleware for one reason: the nil-response
// branch below is unreachable through the real middleware, and a branch that
// cannot be reached in a test is a branch that cannot be shown to work.
type handler interface {
	Handle(ctx context.Context, raw []byte) []byte
}

// proxy is the HTTP transport.
type proxy struct {
	mw        handler
	rpcPath   string
	cardPath  string
	publicURL string // "" disables card relay
	upstream  string
	cardURL   string
	client    *http.Client
}

// ServeHTTP routes exactly two requests and refuses everything else.
//
// An enforcement point that proxies whatever it is given is a general-purpose
// proxy with an authorization check bolted to one of its paths. Only POST on
// the JSON-RPC path and GET on the card path exist here; there is no default
// branch that forwards.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == p.rpcPath:
		p.serveRPC(w, r)
	case r.Method == http.MethodGet && r.URL.Path == p.cardPath:
		p.serveCard(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveRPC runs one JSON-RPC message through the enforcement point.
//
// A denial is HTTP 200 carrying a JSON-RPC error, not an HTTP 4xx. The refusal
// is uniform on purpose (internal/a2apep returns one message for every failing
// check), and answering with a distinguishable status code would put back the
// oracle the uniform body exists to remove.
func (p *proxy) serveRPC(w http.ResponseWriter, r *http.Request) {
	if !isJSON(r.Header.Get("Content-Type")) {
		http.Error(w, "expected Content-Type: application/json", http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageBytes))
	if err != nil {
		http.Error(w, "unreadable or oversize request body", http.StatusBadRequest)
		return
	}

	resp := p.mw.Handle(r.Context(), raw)
	if resp == nil {
		// Handle's contract is that a request always produces a response and
		// only notifications produce none. This is belt-and-braces on that
		// contract rather than a check the PEP relies on: if a future change
		// ever returned nil for a request, an empty 204 would look to the
		// caller like success rather than a refusal.
		id, isRequest := rpcID(raw)
		if !isRequest {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		resp = denial(id)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// forward delivers a token-stripped request to the wrapped agent.
func (p *proxy) forward(ctx context.Context, raw []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	// Only headers this PEP sets. The caller's headers are deliberately NOT
	// copied: the middleware strips the SPT-Txn credential out of the body, and
	// forwarding the caller's Authorization or Cookie would hand the wrapped
	// agent a different credential for the same caller.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if isEventStream(resp.Header.Get("Content-Type")) {
		return nil, errors.New("a2a-pep: the wrapped agent answered with a stream. This PEP " +
			"authorizes discrete message/send calls; relaying a stream would return content " +
			"the enforcement point never saw")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("a2a-pep: wrapped agent returned %s", resp.Status)
	}
	return body, nil
}

// serveCard relays the wrapped agent's card, rewritten to advertise this PEP.
func (p *proxy) serveCard(w http.ResponseWriter, r *http.Request) {
	if p.publicURL == "" {
		http.Error(w, "agent card relay is disabled: start a2a-pep with -public-url so the "+
			"relayed card advertises this PEP rather than the agent behind it",
			http.StatusNotFound)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.cardURL, nil)
	if err != nil {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessageBytes))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		http.Error(w, "upstream agent card unavailable", http.StatusBadGateway)
		return
	}
	rewritten, dropped, err := rewriteCard(body, p.publicURL)
	if err != nil {
		http.Error(w, "upstream agent card is not a JSON object", http.StatusBadGateway)
		return
	}
	if dropped > 0 {
		// Every relay, not once: a persistent misconfiguration deserves a
		// persistent complaint, and a discovery endpoint is not a hot path.
		log.Printf("agent card: dropped %d additionalInterfaces entry/entries. Clients "+
			"can no longer discover those transports through this PEP, which does not "+
			"enforce them. If they must stay reachable, put a PEP in front of them; "+
			"do not re-advertise a route this one cannot guard.", dropped)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(rewritten)
}

// rewriteCard makes the relayed agent card point at the PEP.
//
// This is not cosmetic. An agent card names the endpoint clients should talk
// to, so relaying the wrapped agent's card unmodified publishes the address of
// the agent BEHIND the enforcement point and the first thing any compliant
// client does with it is take the bypass.
//
// `additionalInterfaces` is dropped entirely rather than rewritten. Every entry
// is a second address on a transport this PEP does not enforce at all -- a gRPC
// interface cannot be pointed at a JSON-RPC proxy, and keeping it would
// advertise a bypass that happens to look authorized. An operator who needs
// those transports guarded needs a PEP for those transports, not a card that
// implies one exists.
//
// It returns how many entries it dropped, because dropping them silently is
// the same defect facing the other way: a multi-transport agent degraded to
// JSON-RPC only leaves its other clients unable to discover an endpoint with
// nothing anywhere saying why. The caller tells the operator.
//
// An additionalInterfaces that is present but is not an array is refused
// rather than deleted. The count is the whole point; a value that cannot be
// counted cannot be reported, and dropping it uncounted is the behaviour this
// return value exists to end.
func rewriteCard(card []byte, publicURL string) ([]byte, int, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(card, &obj); err != nil {
		return nil, 0, err
	}
	if obj == nil {
		return nil, 0, errors.New("a2a-pep: agent card is null")
	}
	enc, err := json.Marshal(publicURL)
	if err != nil {
		return nil, 0, err
	}
	dropped := 0
	if raw, ok := obj["additionalInterfaces"]; ok {
		var alts []json.RawMessage
		if err := json.Unmarshal(raw, &alts); err != nil {
			return nil, 0, fmt.Errorf("a2a-pep: agent card additionalInterfaces is present but is not an array: %w", err)
		}
		dropped = len(alts)
	}
	obj["url"] = enc
	obj["preferredTransport"] = json.RawMessage(`"JSONRPC"`)
	delete(obj, "additionalInterfaces")
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, err
	}
	return out, dropped, nil
}

// newUpstreamClient builds the client used for both the agent and its card.
//
// Redirects are refused rather than followed. A proxy that follows a redirect
// can be pointed at a host the operator never configured, which would send a
// request the PEP has just authorized for one agent to a different one.
func newUpstreamClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("a2a-pep: the wrapped agent redirected. Following it would send " +
				"an authorized request to a host the operator never configured")
		},
	}
}

// isJSON reports whether ct is exactly the JSON media type, parameters aside.
func isJSON(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// isEventStream reports whether ct announces Server-Sent Events.
func isEventStream(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "text/event-stream"
}

// validateAbsoluteURL rejects anything that is not an absolute http(s) endpoint.
//
// It guards BOTH -upstream and -public-url. -public-url was previously taken on
// trust and marshalled straight into the relayed card, which made the weakest
// link the one value whose entire purpose is to be an address clients dial: a
// typo published a broken endpoint to every client that fetched the card. The
// whole argument for requiring the operator to state it (rather than
// reconstructing it from forwarded headers) is that a stated value is
// trustworthy. That only holds if it is checked.
func validateAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("want an http or https URL, got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", raw)
	}
	return u, nil
}

// rpcID extracts a usable JSON-RPC id, reporting whether this was a request
// (as opposed to a notification, which is answered with nothing).
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

// denial is the same uniform refusal internal/a2apep puts on the wire: the
// failing check stays in the receipt, not in the error the caller reads.
func denial(id json.RawMessage) []byte {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": a2apep.CodeDenied, "message": "spt-txn: denied"},
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
// key file or an unopenable audit log must stop the process rather than produce
// a PEP that answers anyway. It returns a closer for the audit log.
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
// nothing to verify against, and an absent upstream means there is nothing
// being guarded. Returning the list rather than a bool exists so the operator is
// told which, instead of re-reading the whole usage block.
//
// -public-url is NOT here. Its absence disables agent-card relay, which is a
// refusal, not a fail-open; requiring it would force every operator who does
// not want the card relayed to invent a value for it.
func missingRequired(upstream, agentIdentity, audience, ttsPub, logKeyFile, policyHash string) []string {
	var missing []string
	for _, f := range []struct {
		name  string
		value string
	}{
		{"-upstream", upstream},
		{"-agent-identity", agentIdentity},
		{"-audience", audience},
		{"-tts-pub", ttsPub},
		{"-log-key-file", logKeyFile},
		{"-policy-hash", policyHash},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
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
