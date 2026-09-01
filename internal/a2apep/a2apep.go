// Package a2apep is the SPT-Txn A2A Policy Enforcement Point: JSON-RPC
// middleware that wraps an Agent2Agent endpoint so that every message/send
// requires a valid transaction-scoped token whose intent binding matches the
// message being delivered.
//
// It is the sibling of internal/mcppep and shares its decision core
// (internal/decision) unchanged. That is the point: the authorization layer is
// orthogonal to the transport. MCP carries tool calls, A2A carries agent-to-
// agent messages, x402 carries payments; the question "was this actor allowed
// to do exactly this" is the same question in all three, and is answered in one
// place.
//
// Wire binding (A2A specification v0.3.0):
//
//	method  message/send
//	params  MessageSendParams { message: Message, ... }
//	Message { role, parts, messageId, taskId, contextId, metadata }
//	metadata is "{ [key: string]: any }" for extension data, namespaced by an
//	extension-specific identifier.
//
// The token therefore travels in params.message.metadata["spt-txn/token"], the
// direct analogue of MCP's params._meta["spt-txn/token"], and is STRIPPED
// before the message is forwarded. The wrapped agent never sees the credential
// (docs/THREAT-MODEL.md §4.6, confused-deputy discipline).
package a2apep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
)

// TokenMetaKey is the message.metadata key carrying the SPT-Txn token.
const TokenMetaKey = "spt-txn/token"

// SendMethod is the only A2A method this PEP authorizes.
const SendMethod = "message/send"

// JSON-RPC error codes emitted by the PEP. Same numbering as mcppep so an
// operator reading two PEPs' logs is not learning two dialects.
const (
	CodeParse    = -32700
	CodeDenied   = -32001
	CodeUpstream = -32002
)

// Forward delivers a (token-stripped) request to the wrapped agent.
type Forward func(ctx context.Context, raw []byte) ([]byte, error)

// Middleware enforces SPT-Txn on an A2A message stream. Stateless apart from
// the decision engine it delegates to; holds no keys.
type Middleware struct {
	// Engine is the shared decision core. Required.
	Engine *decision.Engine
	// AgentIdentity is this PEP's identity for the wrapped agent — the intent
	// `target`. A token minted for another agent MUST NOT verify here.
	AgentIdentity string
	// Forward delivers to the wrapped agent. Required.
	Forward Forward
}

// New validates the middleware wiring.
func New(engine *decision.Engine, agentIdentity string, forward Forward) (*Middleware, error) {
	if engine == nil {
		return nil, errors.New("a2apep: decision engine required")
	}
	if agentIdentity == "" {
		return nil, errors.New("a2apep: agent identity required")
	}
	if forward == nil {
		return nil, errors.New("a2apep: forward required")
	}
	return &Middleware{Engine: engine, AgentIdentity: agentIdentity, Forward: forward}, nil
}

type rpcRequest struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// message is the subset of A2A Message this PEP inspects. Everything it does
// not inspect stays raw.
type message struct {
	Role      string                     `json:"role"`
	Kind      string                     `json:"kind"`
	Parts     json.RawMessage            `json:"parts"`
	MessageID string                     `json:"messageId"`
	TaskID    string                     `json:"taskId"`
	ContextID string                     `json:"contextId"`
	Metadata  map[string]json.RawMessage `json:"metadata"`
}

// bound is the message subobject the intent digest covers. Marshalled with
// json.Marshal, whose field order is the struct order, then canonicalised by
// internal/jcs inside intent.Digest.
//
// WHAT IS BOUND, and why each choice:
//
//   - parts     — the content the agent acts on. Byte-exact, as MCP binds
//     `arguments`. This is the whole point.
//   - taskId    — WHERE the message lands. Without it a token authorizing a
//     message into one task would authorize the same content into another.
//   - contextId — same argument one level up.
//
// WHAT IS NOT BOUND, deliberately:
//
//   - messageId — generated per send by the client. The minter cannot predict
//     it, so binding it would make every token unusable. Replay of a whole
//     message is handled by the decision engine's jti replay window, not here.
//   - role      — a client sending a message is always "user"; binding a
//     constant asserts nothing, so Handle PINS it instead: any other value is
//     refused (rpc.role-not-user).
//   - metadata  — carries the credential itself, and is stripped before
//     forwarding. A field cannot both be the key and be locked by it. Any
//     OTHER member of metadata is refused (rpc.metadata-uncovered): it is
//     extension payload the digest does not cover.
type bound struct {
	Parts     json.RawMessage `json:"parts"`
	TaskID    string          `json:"taskId,omitempty"`
	ContextID string          `json:"contextId,omitempty"`

	// HistoryLength comes from params.configuration, NOT from the message. It
	// is here because it is a disclosure control -- it governs how much prior
	// conversation comes back -- and letting the caller choose it unbound is
	// letting the caller choose how much history to extract. Tier 2 of
	// docs/spec/DELEGATION-INTENT-A2A.md 4.1.
	//
	// A pointer so that "absent" and "zero" are different bindings, and so a
	// request that omits configuration produces the same digest it always did.
	HistoryLength *int `json:"historyLength,omitempty"`
}

// Handle processes one raw JSON-RPC message. Every branch that does not
// forward is a deny with a receipt.
func (m *Middleware) Handle(ctx context.Context, raw []byte) []byte {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.Jsonrpc != "2.0" || req.Method == "" {
		m.Engine.RecordDeny("rpc.malformed", false, "")
		return errorResponse(req.ID, CodeParse, "parse error")
	}

	if req.Method != SendMethod {
		// Any OTHER message/* method is refused rather than passed through.
		// message/stream and any future sibling deliver payloads this PEP does
		// not model, and forwarding an unmodelled payload is exactly the hole
		// this middleware exists to close.
		if len(req.Method) >= 8 && req.Method[:8] == "message/" {
			m.Engine.RecordDeny("rpc.unmodelled-message-method", false, "")
			return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
		}
		// Everything else must be on the read-only allowlist. See
		// observableMethods for why that is an allowlist and not a denylist.
		if !observableMethods[req.Method] {
			m.Engine.RecordDeny("rpc.method-not-permitted", false, "")
			return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
		}
		m.Engine.RecordObserved("observe.passthrough." + req.Method)
		resp, err := m.Forward(ctx, raw)
		if err != nil {
			return errorResponse(req.ID, CodeUpstream, "upstream error")
		}
		return resp
	}

	if err := validateSendParams(req.Params); err != nil {
		// A refused webhook gets its own rule path. Every other malformed-params
		// denial is a client bug; this one is an attempt to install an
		// exfiltration destination inside an otherwise ordinary send, and an
		// operator grepping receipts should be able to find it without reading
		// error strings.
		rule := "rpc.params-ambiguous"
		if errors.Is(err, ErrWebhookRefused) {
			rule = "rpc.webhook-refused"
		}
		m.Engine.RecordDeny(rule, false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	var p struct {
		Message       json.RawMessage `json:"message"`
		Configuration json.RawMessage `json:"configuration"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || len(p.Message) == 0 {
		m.Engine.RecordDeny("rpc.params-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	histLen, err := configHistoryLength(p.Configuration)
	if err != nil {
		m.Engine.RecordDeny("rpc.configuration-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	var msg message
	if err := json.Unmarshal(p.Message, &msg); err != nil || len(msg.Parts) == 0 {
		m.Engine.RecordDeny("rpc.message-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	// role is not bound (a constant asserts nothing) — so it is PINNED instead.
	// A client speaking to an agent is "user"; absent is accepted as the
	// constant; anything else is refused. kind, when present, must be
	// "message" for the same reason.
	if msg.Role != "" && msg.Role != "user" {
		m.Engine.RecordDeny("rpc.role-not-user", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	if msg.Kind != "" && msg.Kind != "message" {
		m.Engine.RecordDeny("rpc.kind-not-message", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	// metadata carries the credential and nothing else. Any other member is
	// extension payload A2A extensions act on and the intent digest does not
	// cover it. Refused here, before the decision, so a denial cannot be
	// confused with a strip failure.
	for k := range msg.Metadata {
		if k != TokenMetaKey {
			m.Engine.RecordDeny("rpc.metadata-uncovered", false, "")
			return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
		}
	}

	boundJSON, err := json.Marshal(bound{Parts: msg.Parts, TaskID: msg.TaskID,
		ContextID: msg.ContextID, HistoryLength: histLen})
	if err != nil {
		m.Engine.RecordDeny("rpc.bind-failed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	token := extractToken(msg.Metadata)

	d := m.Engine.Decide(ctx, decision.Input{
		Token: token,
		Intent: intent.Intent{
			Tool:   SendMethod,
			Params: boundJSON,
			Target: m.AgentIdentity,
		},
	})
	if !d.Permit() {
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	stripped, err := stripToken(raw, req)
	if err != nil {
		// If we cannot prove the credential is removed, we do not forward.
		m.Engine.RecordDeny("rpc.strip-failed", true, token)
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	resp, err := m.Forward(ctx, stripped)
	if err != nil {
		return errorResponse(req.ID, CodeUpstream, "upstream error")
	}
	return resp
}

// extractToken pulls the compact token string out of message.metadata.
func extractToken(meta map[string]json.RawMessage) string {
	rawTok, ok := meta[TokenMetaKey]
	if !ok {
		return ""
	}
	var tok string
	if err := json.Unmarshal(rawTok, &tok); err != nil {
		return "" // non-string token value -> treated as absent -> deny
	}
	return tok
}

// stripToken rebuilds the request with message.metadata["spt-txn/token"]
// removed (and metadata itself removed if it becomes empty), leaving every
// other byte intact.
func stripToken(raw []byte, req rpcRequest) ([]byte, error) {
	var params map[string]json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("a2apep: reparse params: %w", err)
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(params["message"], &msg); err != nil {
		return nil, fmt.Errorf("a2apep: reparse message: %w", err)
	}
	if metaRaw, ok := msg["metadata"]; ok {
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			return nil, fmt.Errorf("a2apep: reparse metadata: %w", err)
		}
		delete(meta, TokenMetaKey)
		if len(meta) != 0 {
			// Handle refused this before deciding; reaching here means the two
			// parses disagreed, which is itself a reason not to forward.
			return nil, fmt.Errorf("a2apep: metadata carries members the intent digest does not cover")
		}
		delete(msg, "metadata")
	}
	newMsg, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	params["message"] = newMsg
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rpcRequest{Jsonrpc: req.Jsonrpc, ID: req.ID, Method: req.Method, Params: newParams})
}

// observableMethods is the exact set of A2A methods that only READ. Anything
// that is neither message/send nor on this list is denied.
//
// This is an ALLOWLIST, and it replaces a denylist that was wrong. The earlier
// rule was "refuse message/* siblings, pass everything else through as
// observation", which assumed that non-message traffic does not act. Only three
// of A2A v0.3.0's ten methods are reads. The rest change state, and one of them
// is a capability grant:
//
//   - tasks/pushNotificationConfig/set installs a client-supplied webhook URL
//     that all subsequent task updates are pushed to, and task updates carry
//     message content. A hijacked or prompt-injected agent does not need to
//     defeat the intent binding on message/send at all: it points the webhook
//     at a host it controls, and every authorized message thereafter is copied
//     out through a method the PEP had classified as observation. This is the
//     defect that forced the rule to change.
//   - tasks/pushNotificationConfig/delete removes one, silencing the operator's
//     own notifications.
//   - tasks/cancel transitions a task to canceled. Calling it is not observing
//     it; it is a denial of service against work already authorized.
//   - tasks/resubscribe reopens a stream this PEP does not model, which is the
//     same objection that refuses message/stream.
//   - agent/getAuthenticatedExtendedCard returns an agent card, and a card
//     names endpoints. cmd/a2a-pep rewrites the well-known card precisely so it
//     cannot advertise the agent behind the enforcement point; passing this
//     method through would republish that bypass over JSON-RPC, where the card
//     rewriter never looks.
//
// A method absent from this map is denied whether or not it existed when this
// was written. That is the property a denylist cannot have, and it is the same
// reasoning that makes allowedSendParams and allowedMessageMembers allowlists.
//
// A second consequence: the observe.passthrough.<method> rule path below now
// only ever concatenates one of these three constants. Under the denylist it
// concatenated attacker-supplied text, giving the receipt log an unbounded
// cardinality of rule paths that an adversary chose the contents of.
var observableMethods = map[string]bool{
	"tasks/get":                         true,
	"tasks/pushNotificationConfig/get":  true,
	"tasks/pushNotificationConfig/list": true,
}

// allowedSendParams is the exact set of top-level message/send params members
// this PEP will forward.
//
// A params-level `metadata` is REFUSED, not ignored: it is not covered by the
// intent digest, so forwarding it would hand the wrapped agent input that was
// never authorized -- the same reasoning that makes mcppep reject unrecognised
// tools/call siblings.
//
// `configuration` IS accepted, member by member, per allowedConfiguration.
var allowedSendParams = map[string]bool{"message": true, "configuration": true}

// ErrWebhookRefused reports a message/send carrying
// configuration.pushNotificationConfig.
var ErrWebhookRefused = errors.New("a2apep: configuration.pushNotificationConfig " +
	"is a capability grant, not a formatting option")

// allowedConfiguration is the MessageSendConfiguration surface this PEP will
// forward, and it encodes the three tiers of
// docs/spec/DELEGATION-INTENT-A2A.md 4.1. MessageSendConfiguration is not a
// homogeneous field, and treating it as one is the mistake this map prevents.
//
//   - pushNotificationConfig (TIER 1, a capability grant) is ABSENT. It carries
//     a URL and authentication material: the same webhook as
//     tasks/pushNotificationConfig/set, reachable inside a single message/send.
//     A caller who can set it can redirect the results of a message they were
//     authorized to send. A token that authorizes "send this content to this
//     agent" does not authorize "and copy the results to this host". It is
//     refused explicitly, with its own error and its own receipt rule, rather
//     than falling out of this map as a generic unrecognised member -- because
//     it is not a client mistake, it is the shape of an attack.
//
//   - historyLength (TIER 2, a disclosure control) is accepted and BOUND into
//     the intent digest via bound.HistoryLength. Accepted, but not the caller's
//     to choose freely.
//
//   - acceptedOutputModes and blocking (TIER 3, presentation and transport) are
//     accepted UNBOUND. They change how the answer is shaped and whether the
//     call returns immediately; they do not change what the agent does or who
//     sees the result. Refusing them would make this PEP undeployable against
//     ordinary clients for no security gain, which is a real cost and not a
//     conservative choice.
var allowedConfiguration = map[string]bool{
	"acceptedOutputModes": true,
	"blocking":            true,
	"historyLength":       true,
}

// configHistoryLength extracts the tier-2 member for the intent digest. A
// configuration that is absent, null, or omits historyLength binds nothing, so
// a request that sends no configuration produces the digest it always did.
func configHistoryLength(cfg json.RawMessage) (*int, error) {
	if len(cfg) == 0 || string(bytes.TrimSpace(cfg)) == "null" {
		return nil, nil
	}
	var c struct {
		HistoryLength *int `json:"historyLength"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return nil, err
	}
	return c.HistoryLength, nil
}

// allowedMessageMembers is the Message surface from A2A v0.3.0. It is an
// ALLOWLIST: a member this PEP does not know about may carry payload the
// intent digest does not cover. Update it when the spec adds a field, and
// update the binding at the same time if the new field is acted upon.
var allowedMessageMembers = map[string]bool{
	"role": true, "parts": true, "messageId": true,
	"taskId": true, "contextId": true, "metadata": true, "kind": true,
}

func validateSendParams(params json.RawMessage) error {
	if err := scanObject(params, allowedSendParams, "params"); err != nil {
		return err
	}
	var p struct {
		Message       json.RawMessage `json:"message"`
		Configuration json.RawMessage `json:"configuration"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return err
	}
	if len(p.Configuration) != 0 && string(bytes.TrimSpace(p.Configuration)) != "null" {
		// Checked before the allowlist scan so the webhook gets its specific
		// error rather than a generic "unrecognised member", which an operator
		// would have to already know to look for.
		var cfg map[string]json.RawMessage
		if err := json.Unmarshal(p.Configuration, &cfg); err != nil {
			return err
		}
		if _, present := cfg["pushNotificationConfig"]; present {
			return ErrWebhookRefused
		}
		if err := scanObject(p.Configuration, allowedConfiguration, "configuration"); err != nil {
			return err
		}
	}
	return scanObject(p.Message, allowedMessageMembers, "message")
}

// scanObject rejects a duplicated member name and any member outside allowed.
// Nested duplicate detection for the authorized surface happens in the
// canonicalizer (internal/jcs) when the intent digest is recomputed.
func scanObject(obj json.RawMessage, allowed map[string]bool, what string) error {
	if len(obj) == 0 {
		return fmt.Errorf("a2apep: absent %s", what)
	}
	dec := json.NewDecoder(bytes.NewReader(obj))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("a2apep: %s is not an object", what)
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("a2apep: %s member name is not a string", what)
		}
		if seen[key] {
			return fmt.Errorf("a2apep: duplicate %s member %q", what, key)
		}
		if !allowed[key] {
			return fmt.Errorf("a2apep: unrecognised %s member %q (not covered by intent binding)", what, key)
		}
		seen[key] = true
		if err := skipValue(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// skipValue consumes exactly one JSON value from dec.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		depth := 1
		for depth > 0 {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tok.(json.Delim); ok {
				switch d {
				case '{', '[':
					depth++
				case '}', ']':
					depth--
				}
			}
		}
	}
	return nil
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcErrorResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcError        `json:"error"`
}

func errorResponse(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 || string(id) == "null" {
		return nil
	}
	out, err := json.Marshal(rpcErrorResponse{Jsonrpc: "2.0", ID: id, Error: rpcError{Code: code, Message: msg}})
	if err != nil {
		return nil
	}
	return out
}
