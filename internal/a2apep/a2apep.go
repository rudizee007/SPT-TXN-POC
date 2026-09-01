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
//     constant asserts nothing.
//   - metadata  — carries the credential itself, and is stripped before
//     forwarding. A field cannot both be the key and be locked by it.
type bound struct {
	Parts     json.RawMessage `json:"parts"`
	TaskID    string          `json:"taskId,omitempty"`
	ContextID string          `json:"contextId,omitempty"`
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
		// this middleware exists to close. Non-message traffic (agent card
		// fetch, task query) is observation and passes.
		if len(req.Method) >= 8 && req.Method[:8] == "message/" {
			m.Engine.RecordDeny("rpc.unmodelled-message-method", false, "")
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
		m.Engine.RecordDeny("rpc.params-ambiguous", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	var p struct {
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || len(p.Message) == 0 {
		m.Engine.RecordDeny("rpc.params-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	var msg message
	if err := json.Unmarshal(p.Message, &msg); err != nil || len(msg.Parts) == 0 {
		m.Engine.RecordDeny("rpc.message-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	boundJSON, err := json.Marshal(bound{Parts: msg.Parts, TaskID: msg.TaskID, ContextID: msg.ContextID})
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
		if len(meta) == 0 {
			delete(msg, "metadata")
		} else {
			enc, err := json.Marshal(meta)
			if err != nil {
				return nil, err
			}
			msg["metadata"] = enc
		}
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

// allowedSendParams is the exact set of top-level message/send params members
// this PEP will forward.
//
// `configuration` and a params-level `metadata` are REFUSED, not ignored.
// Neither is covered by the intent digest, so forwarding either would hand the
// wrapped agent input that was never authorized -- the same reasoning that
// makes mcppep reject unrecognised tools/call siblings. Binding them is future
// work; until then, refusing is the honest behaviour.
var allowedSendParams = map[string]bool{"message": true}

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
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return err
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
