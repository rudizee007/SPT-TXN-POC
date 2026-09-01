// Package mcppep is the SPT-Txn MCP Policy Enforcement Point: JSON-RPC
// middleware that wraps an MCP server so that every tools/call invocation
// requires a valid transaction-scoped token whose intent binding matches the
// invocation. Spec: docs/spec/DELEGATION-INTENT-MCP.md §3.
//
// Confused-deputy discipline (docs/THREAT-MODEL.md §4.6): the token travels
// in params._meta["spt-txn/token"] and is STRIPPED before the request is
// forwarded. The wrapped server never sees, stores, or forwards the
// credential — the MCP token-passthrough gap is closed here, not reproduced.
// The PEP holds no credentials that outlive a single decision.
//
// The middleware is transport-agnostic: it operates on raw JSON-RPC 2.0
// message bytes, so it can sit on stdio, HTTP, or SSE framing.
package mcppep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rudizee007/spt-txn-poc/internal/decision"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
)

// TokenMetaKey is the params._meta key carrying the SPT-Txn token.
const TokenMetaKey = "spt-txn/token"

// JSON-RPC error codes emitted by the PEP.
const (
	CodeParse    = -32700 // malformed JSON-RPC
	CodeDenied   = -32001 // authorization denied (uniform; detail is in the receipt)
	CodeUpstream = -32002 // authorized, but the wrapped server failed
)

// Forward delivers a (token-stripped) request to the wrapped MCP server and
// returns its raw response (nil for notifications).
type Forward func(ctx context.Context, raw []byte) ([]byte, error)

// Middleware enforces SPT-Txn on an MCP message stream. Stateless apart from
// the decision engine it delegates to; holds no keys.
type Middleware struct {
	// Engine is the shared decision core. Required.
	Engine *decision.Engine
	// ServerIdentity is this PEP's configured identity for the wrapped
	// server — the intent `target`. A token minted for another server MUST
	// NOT verify here. Required.
	ServerIdentity string
	// Forward delivers to the wrapped server. Required.
	Forward Forward
}

// New validates the middleware wiring.
func New(engine *decision.Engine, serverIdentity string, forward Forward) (*Middleware, error) {
	if engine == nil {
		return nil, errors.New("mcppep: decision engine required")
	}
	if serverIdentity == "" {
		return nil, errors.New("mcppep: server identity required")
	}
	if forward == nil {
		return nil, errors.New("mcppep: forward required")
	}
	return &Middleware{Engine: engine, ServerIdentity: serverIdentity, Forward: forward}, nil
}

// observableMethods is the exact set of MCP client→server methods that only
// READ metadata and carry no caller-chosen target. Anything that is neither
// tools/call nor on this list is denied.
//
// This is an ALLOWLIST. "Anything but tools/call is observation" would assume
// non-invocation traffic does not act, and it does:
//
//   - resources/read takes a caller-chosen uri; with resource templates it is a
//     parametric read of whatever the wrapped server can reach.
//   - prompts/get takes caller-chosen arguments and returns rendered content.
//   - resources/subscribe, logging/setLevel, completion/complete change server
//     state or return caller-steered data.
//   - a method name the wrapped server tolerates but this PEP does not know is
//     not the enforced surface by name.
//
// Extending authorization to resources/read or prompts/get is a spec change
// (an intent binding for a uri, DELEGATION-INTENT-MCP §3); until it exists
// they are denied, not observed. A method absent from this map is denied
// whether or not it existed when this was written — the property a denylist
// cannot have, and the same reasoning the A2A sibling already applies.
//
// Notifications carry no id and get no response; the three listed are the
// lifecycle/progress signals a client sends and none names a target.
var observableMethods = map[string]bool{
	"initialize":                true,
	"ping":                      true,
	"tools/list":                true,
	"resources/list":            true,
	"resources/templates/list":  true,
	"prompts/list":              true,
	"notifications/initialized": true,
	"notifications/cancelled":   true,
	"notifications/progress":    true,
}

// rpcRequest is the minimal JSON-RPC 2.0 shape the PEP needs. Everything it
// does not inspect stays as raw bytes.
type rpcRequest struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type callParams struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta"`
}

// Handle processes one raw JSON-RPC message. It always returns a response
// for requests (never forwards an unauthorized tools/call), and returns nil
// for notifications that produce no response. Every branch that does not
// forward is a deny with a receipt.
func (m *Middleware) Handle(ctx context.Context, raw []byte) []byte {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.Jsonrpc != "2.0" || req.Method == "" {
		m.Engine.RecordDeny("rpc.malformed", false, "")
		return errorResponse(req.ID, CodeParse, "parse error")
	}

	if req.Method != "tools/call" {
		// Everything that is not the enforced surface must be on the read-only
		// allowlist. See observableMethods for why that is an allowlist and not
		// the denylist ("anything but tools/call passes") this used to be.
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

	// tools/call — the enforced surface.
	if err := validateCallParams(req.Params); err != nil {
		// Two hazards closed here:
		//  - duplicate members: the PEP could authorize one reading of the
		//    request while the wrapped server executes another.
		//  - unknown top-level members: only `name`/`arguments`/`_meta` are
		//    covered by the intent digest; any other sibling would be
		//    forwarded UNAUTHORIZED. Reject rather than forward un-bound input.
		m.Engine.RecordDeny("rpc.params-ambiguous", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}
	var call callParams
	if err := json.Unmarshal(req.Params, &call); err != nil || call.Name == "" {
		m.Engine.RecordDeny("rpc.params-malformed", false, "")
		return errorResponse(req.ID, CodeDenied, "spt-txn: denied")
	}

	token := extractToken(call.Meta)

	d := m.Engine.Decide(ctx, decision.Input{
		Token: token,
		Intent: intent.Intent{
			Tool:   call.Name,
			Params: call.Arguments,
			Target: m.ServerIdentity,
		},
	})
	if !d.Permit() {
		// Uniform denial on the wire; the receipt records which check failed.
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

// extractToken pulls the compact token string out of params._meta.
func extractToken(meta map[string]json.RawMessage) string {
	rawTok, ok := meta[TokenMetaKey]
	if !ok {
		return ""
	}
	var tok string
	if err := json.Unmarshal(rawTok, &tok); err != nil {
		return "" // non-string token value → treated as absent → deny
	}
	return tok
}

// stripToken rebuilds the request with params._meta["spt-txn/token"] removed
// (and _meta itself removed if it becomes empty), leaving every other byte
// of params intact.
func stripToken(raw []byte, req rpcRequest) ([]byte, error) {
	var params map[string]json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("mcppep: reparse params: %w", err)
	}
	if metaRaw, ok := params["_meta"]; ok {
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			return nil, fmt.Errorf("mcppep: reparse _meta: %w", err)
		}
		delete(meta, TokenMetaKey)
		if len(meta) == 0 {
			delete(params, "_meta")
		} else {
			enc, err := json.Marshal(meta)
			if err != nil {
				return nil, err
			}
			params["_meta"] = enc
		}
	}
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	out := rpcRequest{Jsonrpc: req.Jsonrpc, ID: req.ID, Method: req.Method, Params: newParams}
	return json.Marshal(out)
}

// allowedCallParams is the exact set of top-level tools/call params members.
// Anything else is rejected: only these are covered by the intent digest, so
// forwarding an unrecognised sibling would hand the wrapped server input that
// was never authorized.
var allowedCallParams = map[string]bool{"name": true, "arguments": true, "_meta": true}

// validateCallParams scans the top level of the tools/call params object and
// rejects (a) duplicated member names and (b) any member outside
// allowedCallParams. Nested duplicate detection for the authorized surface
// happens in the canonicalizer (internal/jcs) when the intent digest is
// recomputed.
func validateCallParams(params json.RawMessage) error {
	if len(params) == 0 {
		return errors.New("mcppep: absent params")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("mcppep: params is not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token() // member name
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("mcppep: params member name is not a string")
		}
		if seen[key] {
			return fmt.Errorf("mcppep: duplicate params member %q", key)
		}
		if !allowedCallParams[key] {
			return fmt.Errorf("mcppep: unrecognised params member %q (not covered by intent binding)", key)
		}
		seen[key] = true
		if err := skipValue(dec); err != nil { // consume the member value
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return err
	}
	return nil
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

// errorResponse builds a JSON-RPC error. For notifications (no id) it
// returns nil — there is nothing to answer, and the deny simply means the
// call was not forwarded.
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
