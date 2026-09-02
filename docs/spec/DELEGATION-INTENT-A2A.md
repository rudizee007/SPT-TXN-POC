# SPT-Txn Specification — A2A PEP Profile

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/a2apep`, `cmd/a2a-pep`, shared with MCP: `internal/decision`, `internal/intent`, `internal/jcs`.
**Wire protocol:** Agent2Agent (A2A) v0.3.0, JSON-RPC 2.0 transport.
**Threat model:** `docs/THREAT-MODEL.md` §3.3, §4.1, §4.2, §4.6.

---

## 0. Relationship to the MCP profile

`docs/spec/DELEGATION-INTENT-MCP.md` §1 (delegation chains with offline
attenuation) and §2 (intent binding, JCS canonicalization, verification) apply
here **unchanged and normatively**. They are protocol-independent: the question
"was this actor allowed to do exactly this" does not vary with the transport
that carried the request.

This document specifies only what differs — the A2A wire binding, the method
surface, and the transport profile. `internal/a2apep` shares `internal/decision`
with `internal/mcppep` byte for byte; a divergence between the two decision
paths is a defect, not a profile difference.

---

## 1. Placement

The PEP wraps an A2A agent. Every `message/send` MUST carry a valid SPT-Txn
token whose intent binding matches the message being delivered. The wrapped
agent is reachable only through the PEP; an operator who leaves the agent's own
port reachable has not deployed an enforcement point, they have deployed a
second address for the same agent (see §6.1, which is the same failure in
documentary form).

---

## 2. Intent construct for A2A

    intent.tool   = "message/send"
    intent.params = JCS(bound)
    intent.target = the PEP's configured agent identity

where `bound` is the subobject of the A2A `Message` that the digest covers:

    bound = {
      "parts":     <the message's parts array, byte-exact>,
      "taskId":    <string, omitted when absent>,
      "contextId": <string, omitted when absent>
    }

### 2.1 What is bound, and why

- **`parts`** — the content the agent acts on. This is the analogue of MCP's
  `arguments` and is the reason the profile exists.
- **`taskId`** — WHERE the message lands. Without it, a token authorizing a
  message into one task authorizes the same content into another.
- **`contextId`** — the same argument one level up.

### 2.2 What is deliberately NOT bound

- **`messageId`** — generated per send by the client. The minter cannot predict
  it, so binding it would make every token unusable on first presentation.
  Replay of a whole message is handled by the decision engine's `jti` replay
  window (MCP profile §3.2 rule 4), not here.
- **`role`** — a client sending a message is always `"user"`. Binding a
  constant asserts nothing.
- **`metadata`** — carries the credential itself and is stripped before
  forwarding. A field cannot both be the key and be locked by it.

A future revision that binds `messageId` MUST also change the minting path, and
the happy-path test will fail loudly if only one side changes: the minter
constructs `bound` from the same struct the PEP does, so a field added to one is
added to both or the digests diverge.

---

## 3. Method surface (normative)

A2A v0.3.0 defines ten JSON-RPC methods. This profile partitions them into
exactly three classes. **The partition is an allowlist.** A method absent from
§3.3 MUST be denied whether or not it existed when this document was written.

### 3.1 Authorized

`message/send`. Requires a token; enforced per §2 and §4.

### 3.2 Refused as unmodelled

`message/stream`, and any future `message/*` sibling. These deliver payloads
this profile does not model — a stream is not a discrete message and cannot be
matched against a single intent digest. They MUST be denied, never proxied.
Forwarding an unmodelled payload is precisely the gap the PEP exists to close.

Receipt rule path: `rpc.unmodelled-message-method`.

### 3.3 Passed through as observation

Exactly three methods, and only these:

    tasks/get
    tasks/pushNotificationConfig/get
    tasks/pushNotificationConfig/list

These read and do not act. They pass unauthenticated but receipted as
`observed`.

### 3.4 Denied

Everything else, including the remaining A2A methods:

| Method | Why it is not observation |
|---|---|
| `tasks/pushNotificationConfig/set` | Installs a client-supplied webhook URL that all subsequent task updates are pushed to, and task updates carry message content. A hijacked agent need not defeat the intent binding at all: it points the webhook at a host it controls, and every authorized message thereafter is copied out. |
| `tasks/pushNotificationConfig/delete` | Removes a webhook, silencing the operator's own notifications. |
| `tasks/cancel` | Transitions a task to `canceled`. A denial of service against work already authorized. |
| `tasks/resubscribe` | Reopens a stream this profile does not model — §3.2's objection, on a different method name. |
| `agent/getAuthenticatedExtendedCard` | Returns an agent card, and a card names endpoints. Passing it through republishes over JSON-RPC the bypass §6.1 exists to close, where the card rewriter never looks. |

Receipt rule path: `rpc.method-not-permitted`.

**Rationale for the allowlist shape.** An earlier revision of this profile used
a denylist — refuse `message/*` siblings, pass everything else as observation —
on the assumption that non-message traffic does not act. Only three of ten
methods are reads. The assumption was wrong, and the shape is what made it
dangerous: a denylist is wrong by default for every method its author did not
consider, including every method added after they stopped considering.

A second property follows. The observation rule path is constructed as
`observe.passthrough.<method>`. Under a denylist that concatenated
attacker-supplied text, giving the receipt log an unbounded cardinality of rule
paths whose contents an adversary chose — a log-injection and log-flooding
primitive inside the evidence layer, which is the one component that must remain
trustworthy when every other is in doubt. Under an allowlist it can only be one
of three constants.

---

## 4. Params surface (normative)

`MessageSendParams` members MUST be allowlisted. This profile accepts exactly
one member, `message`; a params-level `metadata` and any unrecognised sibling
MUST be denied.

`Message` members MUST be allowlisted against the A2A v0.3.0 surface (`role`,
`parts`, `messageId`, `taskId`, `contextId`, `metadata`, `kind`). A duplicated
member name MUST be rejected at parse — not last-wins, not first-wins (MCP
profile §2.2).

### 4.1 `configuration` — three tiers, not one decision

`MessageSendConfiguration` is not a homogeneous field, and treating it as one is
the mistake this section exists to prevent. Its four members fall into three
classes with three different answers:

**Tier 1 — a capability grant. `pushNotificationConfig`.**
It carries a URL and authentication material: the same webhook as
`tasks/pushNotificationConfig/set` (§3.4), reachable inside a single
`message/send`. A caller who can set it can redirect the results of a message
they were authorized to send. It MUST NOT be forwarded unbound. It MUST either
be refused, or be covered by the intent digest so the minter names the
destination. A token that authorizes "send this content to this agent" does not
authorize "and copy the results to this host", and no ergonomic argument reaches
this tier.

**Tier 2 — a disclosure control. `historyLength`.**
It governs how much prior conversation is returned. Letting the caller choose it
is letting the caller choose how much history to extract. It SHOULD be bound
into the intent digest, or clamped by policy at the PEP. It MUST NOT be
forwarded unbound and unclamped.

**Tier 3 — presentation and transport. `acceptedOutputModes`, `blocking`.**
These change how the answer is shaped and whether the call returns immediately.
They do not change what the agent does, and they do not change who sees the
result. They MAY be forwarded unbound.

The current implementation refuses `configuration` entirely. That is a
conservative default taken before the field was examined, not the position this
section states: refusing tier 3 makes the PEP undeployable against ordinary
clients, since `blocking` is routine. The tiering is the intended behaviour and
the flat refusal is the interim.

---

## 5. Credential carriage

The token travels in `params.message.metadata["spt-txn/token"]` — the direct
analogue of MCP's `params._meta["spt-txn/token"]`.

The PEP MUST strip that key before forwarding, and MUST remove `metadata`
entirely if stripping empties it, so that no residue signals to the agent that a
credential was present. If the PEP cannot prove the credential was removed, it
MUST NOT forward (rule path `rpc.strip-failed`).

The wrapped agent never sees, stores or re-presents the credential
(THREAT-MODEL §4.6).

---

## 6. Transport profile (`cmd/a2a-pep`)

A2A rides JSON-RPC over HTTP, so the profile has obligations below the body that
the middleware cannot discharge.

### 6.1 Agent card rewriting

An agent card names the endpoint clients should talk to. A PEP that relays the
wrapped agent's card unmodified publishes the address of the agent *behind* the
enforcement point, and the first thing any compliant client does with that card
is route around the PEP. The enforcement point ships its own bypass.

**This is established practice, not an observation of this profile's.** Kong's
AI A2A Proxy rewrites the card's `url` and its `additionalInterfaces[].url` to
the gateway address; Gravitee and Agentgateway ship A2A proxies of the same
shape. One protocol out, Azure API Management rewrites an OpenAPI document's
`servers` block to the gateway rather than the backend, and rewriting OIDC
`.well-known/openid-configuration` at a reverse proxy has many independent
implementations. This section is written to say what THIS profile requires, not
to claim the requirement is new.

Two requirements below diverge from that practice, deliberately:

- Kong REWRITES `additionalInterfaces[].url` to the gateway. This profile
  DROPS those entries (rule 3). A JSON-RPC PEP cannot enforce a gRPC interface,
  so rewriting one advertises a route the enforcement point does not guard.
- Kong derives the gateway address from `X-Forwarded-*` headers. This profile
  requires the operator to state it (rule 1), because a value reconstructed
  from forwarded headers is influenced by the caller.

Therefore:

1. Card relay MUST be disabled unless the operator supplies the URL clients
   reach the PEP on. A PEP with nothing to advertise serves no card.
2. When relaying, `url` MUST be replaced with the PEP's own address.
3. `additionalInterfaces` MUST be dropped, not rewritten. Every entry is a
   second address on a transport this PEP does not enforce; a gRPC interface
   cannot be pointed at a JSON-RPC proxy, and keeping it would advertise a
   bypass that happens to look authorized. An operator who needs those
   transports guarded needs a PEP for those transports, not a card implying one
   exists.
4. Dropping them MUST be reported to the operator. A multi-transport agent
   silently degraded to JSON-RPC only leaves its gRPC clients unable to discover
   an endpoint, with nothing anywhere saying why. A card that misleads is what
   rules 1 to 3 prevent; a card that silently loses capability is the same
   defect facing the other way.
5. The advertised URL MUST be validated as an absolute http(s) URL before it is
   published. Rule 1 requires the operator to state the address precisely
   because a stated value can be trusted where a reconstructed one cannot --
   which only holds if the stated value is checked.

### 6.2 Header isolation

No client header is copied upstream. Stripping the credential from the body and
then forwarding the caller's `Authorization` or `Cookie` hands the wrapped agent
a different credential for the same caller — the confused-deputy hole of §5, one
layer down.

This SHOULD be structural rather than checked: the forwarding function receives
the token-stripped body and nothing else, so no header map is in scope to copy.
A refactor that threads the client request downward (to reuse a trace header,
or to adopt a general-purpose reverse proxy) reopens this in one line and MUST
be treated as a change to the trust boundary.

### 6.3 Transport rules

1. Exactly two requests exist: POST on the JSON-RPC path, GET on the card path.
   There MUST be no default branch that forwards.
2. The request body MUST be capped before the enforcement point is consulted.
3. A `text/event-stream` answer from the wrapped agent MUST be refused, not
   relayed: relaying it returns content the enforcement point never saw.
4. A redirect from the wrapped agent MUST NOT be followed. Following one sends
   an authorized request to a host the operator never configured.
5. A denial MUST be HTTP 200 carrying a JSON-RPC error. The refusal is uniform
   by design (§7); a distinguishable status code restores the oracle the uniform
   body exists to remove.

---

## 7. Uniform refusal

Every denial returns one message. The failing check is recorded in the receipt,
which the operator reads, and not in the error, which the caller reads. A caller
who can distinguish "wrong audience" from "digest mismatch" from "replayed jti"
can search for a token that works.

---

## 8. What this profile does not do

It does not evaluate whether the declared message is *wise* — that is the policy
layer. It does not authenticate the human principal — that is issuance
(CAT/IdP exchange). It does not model streaming, and refuses rather than
pretends. It does not guard transports other than JSON-RPC over HTTP, and §6.1
requires it to stop advertising the ones it does not guard.

It constrains a holder to its declared action. State this plainly; do not
overclaim.
