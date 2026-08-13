# SPT-Txn P3 Specification — Gateway Form Factor (Skins over One Decision Core)

**Status:** v0.1 draft. Normative language per RFC 2119.
**Companion code:** `internal/decision`, `cmd/extauthz`, `cmd/opashim`, `internal/mcppep`.

---

## 1. Architecture rule

Three thin skins over **one** decision core:

    Envoy ext_authz  ┐
    OPA decision API ├──►  internal/decision.Engine  ──►  receipts
    MCP middleware   ┘

Skins are stateless, hold no signing keys, and contain **no decision logic**.
A compromised skin can deny service; it MUST NOT be able to mint authority.
If a change would let a skin influence a decision, that change moves the skin
inside the trust boundary — reject or re-scope it (THREAT-MODEL §1).

**Structural deny-by-default:** the core returns an opaque `Decision` value
that can only be constructed by the engine. A skin cannot fabricate a permit;
an error path that loses the decision object has nothing to forward and the
skin's zero-value answer is deny. It is impossible to construct a request
that "passed through" without a decision attached (CLAUDE.md §2).

**Latency is a security requirement:** decision path budget p99 < 10 ms. The
skins add serialization only.

## 1.1 What a gateway PEP verifies, and what it relies on

A gateway PEP is presented with **one token** — the SPT-Txn — and nothing else.
It receives no CAT, no CT chain, and it holds no trust-registry snapshot. It
therefore **does not walk the delegation chain**. It relies on the TTS having
walked it at issuance, and verifies the TTS signature.

That reliance is sound only under the conditions below. They are not optional
hardening; they are what makes a non-chain-walking PEP an authorization point
rather than a signature checker.

**A PEP MUST declare a maximum acceptable token lifetime, and MUST reject a
token whose remaining lifetime exceeds it.**

The reliance above buys a revocation gap exactly as long as the token's
lifetime: once minted, an SPT-Txn cannot be withdrawn by revoking the CT, the
CAT, or the issuer's registry key, because the PEP consults none of them.
`txntoken.DefaultTTL` is 30 seconds for this reason, but a TTL is
caller-supplied at issuance and bounded only by the parent CT's expiry — so a
24-hour capability yields an acceptable 24-hour transaction token. The bound has
to be enforced where the reliance is taken, which is the PEP.

**A PEP's replay window MUST be at least its maximum acceptable token
lifetime.**

Single use is enforced by remembering a `jti` for the replay window. If a token
outlives that memory, the slot is pruned while the token is still valid and the
same token is accepted again. Single use then means "single use per replay
window", which is not single use. The two values are one property expressed
twice, so the engine refuses to start when they disagree rather than trusting an
operator to keep them aligned.

**A PEP MUST verify that the token's `aud` names this deployment, and MUST be
configured with that identity explicitly.**

`aud` is the executing domain the token was minted for. A PEP that does not
check it accepts any validly-signed, unexpired token from the same TTS,
including one issued for a different domain entirely — so every deployment under
one TTS becomes a single audience, and the domain boundary exists only in the
issuer's intent. This is step 3 of the eight-step engine, and the gateway form
factor does not run that engine, so the check has to exist here.

The identity is required configuration, not a default. An audience compared
against an unset value passes whenever the token also omits `aud`, which is a
fail-open reachable by misconfiguration alone.

**Consequences to state plainly, because a deployer will otherwise assume
otherwise:**

- Revoking a CT, a CAT, or an issuer key does not invalidate an already-minted
  SPT-Txn at a gateway PEP. The maximum token lifetime *is* the revocation
  latency for this form factor.
- A deployment that needs revocation to take effect faster than that must lower
  the maximum token lifetime, not add a cache.
- A PEP that needs the chain walked at the point of use is not this form factor;
  it is the full engine (`internal/verifier`), which requires the chain to be
  presented and a registry to be reachable.

## 2. Envoy `ext_authz` (HTTP mode)

- Endpoint: `POST /authz` receiving the ext_authz HTTP-service payload
  (request headers as JSON). Covers Istio, service mesh, and most API
  gateways by extension.
- Token: `x-spt-txn-token` request header. Declared intent: the PEP derives
  `intent.tool` from `:method`, `intent.target` from configured upstream
  identity, `intent.params` from the digest-relevant headers profile.
- Response: `200` (permit; strips the token header before upstream — no
  credential passthrough) or `403` (deny; uniform body, receipt records the
  detail). Engine unreachable/timeout ⇒ `403`, class `unavailable`. Never
  5xx for a decision — Envoy fail-open configs treat 5xx as "authz service
  broken"; a decision is always an authz answer.

## 3. OPA-compatible decision API

- Endpoint: `POST /v1/data/spttxn/authz` accepting `{"input": {...}}`,
  answering `{"result": {"allow": bool, "class": "...", "receipt_ref": "..."}}` —
  the input/output shapes existing OPA integrations already send and expect.
  Every existing OPA integration point becomes an SPT-Txn integration point
  for free.
- `allow` is `true` only on a `PERMIT` from the core. Absent fields, wrong
  types, unparseable input ⇒ `{"result": {"allow": false, "class": "violation"}}`.
- The shim performs **no** Rego evaluation and holds **no** policy. It is a
  socket shape, nothing more.

## 4. MCP middleware

Shared with P1 — see `docs/spec/DELEGATION-INTENT-MCP.md` §3. Same core,
agent-shaped socket.

## 5. Deployment bar

Deployable in an afternoon by someone else's platform team, or it does not
count: single static binary per skin, one YAML/env config (core address,
trust-registry keys, jurisdiction profile), no database, health endpoint,
structured logs to stdout.
