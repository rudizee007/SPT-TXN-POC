# SPT-Txn P1 Specification — Delegation Attenuation, Intent Binding, MCP PEP Profile

**Status:** v0.1 draft — spec-first artifact per `docs/ROADMAP.md` P1. Normative language per RFC 2119.
**Companion code:** `internal/jcs`, `internal/intent`, `internal/cttoken` (chain), `internal/mcppep`.
**Threat model:** `docs/THREAT-MODEL.md` §3.3, §4.1, §4.2, §4.6.

---

## 1. Delegation Chains with Offline Attenuation

### 1.1 Model

A delegation chain is a sequence

    CAT (root) → CT₁ → CT₂ → … → CTₙ

where the root is a Compliance Attestation Token and each hop is a Capability
Token whose scope is a **strict attenuation** of its parent. Chains are
verifiable **offline**: a verifier holding the chain and the trust-registry
public keys needs no call home to establish that every hop only narrowed
authority.

### 1.2 Invariants (normative)

1. **Monotonic scope.** For every hop, `scope(child) ⊆ scope(parent)` under the
   containment relation of `internal/tbac` (numeric dimensions are ceilings,
   strings/booleans exact-match, lists subsets, objects recursive). A dimension
   present in the child but absent in the parent MUST be rejected. A dimension
   is a **constraint**, so a hop that *drops* a dimension the parent declared
   does NOT thereby narrow authority — dropping a ceiling would leave that axis
   unconstrained at transaction time. The verifier therefore enforces the
   transaction against the **intersection of every scope from the root to the
   leaf** (the tightest value seen on each axis, with a dropped dimension
   inherited from its nearest ancestor), not against the leaf scope alone. A
   dropped ceiling is thus non-exploitable: it is inherited, never widened.
   (Enforcement point: `verifier.step6Chain` → `step7Scope`.)
2. **Monotonic TTL.** `exp(child) ≤ exp(parent)` and `exp(child) > iat(child)`.
   A child that outlives its parent MUST be rejected at construction AND at
   verification (defense in depth — a malicious issuer must not be able to
   extend lifetime). Defaulted lifetimes clamp to the parent boundary (a
   default is computed, not requested); an explicitly requested TTL that
   would overrun the parent is rejected — the issuer never silently rewrites
   an explicit request.
3. **Bounded depth.** The root carries `delegation_depth_remaining`. Each hop
   decrements it by exactly 1. A hop at depth 0 MUST be rejected. Depth
   overflow, absence, non-integer encoding, or negative values MUST be
   rejected (fail closed).
4. **Full-chain verification.** A verifier MUST walk the entire chain from the
   root. There is no fast path for "trusted" intermediate tokens. Signature,
   expiry, scope containment, depth, and holder-key linkage are re-checked at
   every hop.
5. **Anchor propagation.** `human_anchor` and the root CAT reference propagate
   unchanged through every hop. Any mutation MUST be rejected.
6. **Revocation.** Chains of depth > 1 REQUIRE a status check against the trust
   registry (issuer status + per-token status list where deployed). If no
   status source is reachable the decision is DENY with class `unavailable`.
   Revoking a hop revokes its entire subtree (cascade).

### 1.3 Encoding

Hops are Ed25519-signed JWTs (`alg: EdDSA` allowlisted; `alg: none` and any
unlisted suite rejected — see `docs/spec/CRYPTO-AGILITY.md` for the envelope
that supersedes bare `alg`). Claims per hop:

| Claim | Meaning |
|---|---|
| `txn_token_type` | `"CT"` |
| `capability_scope` | attenuated scope object |
| `delegation_depth_remaining` | parent value − 1 |
| `holder_key` | hex Ed25519 key bound to this hop's holder |
| `spt_parent_ref` / `spt_parent_hash` | immediate parent `jti` / base64url(SHA-256(parent compact JWT)) |
| `spt_cat_ref` | root CAT `jti`, propagated unchanged |
| `human_anchor` | propagated unchanged |

`spt_parent_hash` seals the exact parent bytes: substituting a different
parent with the same `jti` breaks the chain.

---

## 2. Intent Binding

### 2.1 Construct

A transaction-scoped token binds a digest of the **declared action**:

    intent = {
      "tool":   <tool/method identifier, string>,
      "params": <parameter object as declared>,
      "target": <target resource identifier, string>
    }

    intent_digest = SHA-256( "spt-txn-intent-v1" || 0x00 || JCS(intent) )

carried in the token as claim `spt_intent_digest` (base64url, no padding).
The PEP recomputes the digest over the **actual** call and compares in
constant time. Mismatch ⇒ DENY, class `violation`. An agent whose reasoning
is hijacked mid-task holds a token that is cryptographically useless for the
hijacked action (OWASP ASI01).

### 2.2 Canonicalization (normative — the critical section)

Canonical form is **RFC 8785 (JCS)**, restricted to the following accepted
subset. Anything outside the subset MUST be rejected, never normalized
(THREAT-MODEL §4.1: a parser that "helpfully" fixes input is attack surface).

Accepted values:

- Objects with **unique** member names. Duplicate names MUST be rejected at
  parse (not last-wins, not first-wins).
- Arrays, strings, `true`, `false`, `null`.
- Numbers that are **integers** with absolute value ≤ 2⁵³ − 1, without
  fraction or exponent syntax. All other numbers (fractions, exponents,
  `-0`, out-of-range magnitudes) MUST be rejected. Monetary amounts are
  decimal **strings** by profile (`"amount": "125000.00"`), never floats.

Serialization rules (per RFC 8785):

- Object members sorted by member name as sequences of UTF-16 code units.
- No insignificant whitespace.
- String escaping exactly per JCS §3.2.2.2 (two-char escapes `\" \\ \b \f \n
  \r \t`, control characters as lowercase `\u00xx`, all other characters
  literal UTF-8).
- Integers serialized per ECMAScript `Number::toString` (for the accepted
  integer subset: ordinary base-10, `-0` excluded).

**One implementation** (`internal/jcs`) is shared by issuer and verifier
paths. A second implementation anywhere in the tree is a defect. The test
suite carries golden vectors generated from an independent RFC 8785
implementation, plus differential fuzzing (structurally distinct inputs ⇒
distinct digests; semantically identical inputs ⇒ identical bytes).

### 2.3 Verification (normative)

1. Parse the actual call into `intent` shape. Rejection at parse ⇒ DENY
   (`violation`).
2. Compute `JCS(intent)`; any canonicalization error ⇒ DENY (`violation`).
3. Compare digests with `crypto/subtle.ConstantTimeCompare`.
4. Uniform external error: the caller learns only "denied"; the receipt
   records which check failed.
5. A token without `spt_intent_digest` presented to an intent-enforcing PEP
   ⇒ DENY (`violation`). Absence of the claim never downgrades enforcement.

---

## 3. MCP PEP Profile

### 3.1 Placement

The PEP wraps an MCP server (middleware). Every `tools/call` invocation MUST
carry a valid SPT-Txn token whose intent binding matches the invocation.
Only a fixed allowlist of read-only, target-free methods passes through
unauthenticated, receipted as `observed`: `initialize`, `ping`, `tools/list`,
`resources/list`, `resources/templates/list`, `prompts/list`, and the
`notifications/initialized`, `notifications/cancelled`, `notifications/progress`
notifications. Every other method is denied. In particular `resources/read`,
`prompts/get`, `resources/subscribe`, `logging/setLevel` and
`completion/complete` carry a caller-chosen target or change server state and
are NOT observation; authorizing them requires an intent binding of their own
(a `uri` binding for `resources/read`), which this profile does not yet
define. The list is an allowlist: a method absent from it is denied whether
or not it existed when the list was written.

### 3.2 Rules (normative)

1. **Token transport.** The token travels in `params._meta["spt-txn/token"]`.
   The PEP MUST strip `_meta["spt-txn/token"]` before forwarding to the
   server. The server never sees, stores, or forwards the credential — this
   closes the MCP token-passthrough gap (THREAT-MODEL §4.6). The PEP holds no
   credentials that outlive a single decision.
2. **Intent match.** `intent.tool` = the `name` param of `tools/call`;
   `intent.params` = the `arguments` object; `intent.target` = the PEP's
   configured server identity. All three are bound; a token minted for one
   server MUST NOT verify at another (`target` mismatch ⇒ DENY `violation`).
3. **Fail closed.** Malformed JSON-RPC, absent token, malformed token, expired
   token, chain failure, digest mismatch, verifier error, receipt-emission
   failure — every branch resolves to a JSON-RPC error response and no
   forwarded call. Decision classes distinguish `violation` from
   `unavailable`.
4. **Single use.** Within its validity window a token is accepted at most
   once per PEP (replay cache keyed by `jti`; cache unavailable ⇒ DENY
   `unavailable`).
5. **Receipts.** Every decision — permit and deny — emits a Transaction
   Receipt (`docs/spec/RECEIPT-FORMAT.md`) before the response is returned.
   Chained per task, these are the full decision-chain audit record.

### 3.3 What this profile does not do

It does not evaluate whether the declared intent is *wise* — that is the
policy layer's job. It does not authenticate the human principal — that is
the issuance path (CAT/IdP exchange). It constrains a holder to its declared
action. State this plainly; do not overclaim.
