# SPT-Txn Spec Addendum -- Binding Body-Defined Methods (QUERY / RFC 10008) at the HTTP PEP

**Status:** v0.1 draft -- addendum to `docs/spec/DELEGATION-INTENT-MCP.md` (extends
§2 Intent Binding; adds an HTTP PEP Profile parallel to §3). Normative language per
RFC 2119.
**Companion code:** `internal/intent`, `internal/jcs`, `cmd/extauthz`, `cmd/opashim`,
`cmd/grpc-extauthz`, `spt-txn-gateway`.
**Threat model:** `docs/THREAT-MODEL.md` §4.1 (canonicalization), §4.4 (replay), §4.6
(confused deputy).

---

## 1. Motivation

Intent binding (§2) binds `{tool, params, target}`. On the HTTP PEP path today the
call is shaped as `tool = HTTP method`, `params = {"path": <URL path>}`,
`target = upstream identity` (`cmd/extauthz`). That was sufficient while every method
was fully described by **method + URI**: `GET`/`DELETE` carry no security-relevant
body, and the methods that do (`POST`/`PUT`/`PATCH`) were already understood to need
body handling.

**QUERY (RFC 10008, 2026) breaks that assumption.** QUERY is a *safe, idempotent*
method -- so a naive PEP treats it like a read -- whose actual action is defined by
the **request body** (the query), not the URI. Two QUERY calls to the same path with
different bodies are different actions that are **indistinguishable** to a method+path
binding. A token minted for one QUERY therefore authorizes *any* QUERY to that path.
This is an intent-binding under-constraint (OWASP ASI01 regression): the whole point
of §2 is that a hijacked holder cannot perform an action other than the declared one.

The fix is small and self-contained, and -- done correctly -- requires **no
per-method code and no method allowlist**, so the next body-bearing method after QUERY
needs zero changes.

---

## 2. Normative amendment to the Intent construct (§2.1)

The declared-action object gains a **body digest**, and the HTTP request-target is
bound in full:

    intent = {
      "tool":   <method / tool identifier, string>,
      "params": <parameter object as declared>,
      "target": <target resource identifier, string>
    }

For the **HTTP PEP profile** (§4 below), `params` MUST be the object:

    params = {
      "path":        <URL path, string>,
      "query":       <canonical query string, string; "" if none>,
      "body_sha256": <base64url( SHA-256( raw request-body bytes ) ), no padding>
    }

### 2.1 Rules (normative)

1. **The body digest is unconditional.** `body_sha256` MUST be computed and included
   for **every** request regardless of method. An empty body binds the SHA-256 of the
   empty octet string (a fixed, known value). There is **no branch on method** and
   **no list of "methods that have a body."** A method-conditional binding is exactly
   the divergence QUERY just demonstrated (a method omitted from the list is silently
   under-bound), and is PROHIBITED. Bind the body digest always; the empty body is
   simply one specific digest.

2. **Hash the raw bytes, outside JCS.** `body_sha256` is computed over the exact
   request-body octets, before any parsing. It is then carried as a **string** inside
   `params`, so the canonical form of `params` stays inside the RFC 8785 accepted
   subset (§2.2). This is deliberate: a QUERY body may be non-JSON, or JSON containing
   floats or other constructs the JCS subset rejects (§2.2). Such a body MUST NOT be
   pushed through `internal/jcs`; only its hash -- an opaque hex/base64url string --
   is canonicalized. Content-type-agnostic by construction.

3. **Bind exactly the bytes that reach the upstream.** `body_sha256` MUST cover the
   identical octets the PEP forwards. If any component re-serializes, re-encodes, or
   re-orders the body between the digest computation and the upstream (a proxy that
   normalizes JSON, a decompressing intermediary), the binding is void. The PEP MUST
   digest the post-transform bytes it actually forwards, or forward the exact bytes it
   digested. RFC 10008 makes QUERY cacheable keyed on the request content, which
   sharpens this: the cache key, the digest, and the bytes the origin acts on must be
   the same bytes.

4. **Method is an opaque, case-sensitive token.** `tool` carries the method verb
   verbatim. It MUST NOT be case-folded, uppercased, aliased, or validated against an
   enum. Per RFC 9110 method names are case-sensitive; `query` and `QUERY` are
   distinct tokens and MUST produce distinct digests. `QUERY` therefore binds and
   verifies through the existing constant-time digest comparison with no new code --
   which is the correct outcome and the reason no allowlist may be introduced.

5. **Query string is bound.** `params.query` MUST carry the request's query component
   in a canonical form (percent-decoding normalized per RFC 3986, parameters sorted by
   name then value, applied identically issuer- and verifier-side). Binding path-only
   under-constrains both GET-with-query and QUERY, so the request-target is bound as
   path + query + body digest together.

### 2.2 Verification (extends §2.3)

Unchanged from §2.3 except that step 1 ("parse the actual call into `intent` shape")
now includes: read the request body up to the configured cap (§4.4), compute
`body_sha256` over those bytes, and populate `params` per §2.1. All other steps
(canonicalize, constant-time compare, uniform external error, absence-is-violation)
are unchanged. The body digest participates in the same single digest comparison; it
is **not** a second, separately-deletable check.

---

## 3. Format change and rollout (threat #1 discipline)

Adding `query` and `body_sha256` to `params` **changes the canonical form and the
intent digest for every request**, including previously body-less ones. This is a
canonicalization change, i.e. threat-model §4.1 territory, and is handled with the
same discipline as any token-schema change:

- **Version the intent profile.** Bump the intent profile version; do not let old and
  new digests silently coexist on the same PEP.
- **Coordinated issuer + verifier deploy.** The declaring side and the PEP MUST agree
  on the profile version. A mixed fleet fails closed (digest mismatch -> DENY
  `violation`), never open.
- **Re-run the differential canonicalizer test** across issuer and verifier paths
  after the change, and extend the golden vectors to cover body-bearing calls.

This mirrors the format-change discipline in `ASSURANCE-CLAIM-DESIGN.md` §9: cheap now
(nothing external issues these tokens yet), a hard retrofit once a third party does.

---

## 4. HTTP PEP Profile (new -- parallels §3 MCP PEP Profile)

### 4.1 Placement

The PEP is a forward-auth / `ext_authz` decision point in front of an HTTP upstream
(`cmd/extauthz`, `spt-txn-gateway`, `cmd/grpc-extauthz`, or the OPA-shim
`cmd/opashim`). Every guarded request MUST carry a valid SPT-Txn token whose intent
binding matches the request.

### 4.2 Intent mapping (normative)

| Intent field | HTTP source |
|---|---|
| `tool` | the HTTP method verb, verbatim and case-sensitive (`"GET"`, `"POST"`, `"QUERY"`, ...) |
| `params.path` | the request URL path |
| `params.query` | canonical query component (§2.1 rule 5); `""` if absent |
| `params.body_sha256` | base64url(SHA-256(raw request body)); empty-body digest if none |
| `target` | the PEP's configured upstream / server identity (a token minted for one server MUST NOT verify at another) |

### 4.3 Body capture (normative)

1. The PEP MUST have access to the request body to compute `body_sha256`. In an
   Envoy `ext_authz` deployment this requires `with_request_body` (buffered) with
   `allow_partial_message: false`; a PEP that receives a truncated body MUST fail
   closed (§4.4). The OPA-shim path (`cmd/opashim`) requires the caller to supply the
   body (or its digest) in the OPA input; if it is absent for a request that has a
   body, the shim MUST DENY.
2. The PEP MUST read the body **fully** before deciding. A streamed/chunked body that
   cannot be fully buffered within the cap is not intent-bindable and MUST be DENIED
   (fail closed) rather than bound partially.

### 4.4 Fail-closed rules (normative)

- **Oversize body.** Bodies are read under a configured byte cap. Exceeding the cap
  MUST DENY. The PEP MUST NOT bind a **truncated** body: a prefix digest would let an
  attacker append arbitrary trailing content that the origin still acts on. (Existing
  precedent: `cmd/opashim` already denies on body oversize.)
- **Missing/unreadable body** for a request that carries one -> DENY.
- **Every other branch** -- absent/malformed/expired token, chain failure, digest
  mismatch, verifier error, receipt-emission failure -- resolves to an HTTP 403 (or
  the ext_authz deny response) with no forwarded call, exactly as §3.2 rule 3. Classes
  distinguish `violation` from `unavailable`; the failing check stays in the receipt,
  never on the wire.

### 4.5 Credential handling, single-use, receipts

Unchanged from §3.2 rules 1, 4, 5: strip the token before forwarding upstream (the
upstream never sees the credential -- `cmd/extauthz` already sets
`x-envoy-auth-headers-to-remove`); enforce single-use per PEP keyed by `jti` (replay
cache unavailable -> DENY `unavailable`); emit a Transaction Receipt for every
decision, permit and deny, before the response is returned. The receipt SHOULD record
`body_sha256` so the audit trail proves *which* body was authorized.

### 4.6 What this profile does not do

It constrains a holder to its declared HTTP action (method + path + query + body). It
does not evaluate whether the query is *wise* (policy layer), does not authenticate
the human principal (issuance path), and does not inspect body *semantics* -- it binds
the body's bytes, not their meaning. State this plainly; do not overclaim.

---

## 5. Policy guidance (issuance)

The intent digest binds the method cryptographically, so a token scoped for
`GET`+path is already useless for `QUERY`+path (distinct `tool` -> distinct digest ->
DENY `violation`). Additionally, the **issuance** policy (what a CAT/CT will mint
authority for) MUST enumerate permitted methods explicitly. A policy written as "allow
on this route" MUST NOT implicitly authorize QUERY; a new method requires a deliberate
allow, never an inherited one. This keeps the arrival of a new HTTP method a policy
decision, not a silent expansion of authority.

---

## 6. Tests (normative)

The intent path is trust-boundary code (CLAUDE.md §5): spec-first (this note),
implement, **adversarial review in a fresh context** ("assume this body binding can be
bypassed -- find it"), property tests, human line-by-line. Required tests:

1. **Body differential.** Same method + path + query, two different bodies -> two
   distinct intent digests; a token bound to body A DENIES a request with body B.
2. **Empty-body uniformity.** A body-less request binds the empty-body digest
   identically at declaration and verification (single rule, no method branch); assert
   issuer and verifier agree byte-for-byte.
3. **New-method transparency.** `QUERY` binds and matches through the existing digest
   path with no method-specific code; a token scoped `QUERY`+path+query+bodyhash
   permits exactly that request and DENIES `GET`/`POST`/a different body/a different
   path/a different query.
4. **Case-sensitivity.** `query`, `Query`, `QUERY` yield distinct digests; a `QUERY`
   token DENIES a `query` request (fail closed). Assert no code path case-folds the
   method.
5. **No-allowlist regression.** Assert (grep-level and property-level) that no method
   enum or "has-body" method list gates binding; an arbitrary unknown method string
   round-trips bind -> match unchanged.
6. **Non-JCS body.** A body that is not JCS-acceptable (non-JSON, or JSON with floats)
   still binds via `body_sha256` over raw bytes and does NOT trigger a canonicalization
   DENY for a well-formed declared call -- proving the hash-outside-JCS design.
7. **Truncation / oversize.** A body exceeding the cap DENIES and is never bound as a
   prefix; a request whose forwarded bytes differ from the digested bytes DENIES.
8. **Query canonicalization differential.** Reordered/re-encoded but semantically
   identical query strings produce identical `params.query`; distinct queries produce
   distinct digests (fuzz both directions, per §2.2 golden-vector discipline).

---

## 7. Wiring changes (concrete)

- **`cmd/extauthz/main.go`** -- replace
  `Params: []byte(fmt.Sprintf(`{"path":%q}`, r.URL.Path))` with the §4.2 object:
  `path` + canonical `query` + `body_sha256` computed over the fully-read, size-capped
  request body (fail closed on oversize/unreadable/truncated). `Tool: r.Method`
  is retained unchanged (already correct and opaque).
- **`spt-txn-gateway`** -- `extract()` already carries `HTU` (full request-target via
  `X-Forwarded-Uri`); add the body-digest input on the same path and route it into the
  intent params the decision consumes. Requires the fronting proxy to deliver the body
  (Envoy `with_request_body`).
- **`cmd/opashim/main.go`** / OPA integration -- require the caller to supply
  `body_sha256` (or the raw body to hash) in `req.Input`; a request with a body but no
  body digest MUST DENY. Document the Envoy config that populates it.
- **`internal/intent`** -- no change to `Intent{tool, params, target}` or `Digest()`:
  the body binding is entirely a matter of how the HTTP PEPs populate `params`. The
  core stays a single shared implementation; the profile lives at the edge. (If a
  typed HTTP params helper is added for consistency across the four PEPs, it is a
  Sonnet-tier convenience, not a change to the trust-boundary digest.)

---

## 8. Summary

QUERY is the first HTTP method that is safe/idempotent yet body-defined. The intent
mechanism already supports body-defined actions (it digests `params`); the only gap is
that the HTTP PEPs populate `params` from method + path and drop the body. Binding a
digest of the raw body -- unconditionally, hashed outside JCS, over exactly the
forwarded bytes -- closes it, keeps every existing method working unchanged, and makes
the *next* new method a non-event. The cost is a one-time intent-profile version bump
handled with the standard canonicalization-change discipline.
