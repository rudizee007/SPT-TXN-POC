---
title: "Transaction-Bound Authorization Tokens for Software and AI Agents (SPT-Txn)"
abbrev: "SPT-Txn Tokens"
docname: draft-coetzee-oauth-spt-txn-tokens-05
category: exp
ipr: trust200902
area: Security
workgroup: OAuth Working Group (individual submission)
keyword: [oauth, authorization, ai-agent, delegation, attenuation, intent-binding]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: J. Coetzee
    name: "[Author Name]"
    organization: "[Organization]"
    email: "[email]"
normative:
  RFC2119:
  RFC8174:
  RFC8785:  # JSON Canonicalization Scheme (JCS)
  RFC8693:  # OAuth 2.0 Token Exchange
  RFC7519:  # JWT
  RFC9421:  # HTTP Message Signatures (informative alt to DPoP)
  RFC9449:  # DPoP
informative:
  RFC6962:  # Certificate Transparency
  I-D.ietf-oauth-status-list:
  SPIFFE:
    title: "SPIFFE: Secure Production Identity Framework for Everyone"
    target: https://spiffe.io
  OWASP-ASI:
    title: "OWASP Top 10 for Agentic AI Applications"
    target: https://owasp.org
--- abstract

Current authorization is role-scoped: an actor is granted a role whose
authority persists across every action it takes. This fails exactly when
actors fail — under compromise, prompt injection, or goal hijacking — because a
compromised actor retains full role authority. This document specifies
SPT-Txn, a family of transaction-bound authorization tokens in which authority
exists only inside a short-lived token bound to one declared action, on one
resource, under one jurisdictional policy, verified against how the requesting
workload was attested. Delegation across agents and tools is expressed as a
cryptographically sealed chain that can only narrow authority and is verifiable
offline. Each authorization decision emits a signed, tamper-evident receipt as
a byproduct of enforcement. This revision (-05) adds normative specifications
for intent binding, transaction receipts and their transparency log, attested
issuance via OAuth 2.0 Token Exchange, per-token status-list revocation, and
cryptographic algorithm agility including hybrid post-quantum signing.

--- middle

# Introduction

An autonomous software agent that holds a role-scoped credential holds, at every
moment, the full authority of that role. When the agent is manipulated — by a
poisoned document it reads, an injected instruction in tool output, or a
compromised planning loop — that full authority is available to the attacker.
Role scoping fails precisely at the moment agents fail.

SPT-Txn inverts the model. Authority is not attached to an actor for a session;
it is minted per transaction, bound to a single declared action, and expires in
seconds. A compromised agent holds a token that is cryptographically useless for
any action other than the one it declared. This document specifies the token
family, its delegation and attenuation semantics, the binding of a token to a
declared intent, the evidence a decision emits, the issuance of tokens from
attested workload identity, per-token revocation, and algorithm agility.

## Relationship to prior versions

Versions -01 through -04 specified the base token format, the offline
verification model, and jurisdictional token-bound access control. This version
(-05) adds normative Sections {{intent-binding}} (intent binding),
{{receipts}} (transaction receipts and transparency log), {{attested-issuance}}
(attested issuance), {{status-list}} (status-list revocation), and
{{algorithm-agility}} (algorithm agility), reflecting a public reference
implementation.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

**Actor**: a human, workload, or AI agent that requests or holds authority.

**Compliance Attestation Token (CAT)**: the root authorization token for an
actor, establishing its maximum capability scope and delegation depth.

**Capability Token (CT)**: a delegated token, a strict attenuation of its
parent (a CAT or another CT).

**Transaction Token (TXN)**: a short-lived, sender-constrained token bound to a
single concrete transaction.

**Policy Enforcement Point (PEP)**: the component that verifies a presented
token against the actual request and permits or denies.

**Intent**: the declared action a token authorizes — a tool/method identifier,
a canonicalized parameter digest, and a target resource.

# Token Model {#token-model}

An SPT-Txn deployment issues three token types forming a chain of decreasing
authority: CAT (root) -> CT (zero or more delegation hops) -> TXN (leaf,
per-transaction). All are signed JSON Web Tokens {{RFC7519}}. Verification is
offline: a PEP holding the presented tokens and a locally-cached trust-registry
snapshot establishes authority without contacting the issuer.

The core claims of each token type, and the base verification steps
(signature, expiry, audience, revocation, sender constraint, chain, scope,
context binding), are specified in Sections 3 and 5 of the base document and are
unchanged here except as extended below.

# Delegation and Attenuation {#delegation}

A delegation chain is a sequence CAT -> CT_1 -> ... -> CT_n. Each hop MUST
satisfy the following invariants, all enforceable offline:

1. **Monotonic scope.** For every hop, scope(child) is contained in
   scope(parent). Scope dimensions are constraints: numeric dimensions are
   ceilings, string and boolean dimensions require equality, list dimensions
   require the subset relation, and object dimensions are contained recursively.

2. **Effective scope is the chain intersection.** A dimension present in a
   parent but absent in a child is a *constraint that the child did not
   restate*, not a relaxation. A PEP MUST evaluate a transaction against the
   intersection of every scope from the root to the leaf, inheriting a dropped
   dimension from its nearest ancestor that declares it. A hop that omits a
   ceiling therefore cannot escape that ceiling.

3. **Monotonic TTL.** exp(child) MUST NOT exceed exp(parent). An implementation
   MAY clamp a defaulted lifetime to the parent boundary but MUST reject an
   explicitly requested lifetime that would exceed it.

4. **Bounded depth.** The root declares a maximum delegation depth. Each hop
   decrements the remaining depth by exactly one. A hop at depth zero MUST be
   rejected. Absent, non-integer, or negative depth MUST be rejected.

5. **Full-chain verification.** A PEP MUST verify the entire chain from the
   root. There is no fast path for a "trusted" intermediate token. Each hop
   commits to the exact bytes of its immediate parent (a hash), so no
   validly-signed token can be spliced under a parent it was not delegated
   from.

The caveat language MUST be provably narrowing: if it can express "allow X" as
well as "deny unless X", it is unsafe and MUST be restricted. Implementations
SHOULD verify monotonicity with property-based tests over randomly generated
chains asserting that authority never widens at any hop.

# Intent Binding {#intent-binding}

A Transaction Token MAY carry an intent digest that binds the token to a single
declared action. A PEP that enforces intent binding recomputes the digest over
the actual call and compares.

## Intent structure

The declared intent is the JSON object:

~~~
{ "tool": <string>, "params": <object>, "target": <string> }
~~~

where `tool` is the tool or method identifier, `params` is the declared
parameter object, and `target` is the resource or service identity the action
executes against.

## Canonicalization {#canonicalization}

The intent digest is computed over the JSON Canonicalization Scheme
{{RFC8785}} serialization of the intent object, restricted to the accepted
subset in this section. Anything outside the subset MUST be rejected, never
normalized.

- Object member names MUST be unique. A duplicate member MUST be rejected at
  parse time (not resolved last-wins).
- Numbers MUST be integers with absolute value at most 2^53-1, expressed
  without fraction or exponent and without negative zero. Monetary amounts and
  other precise quantities MUST be represented as strings.
- Strings MUST be valid UTF-8 and MUST NOT contain U+FFFD.
- Object members are ordered by member name as sequences of UTF-16 code units,
  per {{RFC8785}}.
- Nesting depth is bounded; exceeding the bound MUST fail closed.

A single canonicalization implementation MUST be shared by the issuer path (that
computes the bound digest) and the verifier path (that recomputes it). Two
implementations will diverge over time, and a divergence is a full
authorization bypass. Implementations MUST differentially test the
canonicalizer against an independent implementation and MUST fuzz it.

## Digest and verification

~~~
intent_digest = base64url( SHA-256( "spt-txn-intent-v1" || 0x00 || JCS(intent) ) )
~~~

carried as the `spt_intent_digest` claim (base64url, unpadded). The PEP
recomputes the digest over the actual call and compares in constant time.
A mismatch MUST result in denial. A token presented to an intent-enforcing PEP
without an `spt_intent_digest` claim MUST be denied; absence never downgrades
enforcement.

Intent binding is the direct mitigation for goal hijacking (OWASP ASI01
{{OWASP-ASI}}): an agent whose reasoning is manipulated mid-task holds a token
that is cryptographically useless for the hijacked action. It does not, and
does not claim to, evaluate whether the declared intent is itself wise; that is
the policy layer's responsibility.

# Transaction Receipts and Transparency Log {#receipts}

An issuer or PEP that emits evidence MUST emit a signed Transaction Receipt at
the moment of each decision, including denials.

## Receipt format

A receipt is a JSON object with: a version string; the PEP identity; a decision
of "PERMIT" or "DENY"; a class of "ok", "violation" (a check failed), or
"unavailable" (a dependency was unreachable); the rule path that fired; the
base64url SHA-256 hash of the presented token; the hash of the policy bundle
version evaluated; the bound intent digest if any; the jurisdiction profile;
a timestamp; and a nonce. The receipt is signed with the log signing key, which
MUST be separate from the token issuance key and rotate on a separate schedule.

The signing input is `"spt-txn-receipt-v1" || 0x00 || JCS(receipt-without-sig)`,
using the same canonicalization as {{canonicalization}}. Receipts MUST NOT carry
payloads or personally identifiable information — hashes and references only.

Operators MUST be able to distinguish a "violation" (an attack) from an
"unavailable" (an outage); the two decision classes are therefore mandatory and
distinct.

## Transparency log

Receipts are appended to an append-only log whose periodic Merkle tree heads
{{RFC6962}} are signed and co-signed by at least one external witness. Any
single receipt is inclusion-provable against a signed tree head without
revealing the rest of the log. A compromised operator cannot produce a
consistent alternate history that a witness will co-sign.

If the log is unreachable, a deployment MUST decide explicitly, and document,
whether decisions proceed with a durable append-only local buffer reconciled on
reconnect, or whether log-unavailability is a fail-closed condition. This MUST
NOT default silently.

# Attested Issuance {#attested-issuance}

An issuer SHOULD issue tokens only from an attested identity, never a bearer
secret alone. Attested workload identity — SPIFFE JWT-SVID or X.509-SVID
{{SPIFFE}}, a Kubernetes projected ServiceAccount token, or a cloud
workload-identity assertion — is presented as the subject token of an OAuth 2.0
Token Exchange {{RFC8693}}. The issuer:

1. Verifies the attestation against the trust domain's keys (never the
   workload's self-report). The signature algorithm MUST be constrained to an
   allowlist; `alg: none` and unexpected algorithms MUST be rejected. Where the
   method defines an audience, it MUST be present and MUST bind the assertion to
   the exchange endpoint.
2. Computes an evidence digest
   `base64url(SHA-256("spt-txn-attest-v1" || 0x00 || evidence))` over the exact
   presented evidence, and seals it, with the attested subject and method, into
   the issued token as the `spt_attestation` claim.
3. Grants scope as the intersection of the requested scope and the policy-
   permitted scope. The requested scope is a ceiling, never an instruction.

The token's expiry MUST NOT exceed the attestation's own expiry; a token cannot
outlive the proof it was minted on. An issuer MAY enforce attestation-freshness
predicates (e.g. "actions of class X require attestation newer than D seconds").

# Status-List Revocation {#status-list}

A CAT, CT, or TXN MAY carry a `status` claim referencing an entry in a Token
Status List {{I-D.ietf-oauth-status-list}}:

~~~
"status": { "status_list": { "idx": <uint>, "uri": <string> } }
~~~

A PEP configured for status checking MUST, for every token in the chain that
carries a `status` claim, resolve the signed Status List Token for the URI from
its local cache and read the status at the index. A status of INVALID
(revoked) or SUSPENDED MUST result in denial. An unresolvable, expired, or
unsigned list, or an out-of-range index, MUST fail closed (deny). The signed
list is consumed offline; a PEP MUST NOT fetch status in the hot authorization
path. Status-list revocation complements, and does not replace, immediate
key-cascade revocation of a delegating issuer.

# Algorithm Agility {#algorithm-agility}

The signature suite identifier MUST be covered by the signature. The signing
input is `"spt-txn-env-v1" || 0x00 || suite_id || 0x00 || payload`, so forcing
a weaker suite requires forging the very signature it is trying to weaken.
Unknown suites MUST be rejected by allowlist.

A hybrid suite carrying both a classical (Ed25519) and a post-quantum (ML-DSA)
signature MUST carry both signatures; an envelope missing one MUST be rejected
as malformed in every mode, so a downgrade cannot be effected by omission. The
verification mode — accept-either (transition) or require-both (strict) — is
verifier configuration and MUST NOT be inferred from the token. A jurisdiction
profile MAY pin a minimum suite, checked before signature dispatch, so a valid
classical signature cannot pass a profile that requires hybrid.

Because transaction tokens are short-lived, algorithm migration is unusually
cheap: a token outlives its algorithm by minutes, not years.

# Security Considerations

The dominant risk classes, in likelihood order, are: (1) canonicalization
mismatch between the issuer and verifier intent-digest paths, which is a full
authorization bypass and is addressed by {{canonicalization}}; (2) attenuation
bypass via a widening caveat or isolated child validation, addressed by
{{delegation}}, in particular the chain-intersection rule; (3) algorithm
downgrade, addressed by {{algorithm-agility}}; (4) replay, addressed by
nonce binding and single-use enforcement at the PEP with a fail-closed replay
cache; (5) parser vulnerabilities, addressed by strict parsing and continuous
fuzzing; (6) revocation gaps, addressed by {{status-list}}; and (7) confused
deputy at the PEP, which MUST act strictly on the token's authority and MUST NOT
forward upstream credentials that outlive a single decision.

Every error path in the trust boundary MUST deny, with a decision class
distinguishing violation from unavailability. Deny-by-default SHOULD be a
structural property of the implementation, such that a request that has not
received a decision cannot be constructed, rather than a runtime check a
refactor can silently remove.

The system constrains an agent to its declared intent; it does not defend
against an agent that is authorized to perform a harmful action and does exactly
that, nor against a compromised issuer with signing-key access (mitigated
organizationally and detectably via the transparency log). Implementations MUST
NOT overclaim these boundaries.

# IANA Considerations

This document requests registration of the following JWT claims in the JSON Web
Token Claims registry: `spt_intent_digest`, `spt_attestation`,
`capability_scope`, `delegation_depth_max`, `delegation_depth_remaining`, and
the use of `status` per {{I-D.ietf-oauth-status-list}}. Full registration
templates will be provided in a subsequent revision.

--- back

# Acknowledgments
{:numbered="false"}

The transparency-log design follows the Certificate Transparency {{RFC6962}}
lineage. The attested-issuance profile builds on OAuth 2.0 Token Exchange
{{RFC8693}} and SPIFFE {{SPIFFE}}.
