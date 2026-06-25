# Architecture

This POC implements a cross-domain SPT-Txn flow with a combined human-plus-agent
holder, on a single OpenBSD host running services for two simulated trust
domains.

## The two domains

Two organisations are simulated as separate services with separate keys,
configurations, and audit logs, all hosted on `foss.violetskysecurity.com`.

**Domain A — AuthOrg.** An "authorising" organisation (think: financial
institution issuing the human's identity proofing and the agent's authority).
Domain A operates:
- An identity wallet endpoint that issues SD-JWTs to verified humans.
- A CAT issuer that converts an SD-JWT into a Compliance Attestation Token
  bound to an agent's key.
- A Capability Token issuer that attenuates a CAT into a scope-limited
  Capability Token.
- A Transaction Token Service (TTS) per RFC 9700 / SPT-Txn that converts a
  Capability Token plus transaction context into an SPT-Txn Token.

**Domain B — ExecOrg.** An "executing" organisation (think: counterparty
processing the transaction the human authorised). Domain B operates:
- A reference verifier implementing the eight-step enforcement engine from
  Section 3.3.
- A resource server that decides whether to execute the transaction based on
  the verifier's decision.
- An audit log writer.

Both domains use the same shared Trust Registry for issuer key resolution.
This matches the spec: "the Trust Registry MUST be used for issuer key
lookup" (Section 8.1) — there is no normative requirement that each domain
has its own registry.

## Services on the host

Each service runs as a separate process under its own dedicated unprivileged
user, pledged to the minimum syscall set it needs.

```
relayd(8) on :443  ──┬── /a/wallet      → domain-a-wallet     (unix socket)
                     ├── /a/cat         → domain-a-cat        (unix socket)
                     ├── /a/cap         → domain-a-cap        (unix socket)
                     ├── /a/tts         → domain-a-tts        (unix socket)
                     ├── /b/verify      → domain-b-verifier   (unix socket)
                     ├── /b/execute     → domain-b-resource   (unix socket)
                     ├── /tr/lookup     → trust-registry      (unix socket)
                     └── /tr/list       → trust-registry      (unix socket)
```

Services and OpenBSD users:

| Service             | User      | Pledge set                                     |
|---------------------|-----------|------------------------------------------------|
| trust-registry      | _spttr    | `stdio rpath wpath cpath flock unix`           |
| domain-a-wallet     | _sptaw    | `stdio rpath unix inet`                        |
| domain-a-cat        | _sptaci   | `stdio rpath unix`                             |
| domain-a-cap        | _sptacp   | `stdio rpath unix`                             |
| domain-a-tts        | _sptat    | `stdio rpath unix`                             |
| domain-b-verifier   | _sptbv    | `stdio rpath unix`                             |
| domain-b-resource   | _sptbr    | `stdio rpath wpath cpath flock unix`           |
| audit-log-writer    | _sptaud   | `stdio rpath wpath cpath flock`                |

All inter-service communication is over local Unix sockets. The only thing
exposed on `:443` is `relayd`, which is itself running pledged.

## Trust Registry interface

The Trust Registry is the single source of truth for issuer keys. Its lookup
interface is format-agnostic — the same interface is used by the mock
SQLite-backed implementation and (later) the EVM chain client.

```go
// Lookup returns the active issuer record for (iss, role) or
// ErrNotFound if no current registration exists.
type Registry interface {
    Lookup(ctx context.Context, iss string, role Role) (*Record, error)
    List(ctx context.Context, role Role) ([]*Record, error)
}

type Role string

const (
    RoleCTIssuer  Role = "ct_issuer"  // signs CAT and Capability Tokens
    RoleTTSIssuer Role = "tts_issuer" // signs SPT-Txn Tokens
    RoleEscrow    Role = "escrow"     // escrow public key
    RoleEscrowReq Role = "escrow_req" // authorised escrow-request signers
)

type Record struct {
    Iss        string       // issuer identifier
    Role       Role         // capability bound to this key
    PublicKey  []byte       // raw Ed25519 (32 bytes) or X25519 for escrow
    KeyType    string       // "Ed25519" or "X25519"
    ValidFrom  time.Time
    ValidUntil time.Time
    Status     RecordStatus // active, revoked, superseded
    Metadata   map[string]string
}
```

This is the abstraction barrier. The mock implementation backs onto SQLite;
the chain implementation will back onto an EVM RPC client. Neither the
verifier nor the issuers care which is in use.

## The combined holder flow

The demo executes this sequence:

1. **Human enrolment at AuthOrg.** Sarah authenticates to Domain A's wallet
   service via an existing OIDC IdP (out of scope for POC — use a static test
   user). Domain A issues her an SD-JWT containing her identity claims plus a
   humanAnchor commitment to her zkDID. SD-JWT is signed by AuthOrg's
   CT-issuer key (registered in the Trust Registry).

2. **Agent spawn.** Sarah's wallet creates an Ed25519 keypair for her AI
   agent ("Agent-7"). She presents her SD-JWT plus the agent's public key to
   Domain A's CAT issuer.

3. **CAT issuance.** Domain A's CAT issuer:
   - Verifies the SD-JWT signature against the Trust Registry (issuer:
     Domain A, role: ct_issuer).
   - Issues a CAT bound to Agent-7's public key (`cnf` claim), with the
     humanAnchor propagated from the SD-JWT.
   - Constructs an Escrow Envelope per Section 9.6.2 (POC: single-party
     ECIES; v2: threshold).
   - Records the envelope in Domain A's escrow vault, keyed by humanAnchor.
   - Signs the CAT with the CT-issuer key.

4. **Capability Token issuance.** Agent-7 presents its CAT plus a scope
   request (`payment:initiate amount<=10000 currency=USD`) to Domain A's
   Capability issuer. Issuer verifies the CAT, attenuates the scope, signs
   the resulting Capability Token.

5. **Cross-domain transaction initiation.** Agent-7 wants to execute the
   payment at Domain B. It presents the Capability Token plus transaction
   context (`beneficiary=ExecOrg/account-X amount=5000 currency=USD
   timestamp=...`) to Domain A's TTS.

6. **TTS issues SPT-Txn Token.** Domain A's TTS:
   - Verifies the Capability Token via Trust Registry lookup.
   - Validates that the transaction context is within Capability scope.
   - Issues a short-lived SPT-Txn Token bound to: Agent-7's key (sender
     constraint via DPoP), the transaction parameters (via
     `spt_txn_context_hash`), and the originating Capability Token (via
     `spt_ct_ref`).
   - Lifetime: 30 seconds.

7. **Cross-domain verification.** Agent-7 presents the SPT-Txn Token to
   Domain B's verifier endpoint with a DPoP proof of possession. Domain B
   runs the eight-step enforcement engine:
   - Step 1: Signature verification against Trust Registry (Domain A's
     TTS-issuer key).
   - Step 2: Expiry check.
   - Step 3: Audience check (`aud` claim must match Domain B's identifier).
   - Step 4: Revocation check (registry lookup for the CT_ref).
   - Step 5: DPoP / sender-constraint verification.
   - Step 6: Capability chain verification (CAT → Capability → SPT-Txn).
   - Step 7: Scope containment check.
   - Step 8: Transaction context hash verification.
   - Returns allow / deny.

8. **Execution and audit.** If verifier allows, Domain B's resource server
   executes the (simulated) transaction and writes the result to Domain B's
   audit log. Domain A's audit log records the SPT-Txn Token issuance.
   Both audit logs publish hourly Merkle roots signed by their respective
   audit-log keys.

The Escrow Envelope from step 3 is never touched during the transaction.
Deanonymization is a separate out-of-band flow (covered in the
`docs/ESCROW-FLOW.md` doc but not part of the primary demo).

## Where the spec's Sections 3.3, 3.4, 5, 6, 7, 8, 9 actually show up

- **Section 3.3 (Eight-Step Enforcement Engine)** — implemented in
  `internal/tbac/engine.go`. Each step is a separate exported function for
  testability.
- **Section 3.4 (Scope Invariants)** — implemented in `internal/tbac/scope.go`.
  Containment check is JWT-scope-string-based for POC; Cedar interop is a
  v2 task.
- **Section 5 (ZK Circuits)** — stubbed in `internal/zk/`. The commitment
  function (Poseidon over BN254) is implemented; circuit verification is a
  TODO that always returns `true` with a logged warning.
- **Section 6 (Trust Registry)** — `internal/trustregistry/`. Mock and (v2)
  chain backends behind the `Registry` interface.
- **Section 7 (Transaction Flow)** — the demo scenario above.
- **Section 8 (Security Considerations)** — enforced through OpenBSD
  hardening: pledge/unveil, dedicated users, signify-protected keys,
  Trust-Registry-only key resolution.
- **Section 9 (Privacy / Escrow)** — `internal/escrow/`. Section 9.6.2
  envelope construction is implemented in single-party form. Section 9.6.5
  deanonymization request interface is implemented end-to-end. Section
  9.6.4 threshold authorization is stubbed (single-party).

## What's deliberately out of scope for the POC

- Real ZK proof verification (Groth16 stubbed; commitment is real).
- Threshold escrow decryption (single-party ECIES; FROST is v2).
- Chain-backed Trust Registry (mock only for v1).
- Biometric circuit execution (POC uses a static test biometric).
- Multi-host deployment (single-host two-domain simulation is sufficient
  for the demo).
- Real OIDC IdP integration at AuthOrg (use a static test user).

Each of these has a documented v2 path. None is on the critical path for
demonstrating that the SPT-Txn protocol works end-to-end as specified.
