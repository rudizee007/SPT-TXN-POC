# Build Order

The order to build services so the POC works end-to-end at each milestone.
Each milestone is independently demoable.

## Milestone 0: Foundation (Day 1, ~6 hours)

**Goal:** OpenBSD host provisioned, repo cloned, first unit tests green.

- [ ] Provision OpenBSD per [`OPENBSD-SETUP.md`](OPENBSD-SETUP.md) steps 0-8.
- [ ] Clone POC repo to `/usr/local/src/spt-txn-poc`.
- [ ] `go test ./...` runs and passes for the included skeleton.
- [ ] TLS verified: `curl -v https://foss.violetskysecurity.com/` returns
      a relayd 404 (because no service is wired up yet) but the TLS
      handshake completes against a valid Let's Encrypt cert.

**Verification:**

```sh
go test ./internal/trustregistry/...
go test ./internal/keys/...
curl -I https://foss.violetskysecurity.com/  # expect HTTP/1.1 404, valid TLS
```

**What you can demonstrate at end of M0:** a hardened OpenBSD host with TLS
serving a stub. Not yet SPT-Txn, but the platform is real.

## Milestone 1: Trust Registry (Day 2, ~6 hours)

**Goal:** A working Trust Registry service over HTTPS that responds to
issuer key lookups.

- [ ] `cmd/trust-registry/main.go` — HTTP server bound to unix socket.
- [ ] `internal/trustregistry/handlers.go` — HTTP handlers for
      `GET /tr/lookup?iss=...&role=...` and `GET /tr/list?role=...`.
- [ ] Service runs under `_spttr` user, pledged to `stdio rpath wpath cpath
      flock unix`.
- [ ] Service reads its config from `/etc/spt-txn/trust-registry.toml`.
- [ ] Service initialises SQLite database at `/var/spt-txn/tr/registry.db`
      with the schema in `internal/trustregistry/schema.sql`.
- [ ] Service writes its socket to `/var/spt-txn/sockets/trust-registry.sock`.
- [ ] `relayd` proxies `/tr/*` to the socket.
- [ ] `scripts/populate-trust-registry.sh` seeds the registry with test
      entries for Domain A's CT issuer, Domain A's TTS issuer, and Domain
      B's audit key.

**Tests:**
- Unit: `internal/trustregistry/mock_test.go` (already in skeleton).
- Integration: `tests/m1_trust_registry_test.go` — spins up the registry
  in-process, populates with test data, queries via HTTP.
- Smoke: `scripts/m1-smoke.sh` — hits the live HTTPS endpoint, checks
  responses.

**Verification:**

```sh
curl -s "https://foss.violetskysecurity.com/tr/lookup?iss=domain-a&role=ct_issuer" | jq .
# Expected: { "iss": "domain-a", "role": "ct_issuer", "public_key": "...", ... }
```

**What you can demonstrate at end of M1:** the Trust Registry interface is
working over HTTPS with real data. This is the foundation everything else
relies on.

## Milestone 2: CAT issuance (Day 3-4, ~10 hours)

**Goal:** Domain A's CAT issuer takes an SD-JWT (or for POC, a test JWT)
and issues a Compliance Attestation Token.

- [ ] `internal/token/cat.go` — CAT structure, claim set, JWT
      serialization, signing.
- [ ] `internal/token/verify.go` — verify-against-trust-registry helper.
- [ ] `cmd/domain-a-cat/main.go` — HTTP service that issues CATs.
- [ ] POST `/a/cat/issue` endpoint accepting a subject token (SD-JWT or
      test JWT) and an agent public key.
- [ ] Issuer key loaded at startup, registered in Trust Registry.
- [ ] Issued CAT signed with the registered CT-issuer key.

**Tests:**
- Unit: CAT claim construction, signature, parse roundtrip.
- Integration: full issuance flow against in-memory registry.
- Smoke: end-to-end against live host.

**Verification:**

```sh
# generate a test SD-JWT
./scripts/gen-test-sdjwt.sh > /tmp/sdjwt.txt

# generate an agent keypair
./scripts/gen-agent-key.sh > /tmp/agent.pub

# request a CAT
curl -s -X POST https://foss.violetskysecurity.com/a/cat/issue \
  -H "Content-Type: application/json" \
  -d @<(jq -n --arg sdjwt "$(cat /tmp/sdjwt.txt)" --arg pub "$(cat /tmp/agent.pub)" \
        '{subject_token: $sdjwt, agent_pubkey: $pub}') | jq .

# Expected: { "cat": "eyJhbG...", ... }
```

**What you can demonstrate at end of M2:** a real CAT issuance flow. The
SD-JWT-to-CAT binding works. Agent keys are bound via `cnf`.

## Milestone 3: Capability Token + scope attenuation (Day 5, ~6 hours)

**Goal:** Domain A's Capability issuer takes a CAT and produces a
scope-attenuated Capability Token.

- [ ] `internal/token/cap.go` — Capability Token structure, signing.
- [ ] `internal/tbac/scope.go` — scope containment check (JWT-style
      string scopes for POC).
- [ ] `cmd/domain-a-cap/main.go` — HTTP service.
- [ ] POST `/a/cap/issue` accepting a CAT and a scope request.
- [ ] Issuer verifies CAT, validates scope-request is contained, signs
      Capability Token.

**Tests:**
- Unit: scope containment edge cases (subset, equal, disjoint, overlap).
- Unit: parent-chain verification.
- Integration: CAT → Capability flow.

**Verification:**

```sh
curl -s -X POST https://foss.violetskysecurity.com/a/cap/issue \
  -H "Content-Type: application/json" \
  -d "{\"cat\": \"$CAT\", \"scope\": \"payment:initiate amount<=10000 currency=USD\"}" | jq .
```

**What you can demonstrate at end of M3:** scope attenuation works
correctly, including refusing requests that exceed the parent's scope.

## Milestone 4: SPT-Txn Token via TTS (Day 6-7, ~10 hours)

**Goal:** Domain A's TTS converts a Capability Token plus transaction
context into a short-lived SPT-Txn Token.

- [ ] `internal/token/txn.go` — SPT-Txn Token structure including
      `spt_ct_ref`, `spt_txn_context_hash`, `cnf` for sender constraint.
- [ ] `internal/dpop/dpop.go` — DPoP per RFC 9449.
- [ ] `cmd/domain-a-tts/main.go` — HTTP service implementing RFC 8693
      token exchange with `requested_token_type=...:txn_token`.
- [ ] Service binds SPT-Txn Token to specific transaction parameters
      (amount, beneficiary, timestamp).
- [ ] Lifetime: 30 seconds.

**Tests:**
- Unit: DPoP proof generation and verification.
- Unit: transaction context hashing determinism.
- Integration: Capability → SPT-Txn issuance.

**Verification:**

```sh
./scripts/m4-demo.sh
# Expected: prints CAT, Capability, SPT-Txn Token in sequence, each verified.
```

**What you can demonstrate at end of M4:** the complete issuance chain from
SD-JWT through SPT-Txn Token is working. No verifier yet, but every token
is well-formed and signature-verifiable.

## Milestone 5: Eight-step verifier (Day 8-9, ~12 hours)

**Goal:** Domain B's reference verifier implements the eight-step engine
from Section 3.3 and correctly accepts valid Txn-Tokens, rejects invalid
ones.

- [ ] `internal/tbac/engine.go` — eight-step engine. One function per step.
- [ ] `internal/tbac/engine_test.go` — per-step unit tests with golden
      vectors.
- [ ] `cmd/domain-b-verifier/main.go` — HTTP service.
- [ ] POST `/b/verify` accepts an SPT-Txn Token and DPoP proof, returns
      allow/deny with the step that decided.

**Tests:**
- Per-step golden vectors: each step has at least one passing and one
  failing test case.
- End-to-end: M4's issued token verifies cleanly at Domain B.
- Negative tests: tampered tokens, expired tokens, wrong audience,
  reused jti, scope overflow, context mismatch — each must fail at the
  correct step.

**Verification:**

```sh
./scripts/m5-demo.sh
# Expected: token issued at Domain A is verified at Domain B, returns allow.
# Then runs negative tests showing each step's failure mode.
```

**What you can demonstrate at end of M5:** the full cross-domain flow
works. A token issued by Domain A is verified by Domain B with no
out-of-band coordination beyond the shared Trust Registry. This is the
core demonstration of the SPT-Txn protocol.

## Milestone 6: Audit log + Merkle publication (Day 10, ~6 hours)

**Goal:** Both domains write to append-only audit logs with periodic
Merkle root publication.

- [ ] `internal/audit/log.go` — append-only file format.
- [ ] `internal/audit/merkle.go` — Merkle tree over log entries, root
      signing with Ed25519.
- [ ] Background goroutine in each domain's services publishes the root
      to a file under `/var/spt-txn/audit/` hourly.

**Tests:**
- Unit: log append, replay, integrity check.
- Unit: Merkle root determinism, signature verification.

**Verification:**

```sh
# After running M5 demo, check audit log
ls -la /var/spt-txn/audit/
# Expected: signed Merkle root files, hourly cadence.
```

**What you can demonstrate at end of M6:** verifiable audit trail across
both domains. Compliance teams can verify that no entries have been
modified or deleted.

## Milestone 7: Section 9.6 escrow envelope (Day 11-12, ~10 hours)

**Goal:** humanAnchor escrow envelopes are constructed at CAT issuance,
stored at the ABAC PDP, and recoverable via the deanonymization request
interface.

- [ ] `internal/escrow/envelope.go` — envelope construction per Section
      9.6.2 (single-party ECIES for POC).
- [ ] `internal/escrow/vault.go` — envelope storage keyed by humanAnchor.
- [ ] `internal/escrow/deanon.go` — deanonymization request handler with
      lawful basis verification stub.
- [ ] `cmd/escrow-vault/main.go` — separate service running as `_sptesc`
      user with the escrow private key.

**Tests:**
- Unit: envelope construct + decrypt roundtrip.
- Unit: AAD binding (humanAnchor + iss + iat) tampering detected.
- Integration: CAT issuance creates envelope, deanon request recovers
  zkDID.

**Verification:**

```sh
./scripts/m7-demo.sh
# Expected: shows envelope created at CAT issuance, then shows
# deanonymization request flow recovering the zkDID.
```

**What you can demonstrate at end of M7:** the Section 9 escrow
specification is operationally real, not just normative text.

## Milestone 8: Integration polish, demo script, recording (Day 13-14)

**Goal:** End-to-end demo runs cleanly from a single script. Documented.
Optionally recorded.

- [ ] `scripts/full-demo.sh` — runs the complete flow from human enrolment
      through cross-domain transaction execution, with prose narration
      between steps.
- [ ] `docs/DEMO-FLOW.md` updated with actual outputs.
- [ ] (Optional) asciinema recording for the IETF presentation.

## Total

14 days of focused work, 80-100 hours, to a working end-to-end POC. Can be
compressed to 10 days if you skip M6 (audit) and M7 (escrow) and demo only
the issuance + verification core, but those two milestones are exactly what
makes the demo credible against Sections 7 and 9 of the spec.

## What's NOT in any of these milestones

- Real Groth16 ZK proof generation/verification. The commitment function is
  real (Poseidon over BN254 via gnark-crypto) but the proof verification
  returns true with a logged warning. Real ZK is a v2 task.
- Real threshold cryptography for escrow. Single-party ECIES for POC,
  FROST-based threshold decryption is a v2 task.
- Chain-backed Trust Registry. Mock SQLite only. Chain is a v2 task that
  swaps the backend behind the same interface.
- Biometric circuit. POC uses a static test biometric. Real biometric
  uniqueness is a v2 task.
- Cedar policy interop (the Clawdrey OVID-ME work). The scope check uses
  JWT-style string scopes. Cedar interop is a v2 task.
- Multi-host deployment. Single host, two-domain simulation. Multi-host
  comes later when you want to demonstrate real cross-network operation.

Each "v2 task" has the interface stubbed in v1 such that the swap is
mechanical.
