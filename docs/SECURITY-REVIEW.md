# SPT-Txn POC — Security Review

A full read of every service (`cmd/`), the OpenBSD integration layer, and the
`internal/` libraries, with adversarial testing and a repeatable host audit
(`scripts/security-audit.sh`). This document records each finding **and its
current, verified status.**

## Current status (2026-06-25)

**All Critical and High findings are resolved.** The repeatable host audit reports
**FAIL=0**, and the key controls are verified live (e.g. `/cat/issue` → 401 without
a valid subject token; `/tr/register` → 404 at the edge; token+proof replay denied
at enforcement step 5). The remaining items are **deferred roadmap** — documented,
bounded, and not exploitable gaps in the POC threat model (key encryption-at-rest,
threshold escrow, and an independent external audit). Trust Registry persistence
(M7), previously deferred, is now **fixed** — see below.

Status shown as **original finding → current state** so the remediation trail is
explicit.

| ID | Severity | Finding | Original → Current |
|----|----------|---------|--------------------|
| C1 | Critical | Unauthenticated trust-registry registration | `[OPEN]` → ✅ **FIXED** (verified live) |
| C2 | Critical | Degenerate all-zero keys accepted | `[OPEN]` → ✅ **FIXED** |
| C3 | Critical | Unauthenticated CAT issuance oracle | `[OPEN]` → ✅ **FIXED** (verified live) |
| C4 | Critical | pledge/unveil were no-ops (sandbox inert) | `[OPEN]` → ✅ **FIXED** |
| H1 | High | DPoP / token replay | `[OPEN]` → ✅ **FIXED** |
| H2 | High | Revocation decided on unverified issuer | `[OPEN]` → ✅ **FIXED** |
| H3 | High | Verifier trusted issuance (scope/depth/holder) | `[OPEN]` → ✅ **FIXED** |
| H4 | High | Signing keys unencrypted at rest | `[OPEN]` → ⚠️ **MITIGATED** · encryption-at-rest `[DEFERRED]` |
| H5 | High | Signify loader didn't validate KDF/checksum | `[OPEN]` → ✅ **FIXED** |
| M1 | Medium | JWT `alg`/`typ` unvalidated | `[OPEN]` → ✅ **FIXED** |
| M2 | Medium | Amount precision (float64) | `[PARTIAL]` → ✅ **FIXED** |
| M3 | Medium | Deanonymization request freshness | `[OPEN]` → ✅ **FIXED** |
| M5 | Medium | No request body size limits | `[OPEN]` → ✅ **FIXED** |
| M6 | Medium | Service user / key-permission drift | `[OPEN]` → ✅ **FIXED** |
| M7 | Medium | Trust Registry resets to revoked on restart | `[NEW]` → ✅ **FIXED** (file-backed persistent registry) |
| L2 | Low | Registry client ignored key status | `[OPEN]` → ✅ **FIXED** |

## Resolved findings — how

**C1 — Unauthenticated trust-registry registration.** Registration is served only on
a dedicated admin Unix socket (`tr-admin.sock`, mode 0600, owner-only); the
relayd-facing TCP listener is a read-only mux. The registrar rejects non-32-byte,
all-zero, and invalid-role keys. Verified: `/tr/register` via relayd → 404, and
`relayd.conf` forwards `/tr/*` to `127.0.0.1:8081`, not to any socket.

**C2 — Degenerate all-zero keys.** `verifier.resolveKey` and the registrar reject
all-zero public keys; registry seeds are `revoked` placeholders, never active.

**C3 — Unauthenticated CAT issuance oracle.** `/cat/issue` now requires a subject
token signed by a registered wallet key, verified before signing. Live: no token →
401, valid token → 200. `cmd/mksubject` generates wallet tokens for testing.

**C4 — Inert sandbox.** Real `pledge(2)`/`unveil(2)` via `golang.org/x/sys/unix` on
every service, tuned per service and tested on the host (a pledge violation is
fatal). `catsvc` additionally `unveil`s to only its key path; `tr-svc` confines to
the ZK key directory, with the `dns` promise only for the outbound (originator) role.

**H1 — DPoP/token replay.** Single-use `jti` cache + `ath` token-binding in the
verifier; a captured `{token, DPoP proof}` is denied at enforcement step 5.

**H2/H3 — Verifier no longer trusts issuance.** The eight-step engine re-derives the
decision: it does not act on an unverified issuer, and re-enforces CAP⊆CAT scope
monotonicity, delegation-depth bounds, and holder-key binding.

**H5 — Signify loader validation.** `loadSignifyKey` now rejects passphrase-encrypted
keys (`kdfrounds != 0`) and verifies the embedded checksum (first 8 bytes of
SHA-512 over the secret key) before use, so a corrupted or wrong key is rejected
rather than silently used. Fixed and deployed. **Scope check:** `catsvc` is the only
service that loads a signify *secret* key; `trsvc` is a lookup/registrar service
that holds no signing key, and `tr-svc` uses a hex-encoded (non-signify) SD-JWT
key — so there is no parallel loader to harden.

**M1** — `alg` pinned (`EdDSA`) and headers validated across all four JWT verifiers
(adversarially tested for `alg:none`/confusion). **M2** — amounts compared with
exact `big.Rat` carrying `json.Number`, with a 2⁵³+1 precision test. **M3** —
deanonymization requests have a freshness window + replay guard. **M5** — request
bodies capped (64 KiB) on `catsvc` and `trsvc`. **M6** — the deployment runs each
service under a dedicated user with its key readable by exactly that user
(`ct-issuer.sec` is `0400 _sptaw`, the catsvc user). **L2** — the registry client
decodes and carries record `Status`.

## Confirmed sound (positive results)

ZK public-input handling (the verifier supplies public inputs; they are not trusted
from the proof); escrow envelope (fresh ephemeral X25519 per seal, random nonce, AAD
binds `anchor|iss|iat`); ledger canonicalization (separator-byte injection blocked,
extras sorted); audit hash-chain + signed Merkle roots; SD-JWT forged-disclosure
rejection. Adversarial tests cover alg-confusion, zero-key, forged over-scoped CAP,
negative amounts, and cross-domain audience.

## Deferred to v2 / grant scope (documented; not POC threat-model gaps)

- **H4 — Key encryption-at-rest.** `*.sec` keys are `0400/0600` and `unveil`-confined
  (a compromised service reads only its own key — blast radius already cut), but
  unencrypted on disk. Options, cheapest first: OpenBSD `softraid` full-disk
  encryption (one passphrase/keydisk at boot — best ROI; Linux equivalent: LUKS +
  TPM2); HSM/TPM-sealed key wrapping; or threshold (FROST) so no single host holds a
  whole signing key. Tied to the production-OS decision.
- **M7 — Trust Registry persistence. FIXED.** Previously the in-memory mock registry
  seeded revoked placeholders on start and did not persist real registrations, so a
  `trsvc` restart silently reverted issuers to "revoked" and fail-closed services
  refused to start. `trsvc` now uses `trustregistry.PersistentRegistry` — a pure-Go,
  file-backed store (atomic write-temp-then-rename, mode 0600, no CGo, pledge-safe)
  at `SPT_TR_DB` (default `/var/spt-txn/tr/registry.db`). Real registrations are
  durable across restarts; `seedIfEmpty` is a no-op on a non-empty store, so an issuer
  is never silently re-revoked. Regression tests in
  `internal/trustregistry/persist_test.go` (survive-restart, revoke-persists,
  corrupt-file-surfaced). `scripts/register-issuers.sh` is now only needed **once**,
  right after upgrading to this build (to populate the keys the first time). A
  chain-backed registry remains the v2 target.
- **Threshold (FROST) escrow decryption; chain-backed Trust Registry; an independent
  ZK-circuit + protocol audit** (grant-funded, by a reputable firm).

## Methodology & reproducibility

Findings were derived from a line-by-line source read plus adversarial unit tests
and a host-state audit. `scripts/security-audit.sh` re-verifies the live host
(OS patch level, pf, listeners, edge exposure, pledge-in-source, key permissions,
registry contents, doas/sshd) and is the basis for the FAIL=0 claim; it can be
re-run by any reviewer with host access.
