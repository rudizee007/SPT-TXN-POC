# SPT-Txn — Privacy-Preserving Compliance & Travel Rule Authorization (Reference POC)

[![CI](https://github.com/rudizee007/SPT-TXN-POC/actions/workflows/ci.yml/badge.svg)](https://github.com/rudizee007/SPT-TXN-POC/actions/workflows/ci.yml)
&nbsp;Apache-2.0 · Go 1.25 / gnark v0.15 · OpenBSD · live demo: <https://foss.violetskysecurity.com>

SPT-Txn verifies compliance **once** and proves it **everywhere**, in zero
knowledge — so regulated institutions and VASPs can transact, tokenise, and settle
on-chain without exposing PII. A user holds a **Compliance Attestation Token
(CAT)** (a W3C Verifiable Credential bound to a zero-knowledge identity commitment,
**zkDID/humanAnchor**); a platform checks a ZK proof of the CAT against a policy and
issues a scope-bounded **Capability Token (CT)**; each action emits a
transaction-bound **SPT-Txn token**. For inter-VASP transfers it carries a
payload-level **FATF Travel Rule** ZK attestation. No PII on the wire; no native
token; blockchain-agnostic (XRPL is the primary integration target).

> **Status: working, security-audited reference implementation** — not a skeleton,
> and not yet production. Deployed and running on a hardened OpenBSD host with a
> live two-party Travel Rule demo. Ten chain adapters; attestation-anchor contracts
> live on four public testnets; an **on-chain ZK verifier** live on two L2s; the
> agentic delegation layer is **POC-built, tested, and now provable in zero
> knowledge**. See [`docs/STATUS`](docs/STATUS.md) for the current-state map,
> [`docs/RUNBOOK.md`](docs/RUNBOOK.md) to reproduce the deployments, and the roadmap
> below for what production still needs.

## What's built and running

- **Real zero-knowledge** — Groth16/BN254 circuits (identity commitment,
  amount-over-threshold, VASP membership), **not stubs**. Hash migrated MiMC →
  **Poseidon2** (benchmarked: −44 % constraints, −41 % prove). `internal/zkproof`,
  `internal/zkhash`, `cmd/zk-setup`, `cmd/zk-bench`.
- **Live FATF Travel Rule** — IVMS101 + selective-disclosure SD-JWT + the three ZK
  predicates, carried over the OpenVASP **Travel Rule Protocol (TRP)** between two
  **separate VASP services** (originator proves, beneficiary verifies with the
  verifying key only). Cleartext-only transfers refused. `internal/travelrule`,
  `internal/trp`, `internal/ivms101`, `internal/vaspregistry`, `cmd/tr-svc`.
- **The token chain** — CAT → CT → SPT-Txn with scope attenuation, bounded
  delegation depth, immutable humanAnchor, 30 s transaction-bound tokens, DPoP
  sender-constraint, and the eight-step offline enforcement engine.
- **Security by design (OpenBSD)** — real `pledge(2)`/`unveil(2)` sandboxing,
  privilege separation, relayd TLS, signify keys; a host-runnable audit at
  **FAIL=0** (`scripts/security-audit.sh`). See `docs/SECURITY-REVIEW.md`.
- **Audit log** with hash-chain + signed Merkle roots; **escrow** envelope for
  lawful deanonymization.
- **EO-14409 ready** — a CycloneDX **Cryptographic Bill of Materials**
  (`docs/cbom.json`, `docs/CBOM.md`) and a lifetime-triaged hybrid post-quantum
  migration plan.
- **Blockchain-agnostic, multi-chain** — one `Ledger` adapter interface binds an
  authorization to a transaction across **ten chains** (XRPL, Hedera, Solana,
  Stellar, Starknet, Aptos, Ethereum, XDC, Algorand, Arbitrum), all tested.
  `internal/ledger`. Chains are integration targets, never dependencies.
- **Live on-chain footprints** — attestation-anchor contracts on Ethereum Sepolia,
  Starknet Sepolia, Aptos testnet, and Arbitrum Sepolia (plus a Solana devnet memo
  anchor), each holding a genuine token-derived `ContextHash`. `cairo/`, `move/`,
  `solidity/`, `cmd/anchor`.
- **On-chain ZK verification** — a gnark Groth16 verifier + `AttestationVerifier`
  wrapper verify a selective-disclosure proof (amount ≥ threshold, amount hidden)
  **on-chain** and anchor only if it checks out — live on Ethereum and Arbitrum
  Sepolia. `cmd/zk-export-solidity`, `cmd/zk-solcalldata`, `solidity/src/`.
- **Agentic authorization (POC-tested) + ZK chain proof** — multi-hop CT→CT
  delegation, an offline N-hop verifier, a granular revocation cascade, and a
  Groth16 `ChainCircuit` that proves a delegation chain valid (attenuation, depth,
  human-anchor) **without revealing intermediate scopes**, with an opt-in,
  gnark-free verifier seam. `internal/cttoken`, `internal/verifier`,
  `internal/zkproof`, `cmd/agentdemo`, `cmd/agentsvc`.
- **Scoped-disclosure SDK + schema** — a request → consent → response protocol for
  time-limited, scope-selected selective disclosure (discloses only requested ∩
  consented). `internal/disclosure`, `docs/DISCLOSURE-SCHEMA.md`.

## Documentation

- [`docs/REVIEWER-BRIEF.md`](docs/REVIEWER-BRIEF.md) — **start here**: one-page brief leading with what's real (live footprints, on-chain ZK, F1 closed, live Travel Rule) and the honest boundaries.
- [`docs/DEMO.md`](docs/DEMO.md) — reproduce it in minutes: the suite, ZK metrics, agentic demo, anchoring, the x402 gate, live endpoints + footprints.
- [`docs/STATUS.md`](docs/STATUS.md) — current-state map: every component, where it lives, live on-chain addresses, ZK metrics, how to build/test.
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) — reproducible ops: ZK setup, deploy contracts to a chain, generate + verify an on-chain proof, website deploy.
- [`docs/BUILD-JOURNAL.md`](docs/BUILD-JOURNAL.md) — chronological build log + the key engineering decisions and their rationale.
- [`docs/ZK-ONCHAIN-AND-AGENTIC-PLAN.md`](docs/ZK-ONCHAIN-AND-AGENTIC-PLAN.md) — on-chain ZK verifier + agentic ZK chain proof design (built) and metrics.
- [`docs/DISCLOSURE-SCHEMA.md`](docs/DISCLOSURE-SCHEMA.md) — the language-agnostic scoped-disclosure request/response schema.
- [`docs/WORKING-PAPER-v2.md`](docs/WORKING-PAPER-v2.md) — the framework paper
  (architecture, zkDID, zkDNS + alternatives, measured crypto, PQ, Travel Rule).
- [`docs/GLOSSARY.md`](docs/GLOSSARY.md) — **authoritative** terminology + the
  CAT/attribute model + standards mapping.
- [`docs/CBOM.md`](docs/CBOM.md) / [`docs/cbom.json`](docs/cbom.json) — Cryptographic Bill of Materials.
- [`docs/ZK-CIRCUIT-SPEC.md`](docs/ZK-CIRCUIT-SPEC.md) — auditor-facing spec of every circuit (inputs, constraints, soundness arguments) to de-risk an independent ZK audit.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — STRIDE + LINDDUN threat model with mitigations and residual risks.
- [`docs/SCALING-AND-SUBSTRATE.md`](docs/SCALING-AND-SUBSTRATE.md) — how it scales beyond one host (stateless verifier / per-participant issuer / off-hot-path registry) + the storage-substrate decision (on-chain Merkle root + signed Go snapshots; DWN as inspiration only).
- [`docs/PLATFORM-AND-OSS-STRATEGY.md`](docs/PLATFORM-AND-OSS-STRATEGY.md) — open-source posture, OpenBSD vs FIPS-140-3 hardened Linux (portable-Go migration; Go FIPS mode), and the OSS scaling stack for high request volumes.
- [`docs/INTEGRATION-READINESS-CHECKLIST.md`](docs/INTEGRATION-READINESS-CHECKLIST.md) — what an L1/L2 or VASP requires before integrating (security/TPRM, Travel Rule interop, technical, crypto, legal) with SPT-Txn's honest current status against each.
- [`docs/INTEGRATION-SCORECARD.md`](docs/INTEGRATION-SCORECARD.md) — one-page Differentiator/Meets/Gap scorecard for a partner conversation.
- [`docs/VASP-SECURITY-QUESTIONNAIRE.md`](docs/VASP-SECURITY-QUESTIONNAIRE.md) — pre-filled SIG/CAIQ-style answers (incl. the embedded-library "not a data processor → N/A" framing).
- [`docs/conformance-vectors.json`](docs/conformance-vectors.json) — deterministic conformance vectors (per-chain context hash, humanAnchor); regenerate/check with `cmd/conformance`. Independently verify an audit log with `cmd/auditverify`.
- [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md) — full security review (FAIL=0; roadmap items noted); [`docs/SECURITY-REVIEW-2026-06-28.md`](docs/SECURITY-REVIEW-2026-06-28.md) — review of the new surface (adapters, contracts, ZK chain, verifier seam); [`docs/SECURITY-REVIEW-2026-06-28-extended.md`](docs/SECURITY-REVIEW-2026-06-28-extended.md) — extended surface (Sui Move anchor, Hedera HCS/DID, more adapters, x402 gate).
- [`docs/TRP-TRISA-INTEROP.md`](docs/TRP-TRISA-INTEROP.md) — Travel Rule transport + TRISA bridge design.
- [`docs/V2-TOPICS-CHECKLIST.md`](docs/V2-TOPICS-CHECKLIST.md) / [`docs/V2-RESEARCH-NOTES.md`](docs/V2-RESEARCH-NOTES.md) — v2 coverage + research.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/OPENBSD-SETUP.md`](docs/OPENBSD-SETUP.md) — design + provisioning (some sections predate the current deployment).

## Repository layout

`cmd/` services + tools (tr-svc, agentsvc, catsvc, trsvc, agentdemo, anchor,
zk-setup, zk-export-solidity, zk-solcalldata, zk-bench, regkey, mksubject) ·
`internal/` libraries (ledger, zkproof, zkhash, zkdid, disclosure, travelrule,
trp, ivms101, vaspregistry, sdjwt, dpop, escrow, verifier, trustregistry,
cattoken, cttoken, txntoken, tbac, …) · `cairo/`, `move/`, `solidity/` (on-chain
attestation-anchor + ZK verifier contracts) · `docs/` · `scripts/`
(security-audit, rc services, register-issuers) · `configs/` · `web/` (the
foss.violetskysecurity.com site source).

## Standards & links

Terminology anchors to W3C Verifiable Credentials / DID Core, SD-JWT, OAuth
Transaction Tokens (`draft-coetzee-oauth-spt-txn-tokens`), DPoP (RFC 9449), NIST SP
800-207/162, FIPS 203/204, FATF Rec 16 / IVMS101. Live: <https://foss.violetskysecurity.com>.
Preprints: Zenodo `10.5281/zenodo.20870193` (framework paper v2), `10.5281/zenodo.19299787` (theory), `10.5281/zenodo.18917439` (framework v1).

## Build & test

Go 1.25+, gnark v0.15. The reference deployment runs on OpenBSD; the Go code is
OS-portable (the pledge/unveil layer is behind build tags, with a no-op for
non-OpenBSD). `go build ./...`; `go test ./internal/...`. ZK setup writes circuit
keys via `cmd/zk-setup`.

## Roadmap (honest)

Not production-ready. Agentic AI authorization is now **POC-built and tested**
(multi-hop delegation, offline N-hop verification, granular revocation cascade)
and **provable in zero knowledge** (the `ChainCircuit`), but not battle-tested at
scale. Honest gaps that remain: in the **opt-in ZK chain mode**, intermediate-hop
issuer **signatures are not verified in-circuit** (only scope/depth are — the
cleartext mode verifies every hop's signature, so it remains the stronger default;
see the security review); **on-chain footprints are testnet** (mainnet anchoring +
the on-chain ZK verifier on mainnet are the next step); the open append-only
anchor contracts would want access control or a fee on mainnet; biometric
uniqueness is a placeholder; the `.zkdid`/`.zkdns` production identity/naming layer
is an integration (interim works today); hybrid PQ key migration is designed, not
implemented; and an **independent ZK-circuit + protocol audit** is wanted (the
Arbitrum Audit Fund can subsidize). See [`docs/STATUS.md`](docs/STATUS.md) and the
grant docs for the funded plan.

## License

Apache-2.0 (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). All dependencies are
permissive (Apache-2.0 / BSD / MIT / ISC); no copyleft. Copyright 2026 Rudolf J.
Coetzee / Violet Sky Security SEZC.
