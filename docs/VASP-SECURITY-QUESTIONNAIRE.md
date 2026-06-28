# VASP / counterparty security-questionnaire — response template

Pre-filled answers to the standard vendor security questionnaire (SIG / CAIQ /
DORA-style) a VASP or chain foundation will send. Answers are **honest about
current state** — overclaiming is a diligence risk. Fill the bracketed bits per
engagement. Legend: **✅ yes** · **◐ partial** · **○ not yet** · **N/A** (out of
scope for the chosen deployment model — see §0).

## 0. Read this first — engagement model determines scope

The single most important framing, and it shrinks most of this questionnaire:

> **SPT-Txn's verifier is an offline, stateless library, and issuers are
> per-participant. In the recommended deployment you embed the open-source
> (Apache-2.0) verifier inside your own infrastructure and run your own issuer —
> SPT-Txn (the vendor) receives, stores, and processes none of your data.**

Consequence: in the embedded model, SPT-Txn is **not a data processor / sub-
processor**. Questions about *our* data residency, *our* hosted SOC 2 boundary,
*our* breach notification for *your* data, and *our* sub-processors are **N/A** —
that scope is yours, on your infrastructure. Confirm the model first; the answers
below assume the embedded model and flag where a *hosted* option would change them.

## 1. Company & governance

- **Legal entity / jurisdiction?** Violet Sky Security SEZC (Cayman Islands).
- **Primary contact?** rudi@violetskysecurity.com.
- **Team size / key personnel?** Solo developer/founder (secure-systems / CISO
  background; author of the IETF draft + preprints). ○ Stated plainly — staffing
  scales with adoption/funding.
- **Is the product open source?** ✅ Apache-2.0 core (auditable by you, no vendor
  lock-in). Public repo + IETF Internet-Draft + Zenodo preprints.

## 2. Data handling & privacy

- **What customer/PII data do you store or process?** ✅ In the embedded model,
  **none** — verification is local to you; issuers are yours. SPT-Txn's design
  keeps **no PII on-ledger** (only hashes / hiding ZK commitments).
- **How is PII minimized in the Travel Rule flow?** ✅ Selective-disclosure
  SD-JWT reveals only the FATF-required fields; everything else is proven in zero
  knowledge (amount hidden, counterparty-VASP hidden). Stronger than encrypt-in-
  transit, which still delivers full PII to the counterparty.
- **GDPR / MiCA / DORA alignment?** ◐ Data-minimisation by design (no PII on
  ledger; ZK disclosure). A formal DPA is provided **only if** a hosted option is
  used (N/A for embedded).
- **Data residency?** N/A (embedded) — data stays in your environment.

## 3. Cryptography

- **Algorithms?** Ed25519 (FIPS 186-5 approved), SHA-256, Groth16/BN254 with
  Poseidon2; Baby Jubjub EdDSA for in-circuit signatures.
- **Is cryptography FIPS 140-3 validated?** ◐ Application crypto runs in the
  **FIPS 140-3-validated Go Cryptographic Module** (build flag); a full-system
  FIPS Linux profile is available on request. See `docs/PLATFORM-AND-OSS-STRATEGY.md`
  §2a for the exact boundary (app module / TLS / OS). We do **not** claim the
  whole OS is FIPS unless deployed on the FIPS Linux profile.
- **Post-quantum readiness?** ✅ Lifetime-triaged hybrid-PQ migration plan +
  CycloneDX CBOM (EO-14409-aligned).
- **Key management?** ◐ Signing keys are file-perm-protected today; production
  HSM/KMS (PKCS#11) + threshold/MPC is the documented hardening milestone.

## 4. Application security & SDLC

- **Secure development lifecycle?** ◐ Version control, CI (vet/build/test),
  code + security reviews, a published threat model (STRIDE/LINDDUN).
- **Dependency / supply-chain risk?** ✅ Deliberately dependency-light **pure Go**
  (no cgo); CBOM published; SBOM generable from Go modules on request.
- **Memory safety?** ✅ Go (memory-safe); the on-chain contracts are
  audited-scope Solidity/Cairo/Move.

## 5. Vulnerability management & testing

- **Penetration testing?** ◐ Host security audit at **FAIL=0**; **fuzz testing**
  (millions of executions, fails-closed) of the canonical encoder and the
  eight-step verifier; adversarial test suite. No third-party pen test yet (○ —
  scales with engagement).
- **Independent security / cryptography audit?** ○ **Requested, not self-
  certified** — an independent ZK-circuit + protocol audit is the top roadmap
  item; an auditor-ready circuit spec (`docs/ZK-CIRCUIT-SPEC.md`) is prepared.
- **Vulnerability disclosure?** ◐ Public repo issues; a formal VDP/SLA is a
  maturity step.

## 6. Infrastructure, access & resilience

- **Hosting / OS?** OpenBSD (pledge/unveil sandboxing, privsep, relayd TLS) for
  the reference POC; a hardened/FIPS Linux profile for regulated deployments. In
  the embedded model this is **your** infrastructure.
- **Access control / least privilege?** ✅ Per-service `_spt*` users, no-login
  shells, socket-only admin endpoints, OpenBSD privilege separation.
- **Availability / SLA / BCP-DR?** ○ One host today; the scaling model
  (stateless replicas / embedded library, on-chain-anchored signed-snapshot
  registry) is documented (`docs/SCALING-AND-SUBSTRATE.md`). No SLA at POC stage.
- **Incident response?** ○ Not formalized (solo) — a maturity/funding step.

## 7. Compliance & certifications

- **SOC 2 Type II?** ○ Not yet. **ISO 27001?** ○ Not yet. (Both are funded
  maturity steps; in the embedded model your own SOC 2 boundary is what governs
  *your* deployment.)
- **Audit trail?** ✅ Hash-chained, signed-Merkle-root audit log; independently
  re-verifiable with `cmd/auditverify` (keyless) and anchorable on-chain.

## 8. Travel Rule specifics

- **IVMS101?** ✅ Implemented. **Protocols?** ◐ **TRP transport live**
  (two-party, cleartext-only refused); **TRISA payload bridge implemented**
  (`internal/trisa`), sealed gRPC transport scoped as a separate module;
  OpenVASP-aligned. (2026 reality: a primary + a bridge for counterparty coverage
  — that is the trajectory here.)
- **Where is Travel Rule data captured?** Upstream, at the CAT issuer / your KYC
  pipeline (IVMS101 fields captured at onboarding); SPT-Txn *carries* them
  privacy-preservingly. Flag: the upstream pipeline must capture the fields.

## 9. Sub-processors

- **List sub-processors with access to our data.** **None** in the embedded model
  (no data leaves your environment). A hosted option would enumerate any here.

---

**Bottom line to convey:** strong exactly where it's hard to fake (architecture,
real ZK, privacy-preserving Travel Rule, multi-chain, open source, no-PII-on-
ledger) and honest about the formal-assurance items (SOC 2 / ISO / pen test /
independent audit / SLA) that a first partner + funding are meant to complete —
and in the embedded model, much of the questionnaire is simply **N/A because we
never hold your data.**
