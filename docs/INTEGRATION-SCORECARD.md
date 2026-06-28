# SPT-Txn — integration scorecard (one page)

How SPT-Txn maps to a VASP / L1 / L2 evaluation, scored honestly. Detail +
remediation in [INTEGRATION-READINESS-CHECKLIST.md](INTEGRATION-READINESS-CHECKLIST.md);
questionnaire answers in [VASP-SECURITY-QUESTIONNAIRE.md](VASP-SECURITY-QUESTIONNAIRE.md).

**Rating:** 🟢 differentiator (we win) · 🔵 meets bar · 🟡 partial · 🔴 gap.

| Area | Rating | One-line status |
|---|---|---|
| Privacy-preserving Travel Rule (ZK, amount hidden, no PII on-ledger) | 🟢 | SD-JWT + 3 Groth16 proofs over TRP; stronger than encrypt-in-transit |
| Real zero-knowledge (F1 closed: in-circuit issuer signatures) | 🟢 | Groth16/BN254, Poseidon2, ~1 ms verify, 164 B |
| Multi-chain neutrality | 🟢 | 15 adapters, one interface; chain is anchor, not dependency |
| Open source (Apache-2.0) | 🟢 | Auditable, no lock-in; embed-don't-host model |
| Offline / embeddable verifier (not a data processor) | 🟢 | Shrinks the whole TPRM surface — verification runs in *your* infra |
| IVMS101 | 🔵 | Implemented |
| Travel Rule protocol coverage | 🟡 | TRP live; TRISA **payload bridge built**, sealed-gRPC transport scoped |
| On-chain footprints | 🟡 | 6 live testnets; mainnet runbook ready, not deployed |
| CBOM / post-quantum plan | 🔵 | Published CBOM + hybrid-PQ plan (EO-14409-aligned) |
| Audit trail | 🔵 | Hash-chained + signed Merkle roots; keyless re-verify tool |
| Adversarial testing | 🔵 | Fuzzing (millions of execs, fails-closed) + host audit FAIL=0 |
| FIPS 140-3 | 🟡 | App crypto via Go FIPS module; full-OS = optional Linux profile |
| Independent ZK + protocol audit | 🔴 | **Requested, not done** — the #1 gate; audit-prep spec ready |
| SOC 2 Type II / ISO 27001 | 🔴 | Not yet (funded maturity step; N/A scope in embedded model) |
| Third-party pen test | 🔴 | Not yet (internal hardening strong; external test pending) |
| SLA / uptime / BCP-DR | 🔴 | One host; scaling model defined, not operated |
| Key custody (HSM/threshold) | 🟡 | File-perm today; HSM/KMS is the production milestone |
| Commercial (MSA / DPA / liability) | 🔴 | No formal terms yet (first-engagement step) |

## Read

Strong (🟢) where it's hard to fake — privacy, ZK, neutrality, open source, the
embed model. Meets bar (🔵) on the table-stakes. Gaps (🔴) are the **formal-
assurance** layer that money + a first partner buy, not engineering risk.

**Engagement guidance:** lead as a **design partner embedding an open-source
library** (where 🟢/🔵 dominate and 🔴 items are stage-appropriate), not as a
production data-processing vendor (where the 🔴 questionnaire items gate you).
Close the one proactive gate — the **independent ZK audit** — because every
serious counterparty asks for it.
