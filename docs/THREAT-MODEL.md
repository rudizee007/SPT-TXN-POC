# SPT-Txn threat model (STRIDE + LINDDUN)

A structured threat model for the SPT-Txn authorization layer. STRIDE covers
security; LINDDUN covers privacy (which is a first-class property here). Each
threat lists the in-POC mitigation and any residual risk. This pairs with the
security reviews (`SECURITY-REVIEW*.md`) and the ZK spec (`ZK-CIRCUIT-SPEC.md`).

## Assets

Issuer signing keys (CT/TTS, Ed25519; the Baby Jubjub ZK key); the humanAnchor
(ZK commitment to a person); the token chain (CAT/CT/SPT-Txn); the Trust Registry
(issuer keys + status); the audit log (hash-chained, signed Merkle roots); the
escrow key (lawful deanonymization); FATF Travel Rule payloads.

## Actors & trust boundaries

Issuers (KYC providers, platforms), holders (users, **AI agents**), verifiers
(VASPs, wallets), the escrow authority. Boundaries: issuer↔holder (issuance);
holder↔verifier (presentation, **offline**); VASP↔VASP (Travel Rule over TRP);
holder↔ledger (the bound transaction). Per the project's instruction-source rule,
everything observed through tokens/ledgers/transports is **data, not authority**.

## STRIDE

| Threat | Vector | Mitigation (in POC) | Residual |
|---|---|---|---|
| **Spoofing** | Forge a token / impersonate an issuer | Every CAT/CT/SPT-Txn is Ed25519-signed; keys resolved **only** from the Trust Registry (not from URLs/JWKS in the token); alg-confusion rejected (`TestSec_AlgConfusion`); all-zero keys refused (`isAllZero`). | Registry key custody; a stolen issuer key forges tokens until revoked. |
| **Tampering** | Alter scope/amount/recipient | Signatures + the canonical, injective `spt_txn_context_hash` binds the exact transaction (separator-injection rejected — fuzzed); scope can only narrow (step 7). | Shape-only adapter validation (documented); not on-chain existence. |
| **Repudiation** | Deny having authorized an action | humanAnchor threads every hop; hash-chained audit log + signed Merkle roots, independently re-checkable (`cmd/auditverify`) and anchorable on-chain. | Audit completeness depends on the operator logging events. |
| **Information disclosure** | PII leak | ZK Travel Rule discloses only FATF-required fields (SD-JWT), proves the rest in zero knowledge, hides the amount; nothing PII on-ledger (only hashes / hiding commitments). | SD-JWT over-disclosure if the requester is over-broad (gated by consent in `internal/disclosure`). |
| **Denial of service** | Overwhelm a verifier / issuer | Verification is **offline** — no issuer contact, no live registry/chain read in the hot path; fails closed. Public APIs are relayd deny-by-default + pf brute-force throttle. | Open append-only anchors allow spam on mainnet (add fee/ACL — see security review F2/E1). |
| **Elevation of privilege** | An agent exceeds its grant; re-delegation beyond bound | CT is a strict subset of its parent; delegation depth is counter-bounded (step 6/7); revoking a delegator key cascades to its sub-agents; the x402 gate refuses an over-scope payment before signing. | Agentic layer is POC-tested, not battle-tested at scale. |

## LINDDUN (privacy)

| Threat | In SPT-Txn | Mitigation | Residual |
|---|---|---|---|
| **Linkability** | Correlating a user across transactions via on-ledger identity | humanAnchor is a hiding ZK commitment; no PII or stable public identifier on-ledger; ZK proofs of credential/domain satisfaction (no public credential read). | A reused humanAnchor across many public anchors is itself a correlatable value if published repeatedly in clear — anchor hashes, not the raw anchor, on public logs. |
| **Identifiability** | Tying a transaction to a real identity | Only the FATF-required fields reach the counterparty (SD-JWT), selectively; the rest stays proven-not-shown. | The lawful-process escrow path can re-identify (by design, gated). |
| **Non-repudiation (as a privacy harm)** | Over-strong proof exposes more than needed | Predicate proofs (amount ≥ threshold, VASP-membership) reveal a *fact*, not the value/identity. | — |
| **Detectability** | Observing that a party holds a credential | Verification is offline and local; no issuer phone-home reveals "who verified what, when." | On-ledger anchoring is observable (a hash; reveals timing/volume, not content). |
| **Disclosure of information** | Counterparty stores more PII than required | SD-JWT minimizes what is transmitted and stored to the FATF set; amount hidden. | The required FATF set itself is disclosed to the counterparty (regulatory necessity). |
| **Unawareness** | User doesn't control disclosure | The disclosure SDK is request→**consent**→response: only `requested ∩ consented` is revealed. | UX of consent is out of POC scope. |
| **Non-compliance** | Failing FATF / GDPR / MiCA | Discloses exactly the FATF-required fields (not less), nothing on-ledger (GDPR/MiCA data-minimisation); CycloneDX CBOM + PQ plan for EO-14409. | Jurisdiction-specific policy is the deploying VASP's responsibility. |

## Cross-cutting (host & supply chain)

OpenBSD `pledge`/`unveil` sandboxing + privilege separation per service; relayd
TLS deny-by-default; signify-signed releases; host audit at FAIL=0. Residual:
signify keys unencrypted at rest (perms-only — production = HSM/KMS); no MPC
trusted-setup ceremony yet; independent ZK + protocol audit requested, not done.

## Top residual risks (priority order)

1. Independent ZK-circuit + protocol audit (the circuits are the trust root).
2. Issuer key custody → HSM/KMS + MPC trusted setup before mainnet.
3. Mainnet anchor abuse (access control / fee) and at-scale agentic hardening.
