# Security review — new surface (2026-06-28)

A focused review of the code added **after** the 2026-06-25 audit (`docs/SECURITY-REVIEW.md`):
the new ledger adapters, the on-chain contracts, the agentic ZK chain proof, the
verifier ZK seam, and the scoped-disclosure SDK. This is a source-level review;
re-run the host script for the environment checks:

```
doas sh scripts/security-audit.sh     # target FAIL=0
go test ./...                          # full suite, incl. ZK + verifier + disclosure
```

## Scope reviewed

`internal/ledger/{ethereum,xdc,algorand,arbitrum,aptos}.go`; `solidity/src/*.sol`;
`cairo/attestation_anchor`, `move/attestation_anchor`; `internal/zkproof`
(`ChainCircuit`, `ProveChain`/`VerifyChain`, `LeafScopeCommitment`, `CurrencyCode`);
`internal/verifier` (`step6ChainZK`, `ChainVerifierFunc`); `internal/disclosure`;
`cmd/{anchor,zk-export-solidity,zk-solcalldata}`.

## Findings

| # | Severity | Finding |
|---|---|---|
| F1 | Medium (by-design) | ZK chain mode proves per-hop issuer registry-membership (phase 1) but does not yet verify intermediate-hop issuer signatures in-circuit |
| F2 | Low | Open append-only anchoring (anyone can anchor) — spam/storage growth on mainnet |
| F3 | Low | Shape-only address validation in adapters (POC) |
| F4 | Low (process) | Throwaway testnet deployer keys in shell history; one EVM key lost |
| F5 | Info | Human-anchor binding in ZK chain mode is a cleartext endpoint check (intentional) |

### F1 — ZK chain mode: per-hop membership proven (phase 1); signatures not yet in-circuit (Medium, by design)
The cleartext `step6Chain` verifies **every** hop's signature against a registered
issuer key, the parent-hash binding, jti linkage, scope monotonicity, and depth.

**Phase 1 (implemented 2026-06-28):** `ChainCircuit` now also proves, for each
*active* hop, that the hop's issuer key is a **member of the registered-CT-issuer
Merkle tree** (public `RegRoot`), reusing the matched Poseidon2 Merkle gadget. So a
ZK-mode proof now demonstrates scope attenuation + depth + human-anchor **and** that
every hidden hop names a registry-listed issuer. Cost: chain circuit 5,936 → 17,945
constraints, prove 16 → 84 ms; verify (~0.8 ms) and proof size (164 B) unchanged.
Negative tests cover an unregistered issuer (rejected at prove) and a wrong registry
root (rejected at verify).

**Residual gap (the honest limitation):** membership proves the hop *names* a
registered issuer, not that the issuer **signed** it. Registry leaves are issuer IDs,
which are not secret — so a malicious prover who knows them could still name
registered issuers it does not control. Closing this needs **in-circuit signatures**
(phase 2): issuers dual-key (keep Ed25519 for JWS/VC interop, add a SNARK-friendly
EdDSA key, e.g. Baby Jubjub) and the circuit verifies each hop's signature against a
registry-member key. Estimated cost (4 hops): roughly +20–40k constraints on top of
phase 1, prove in the few-hundred-ms range, verify still ~1 ms.
- **Mitigations in place:** ZK mode is strictly opt-in (requires an injected
  `ChainVerifier`); the **cleartext mode is the default and the stronger path** (it
  verifies signatures); the CAT and leaf CT endpoints are still signature-verified;
  `CLeaf`/`D`/`RegRoot` are bound to the verifier's trusted context; documented in the
  engine, RUNBOOK §7, and the plan doc.
- **Recommendation:** decide phase 2 (in-circuit signatures) with the phase-1 cost in
  hand. Until then, ZK mode = scope-privacy + registry-membership, not a replacement
  for cleartext issuer-signature verification of intermediates.

### F2 — Open append-only anchoring (Low)
`AttestationAnchor`/`AttestationVerifier` (Solidity), the Cairo contract, and the
Move module let **anyone** append a root (intentional: a public, append-only log;
no owner, no funds, no upgradeability — minimal attack surface, no reentrancy since
the only external call is a `view` to the verifier and no value moves). On a public
**mainnet** this allows spam / unbounded storage growth.
- **Recommendation (mainnet only):** add access control or a small anti-spam fee, or
  rate-limit at the relayer. Not a testnet concern.

### F3 — Shape-only address validation (Low)
Adapters validate address *shape* (prefix, hex length, base32 alphabet, Move type
tags) but not on-chain existence or checksums (EIP-55, StrKey, Algorand checksum).
This is documented per adapter and acceptable for transaction-binding (the binding is
to the canonical string; correctness of the address is the issuer's responsibility).
`canonicalEncode` rejects the reserved separator bytes, so no field-injection.

### F4 — Throwaway keys in shell history (Low, process)
Testnet deployer private keys were `export`ed in shell history during deploys, and
one EVM key was lost (a fresh one was generated). No production/mainnet secret was
exposed; all keys are disposable testnet keys.
- **Recommendation:** `history -d` the lines; never reuse any of these keys on
  mainnet; for mainnet use a hardware-backed or env-file key never echoed.

### F5 — Human-anchor cleartext binding in ZK mode (Info, intentional)
In ZK chain mode the human anchor is bound by the cleartext CAT = leaf = SPT-Txn
`human_anchor` equality, not in-circuit. This is the **correct** trust model: the
agent-prover must not hold the human's anchor preimage, so folding it into the
circuit would be wrong. Recorded as a deliberate boundary, not a gap.

## Positives confirmed

- **No cross-chain hash collision:** every adapter tags the chain in the canonical
  preimage; each has a passing no-collision test.
- **Field-wraparound guarded:** `ChainCircuit` range-checks amounts to 64 bits and
  depth to 32 bits (same discipline as the threshold circuit's CR-4 fix); negative
  tests (widening, currency-switch, over-depth, wrong-depth) all fail closed.
- **Verifier seam is safe:** the ZK branch is additive and gated (`ChainProof != nil`
  + an injected verifier); the proven cleartext `step6Chain` is untouched; the
  verifier package stays gnark-free (dependency injection). On-chain: a valid proof
  anchors, a tampered proof reverts (`0x7fcdd1f4`).
- **Disclosure SDK:** discloses only `requested ∩ consented`, rejects out-of-scope /
  expired / mismatched responses; relies on the holder-/transaction-bound outer
  token for replay/holder-binding (the documented `sdjwt` invariant).
- **No new edge-exposed mutating endpoints;** contracts hold no funds, no owner, no
  upgrade path; `agentsvc` verify-role holds no key (`pledge "stdio rpath inet"`).

## Host audit result (2026-06-28 run)

`scripts/security-audit.sh` on the deployed OpenBSD host (stale checkout — audits
the running services/configs, not the new Mac-side code): **PASS=29, WARN=9,
FAIL=0.** Target (FAIL=0) met. WARN triage:
- By design: `*.4445`/`*.4446` public API listeners (relayd deny-by-default); sshd
  password auth (pf brute-force throttled — operator's standing choice).
- Tradeoffs (production hardening, fine for POC): 5× signify keys unencrypted at
  rest (perms-only protection — always-on service; production = HSM/KMS or boot
  unlock); `doas permit nopass` (review scope).
- Resolved (audit-check precision, 2026-06-28): both remaining WARNs were
  `scripts/security-audit.sh` **false positives**, now fixed at the source.
  - *All-zero key:* the check warned whenever the registry held *any* active key
    **and** *any* all-zero key, without testing they were the **same** record.
    The all-zero entries are the `seedIfEmpty` placeholders (`domain-a`/`domain-b`
    slots), seeded `StatusRevoked` by construction, and the verifier refuses
    all-zero keys regardless (`engine.go isAllZero`). The check now correlates per
    record: `FAIL` only on an **active** all-zero key (the genuine risk — a
    placeholder slot left active / never `regkey`-replaced), `INFO` on revoked
    placeholders. Confirm live (expect every match `"status":"revoked"`):
    `curl -s http://127.0.0.1:8081/tr/list | tr -d ' \n' | awk '{gsub(/\},\{/,"}\n{");print}' | grep '"public_key":"0\{64\}"'`
  - *`:443`:* the check probed IPv4 only; it now checks IPv4+IPv6 and, when relayd
    is up but `:443` is unbound, says so explicitly (keypair/cert) rather than the
    generic "relayd down?". Confirm live: `doas netstat -an | grep '\.443 '`
    (expect a `LISTEN` row — the site is serving, so this was a probe race).

The new adapter/ZK/contract code is NOT deployed to the host; it is covered by
`go test ./...` (full suite green on the Mac, 2026-06-28) + the source review above.

## Recommendations (priority order)

1. Run `scripts/security-audit.sh` on the host over the new files; confirm FAIL=0.
2. Commission an **independent ZK-circuit audit** of `ChainCircuit` (soundness of the
   inactive-tail padding, the leaf selector, and the range-check bounds) — the
   Arbitrum Audit Fund can subsidize.
3. Decide the ZK-mode posture: document it as scope-privacy only (current), or fund
   in-circuit intermediate-signature proofs for full parity with cleartext (F1).
4. Mainnet hardening before any mainnet deploy: anchor access control/fee (F2),
   hardware-backed keys (F4).
