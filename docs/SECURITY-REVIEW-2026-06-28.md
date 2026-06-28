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
| F1 | Resolved (phases 1+2) | ZK chain mode now verifies, in-circuit, a registered CT-issuer's Baby Jubjub signature over each hop's scope — parity with the cleartext issuer-trust check |
| F2 | Low | Open append-only anchoring (anyone can anchor) — spam/storage growth on mainnet |
| F3 | Low | Shape-only address validation in adapters (POC) |
| F4 | Low (process) | Throwaway testnet deployer keys in shell history; one EVM key lost |
| F5 | Info | Human-anchor binding in ZK chain mode is a cleartext endpoint check (intentional) |

### F1 — ZK chain mode: per-hop issuer signatures now verified in-circuit (RESOLVED, phases 1+2)
The cleartext `step6Chain` verifies **every** hop's signature against a registered
issuer key, the parent-hash binding, jti linkage, scope monotonicity, and depth. The
original gap: ZK mode proved only scope/depth/anchor, so a prover could in principle
present an attenuating chain whose hidden hops were not issued by trusted issuers.
Closed in two steps (both implemented 2026-06-28, full suite green):

- **Phase 1 — membership.** `ChainCircuit` proves, for each active hop, that the hop
  issuer's key is a member of the registered-CT-issuer Merkle tree (public `RegRoot`),
  reusing the matched Poseidon2 Merkle gadget. (5,936 → 17,945 constraints.)
- **Phase 2 — signatures.** Each active hop additionally verifies, in-circuit, a Baby
  Jubjub **EdDSA signature** (gnark `std/signature/eddsa`, MiMC challenge) by that
  issuer over the hop's scope commitment `H(DomainAmount, MaxAmt, Currency)`, and binds
  the signing public key to the membership leaf `H(DomainIssuer, A.X, A.Y)`. So a valid
  signature from an **unregistered** key, the **wrong signer**, or over an **unsigned
  scope** all fail. (17,945 → 52,001 constraints, prove 84 → 181 ms; verify ~1 ms and
  proof 164 B unchanged.) Negative tests: `TestChain_RejectsUnregisteredIssuer`,
  `TestChain_RejectsWrongSigner`, `TestChain_RejectsScopeNotSigned`,
  `TestChain_RejectsWrongRegRoot`.

ZK mode now reaches parity with the cleartext path on intermediate-hop issuer trust.

**Operational consequence (documented, not a gap):** issuers must **dual-key** — keep
Ed25519 for JWS/W3C-VC interop and the cleartext path, and add a Baby Jubjub key used
only to sign the hop scope commitment for the ZK proof. The Baby Jubjub key is an
auxiliary ZK artifact, **not** the authoritative attestation, and Baby Jubjub +
Groth16/BN254 is **classical-security only** (not post-quantum) — the authoritative,
eventually-PQ-hybrid signature remains the Ed25519 line. Custody the Baby Jubjub key
with the same rigor as the Ed25519 key (a leak lets an attacker forge ZK chain proofs
for that issuer, though not its JWS/VCs). `eddsa_probe_test.go` pins the in-circuit
EdDSA API and can be kept as a fast regression guard.
- **Status:** ZK chain mode is still strictly opt-in (injected `ChainVerifier`);
  cleartext remains the default; `CLeaf`/`D`/`RegRoot` are bound to the verifier's
  trusted context. Residual lower-priority items: an independent ZK-circuit audit of
  `ChainCircuit` soundness is still wanted (Rec 2 below).

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
