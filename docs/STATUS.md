# SPT-Txn — project status (current-state map)

Snapshot as of 2026-06-28. What exists, where it lives, what's live on-chain, and
how to build and verify it. Pairs with [RUNBOOK.md](RUNBOOK.md) (how to reproduce)
and [BUILD-JOURNAL.md](BUILD-JOURNAL.md) (how we got here).

## Component map

| Area | Lives in | State |
|---|---|---|
| Token chain (CAT → CT → SPT-Txn) | `internal/cattoken`, `internal/cttoken`, `internal/txntoken` | tested |
| Eight-step enforcement engine | `internal/verifier` | tested |
| Agentic delegation (CT→CT, N-hop, revocation cascade) | `internal/cttoken`, `internal/verifier`, `cmd/agentdemo` | POC-tested |
| Agentic ZK chain proof (`ChainCircuit`) + verifier seam | `internal/zkproof`, `internal/verifier` (`step6ChainZK`) | built + tested + benchmarked + token-bound |
| ZK predicates (commitment, threshold, VASP) | `internal/zkproof`, `internal/zkhash` (Poseidon2/BN254) | tested |
| On-chain ZK verifier (Solidity) | `solidity/src/{Groth16Verifier,AttestationVerifier}.sol`, `cmd/zk-export-solidity`, `cmd/zk-solcalldata` | live on 2 L2s |
| Scoped-disclosure SDK + schema | `internal/disclosure`, `docs/DISCLOSURE-SCHEMA.md` | built + tested |
| Travel Rule (IVMS101 + SD-JWT + ZK) | `internal/travelrule`, `internal/sdjwt`, `internal/trp`, `internal/ivms101`, `cmd/tr-svc` | live (2-party) |
| Ledger adapters (12 chains) | `internal/ledger` | tested |
| On-chain anchor contracts | `cairo/attestation_anchor`, `move/attestation_anchor`, `solidity/src/AttestationAnchor.sol` | live on 4 chains |
| End-to-end anchoring tool | `cmd/anchor` | tested |
| Hedera HCS anchoring client (A1) | `clients/hcs-anchor` (separate module) | built; keyless mirror-node verify; anchoring is an operator action |
| Services (verify-role, Travel Rule) | `cmd/agentsvc` (:4446), `cmd/tr-svc` (:4445) | deployed (OpenBSD) |
| CI | `.github/workflows/ci.yml` | build + vet + test on push/PR |
| Site | `web/` → foss.violetskysecurity.com | live |

## Ledger adapters (12)

`xrpl`, `hedera`, `solana`, `stellar`, `starknet`, `aptos`, `sui`, `ethereum`
(covers all EVM L2s), `xdc`, `algorand`, `arbitrum`, `polkadot`. Each:
`Name`/`Validate`/`Canonicalize`,
chain-tagged preimage (no cross-chain hash collision), shape-only address checks
(POC). One EVM adapter + one Solidity contract set cover Ethereum L1 and every
EVM L2.

## Live on-chain footprints (public testnets)

| Chain | Contract / module | Address | Notes |
|---|---|---|---|
| Ethereum Sepolia | AttestationAnchor | `0x3fC3bE148c4902C21dfaf4ccff1E0c99d6F57089` | real token-derived root |
| Ethereum Sepolia | Groth16Verifier | `0x8032A63cA0f19cA5Ce81f479d0c29213C6640a69` | ZK verifier |
| Ethereum Sepolia | AttestationVerifier | `0x311612c4E2D7E93CF5d80C0138B55C8A723B95ef` | ZK-gated anchor |
| Arbitrum Sepolia | Groth16Verifier | `0x805d8Cd70ab6aA00bFD5956DA65062aC7Fb689fD` | ZK verifier |
| Arbitrum Sepolia | AttestationVerifier | `0x349edc056b6A3809a5B7FCFC8f260539aB0e13D8` | ZK-gated anchor |
| Arbitrum Sepolia | AttestationAnchor | `0x07229AdF304d557e8D4a02B2a5ED92C13907Dc3d` | plain anchor |
| Starknet Sepolia | attestation_anchor (Cairo) | `0x0620fe8ccb9c19fe9acce44dccc6a6a3d851974dcd97f05949982453de853de1` | real token-derived root |
| Aptos testnet | attestation_anchor (Move) | `0x0b1f35b54e92d49d21d1badca271b9ab5686f22f82d6f88c6731cac20cbe0aa2` | real token-derived root |
| Solana devnet | SPL-memo anchor wallet | `BeWdnfiJ52LpaGudU6ZhGLVcpeBEYxHYewZC4DZopVi4` | memo anchor |
| Hedera testnet | HCS topic (attestation anchor) | `0.0.9357269` (seq 1) | real token-derived ctx hash `9448…7581`; keyless mirror-node verify; milestone A1 |
| Hedera testnet | `did:hedera` DID document (HCS) | `0.0.9357387` | issuer DID + bound humanAnchor; keyless mirror-node resolve; milestone A2 |

The on-chain ZK verifier (Ethereum + Arbitrum Sepolia) verifies a threshold
selective-disclosure proof on-chain and records the root only if it checks out; a
tampered proof reverts.

The Hedera HCS footprint is **live on testnet** (topic `0.0.9357269`, sequence 1,
consensus timestamp `1782658058.681753330`) — a real `cmd/anchor -chain hedera`
context hash anchored via `clients/hcs-anchor` and confirmed keyless on the public
mirror node. All footprints are **testnet**. A first **mainnet** footprint
(Arbitrum One or Base, same bytecode) is runbook-ready in [RUNBOOK.md](RUNBOOK.md)
§12, pending a funded deploy (an operator action — needs a dedicated, funded
mainnet key).

## ZK circuit metrics (BN254 / Poseidon2 / Groth16, `go run ./cmd/zk-bench -prod`)

| circuit | constraints | setup | prove | verify | proof |
|---|---|---|---|---|---|
| commitment | 373 | 34 ms | 6 ms | ~1.0 ms | 164 B |
| threshold | 2,026 | 91 ms | 7 ms | ~0.8 ms | 164 B |
| chain (4-hop) | 52,001 | 1.88 s | 181 ms | ~1.0 ms | 164 B |

Verify is constant ~1 ms and proofs are a constant 164 B regardless of chain length.
The chain circuit grew 5,936 → 17,945 → 52,001 constraints (prove 16 → 84 → 181 ms)
as F1 was closed in two steps: phase 1 added per-hop issuer registry-membership
(Poseidon2 Merkle), phase 2 added per-hop in-circuit Baby Jubjub EdDSA signature
verification (~7k constraints/hop). Verify and proof size are unchanged (Groth16 is
constant-size), so even a fully signature-checked 4-hop chain verifies in ~1 ms.

## Build & test

Go 1.25+, gnark v0.15 (Go can't install in the Cowork sandbox — build on the Mac/host).

```
go build ./...
go vet ./...
go test ./...
go run ./cmd/agentdemo        # offline agentic delegation + revocation demo
go run ./cmd/zk-bench -prod   # production circuit metrics
go run ./cmd/anchor -chain ethereum   # mint a chain, print the real ContextHash + anchor calldata
```

## Grant status (summary; details in gitignored docs)

Anthropic Fellows + OpenAI Cybersecurity — **submitted**. EF ESP + Arbitrum
Multichain — **drafted and demo-backed, ready to submit**. XRPL, Stellar SCF,
Aptos Payments, Starknet Seed — drafted (need a community/traction step).

## Honest boundaries

POC, security-audited, not production. Agentic layer POC-tested, not battle-tested
at scale. The opt-in ZK chain mode now verifies, in-circuit, that **each hidden hop
carries a real Baby Jubjub signature from a registered CT-issuer over its actual
scope** (F1 closed — phases 1+2), reaching parity with the cleartext path's
issuer-trust check. This requires issuers to dual-key (Ed25519 for JWS/VC interop +
a Baby Jubjub key for the ZK proof); the Baby Jubjub key is an auxiliary ZK artifact,
not the authoritative (or PQ) signature. See
[SECURITY-REVIEW-2026-06-28.md](SECURITY-REVIEW-2026-06-28.md). On-chain footprints
are testnet. The human-anchor binding in ZK chain mode is a cleartext endpoint
check (by design — the agent must not hold the human's anchor preimage). The
offline verifier library is the primary path; hosted endpoints are a convenience.
