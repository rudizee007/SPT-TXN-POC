# SPT-Txn — build journal

A chronological record of the multi-chain + ZK + agentic build work (June 2026),
with the engineering decisions and their rationale. Current-state summary lives in
[STATUS.md](STATUS.md); reproduction steps in [RUNBOOK.md](RUNBOOK.md).

## Ledger adapters → ten chains

Started from four tested adapters (XRPL, Hedera, Solana, Stellar) and added Aptos
(Move), then Ethereum (EVM), then XDC and Algorand, then Arbitrum. Each adapter is
`Name`/`Validate`/`Canonicalize` behind one `Ledger` interface, with the chain name
in the canonical preimage so two chains can't produce a colliding
`spt_txn_context_hash` (each adapter has a no-collision test).

Key decisions:
- **EVM is build-once-run-everywhere.** One `ethereum.go` adapter + one Solidity
  contract set cover Ethereum L1 and every EVM L2. `xdc.go` and `arbitrum.go` are
  thin aliases (EVM-identical, distinct chain tag) so binding is labeled per-chain.
- **Shape-only validation** (address format, currency) is sufficient for the POC;
  on-ledger existence/checksum is integration work, documented per adapter.
- **Chains are integration targets, not dependencies** — the blockchain-agnostic
  invariant held throughout.

## On-chain anchor contracts on four chains

A minimal attestation-anchor (store a 32-byte root, by whom, when) implemented per
VM: Cairo (`cairo/attestation_anchor`, `u256`), Move (`move/attestation_anchor`,
`vector<u8>`, append-only `AnchorBook`), Solidity (`solidity/src/AttestationAnchor.sol`,
`bytes32`). Deployed to Starknet Sepolia, Aptos testnet, Ethereum Sepolia, and
Arbitrum Sepolia; Solana devnet uses an SPL-memo anchor.

Toolchain lessons:
- **Starknet: use sncast + scarb 2.18, not starkli 0.4.2.** starkli 0.4.2 is too
  old for current Sepolia — it rejects Sierra 1.8 and computes a stale CASM class
  hash on 1.6. sncast (current) declares/deploys cleanly with `--network sepolia`.
- **Arbitrum L2 funding via the Inbox `depositEth()`** from L1 (CLI, no wallet) —
  the canonical bridge, address from the Arbitrum docs.

## Real end-to-end anchoring

`cmd/anchor` mints a real CAT→CT→SPT-Txn chain, computes the genuine
`spt_txn_context_hash`, runs the eight-step verifier (ALLOW), and prints per-chain
anchor calldata. The footprints on Ethereum/Starknet/Aptos were re-anchored with
these **real token-derived** hashes (not demo values); `-onchain` confirms MATCH.
This is what makes a footprint mean "bound to a verified token," not a placeholder.

## On-chain ZK verifier (the ESP "verify without revealing")

`Artifacts.ExportSolidity` + `cmd/zk-export-solidity` export a gnark Groth16
verifier from the pinned vk; `AttestationVerifier.sol` calls it and anchors only if
the proof checks out; `cmd/zk-solcalldata` encodes a real `threshold` proof into
calldata. Deployed + proven live on Ethereum and Arbitrum Sepolia — a real
amount-over-threshold proof (amount hidden) verified on-chain; a tampered proof
reverts. The generated verifier's signature is `verifyProof(bytes, uint256[2])`
and it reverts on failure (no bool).

## Agentic ZK chain proof

`ChainCircuit` (Groth16/BN254, `MaxHops=4`) proves a delegation chain valid —
attenuation (parent − child ≥ 0 via 64-bit range check), currency unchanged, depth
decrements and stays ≥ 0 — **without revealing intermediate scopes**, with a public
leaf-scope commitment and a human-anchor public input. `ProveChain`/`VerifyChain`/
`ChainHop` + `CircuitChain`. Tests reject widening, currency-switch, over-depth, and
wrong-depth. Measured: 5,936 constraints, 16 ms prove, ~1 ms verify, 164 B.

Decisions:
- **Signatures stay native (out of circuit).** In-circuit Ed25519 is expensive; the
  circuit proves the scope/depth/anchor invariants, the eight-step engine keeps the
  cryptographic identity checks. This is the honest division of labour — and it is
  the source of the documented ZK-mode limitation (intermediate signatures are not
  re-verified in ZK mode; see the security review).
- **Single human anchor, bound in clear.** The circuit does not prove the human's
  anchor preimage — the agent-prover must not hold it. The human is bound by the
  cleartext CAT = leaf = SPT-Txn `human_anchor` equality the verifier already checks.
- **Token binding.** `step6ChainZK` derives the leaf-scope commitment (`CLeaf`) from
  the presented leaf CT's scope and the max depth (`D`) from the CAT — so a proof
  can't claim a different leaf scope or a deeper chain than presented.
- **Verifier stays gnark-free.** The ZK mode is wired by dependency injection
  (`verifier.ChainVerifierFunc`), so the lightweight offline verifier never imports
  gnark; ZK verification is strictly opt-in.

## Scoped-disclosure SDK + schema

`internal/disclosure` — a request → consent → response protocol for time-limited,
scope-selected selective disclosure over SD-JWT: discloses only `requested ∩
consented`, rejects out-of-scope/expired/mismatched responses, reports withheld
fields. Language-agnostic schema in `DISCLOSURE-SCHEMA.md`. Second of the two ESP
deliverables (the on-chain ZK verifier being the first).

## Supporting work

GitHub Actions CI (`go vet`/`build`/`test`); the website's live proof-of-execution
strip + interactive 8-step verifier demo + on-chain anchor readout; GoAccess-over-SSH
analytics with a 30-day-retention privacy update; and grant packages (Anthropic +
OpenAI submitted; EF ESP + Arbitrum demo-backed and ready).

## Crypto note

Poseidon2 (not MiMC) is the ZK-friendly hash across **all** circuits — the
MiMC→Poseidon2 migration completed in v2 (gnark v0.15); the chain circuit was built
on Poseidon2 from the first line. Groth16/BN254 throughout; verify is constant-time
and cheap, on-chain or offline.
