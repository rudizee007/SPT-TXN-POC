# SPT-Txn throughput benchmark

Measured throughput/latency for the SPT-Txn hot path, so an integrator operating
at machine scale (e.g. an AI-agent platform issuing and verifying authorizations
for many concurrent agents) gets **measured numbers, not estimates**.

## Run

```bash
go run ./cmd/loadbench                 # full run, includes the ZK circuit
go run ./cmd/loadbench -d 5s           # 5s per cheap benchmark (steadier numbers)
go run ./cmd/loadbench -zk=false       # skip ZK (fast: primitives only)
go run ./cmd/loadbench -hops 4 -proofs 12
```

Report the machine (CPU model, core count) alongside the numbers.

## What it measures and why

| Operation | Where it sits in the flow |
|---|---|
| **Ed25519 sign** | Minting an SPT-Txn action token (issue side) — one per agent action |
| **Ed25519 verify** | The per-hop signature check inside the cleartext eight-step verify |
| **SHA-256** | Canonical/context hashing performed during verification |
| **ZK chain verify** | Groth16/BN254 N-hop delegation-proof check — the per-action cost on the *privacy* path |
| **ZK chain prove** | Proof **generation** — the expensive op, done **once per delegation chain/session** and amortized over every action that agent takes |

Cheap ops are measured single-threaded and across `GOMAXPROCS` workers to show
horizontal scaling (the verifier is stateless, so it scales with cores). ZK
verify is also run in parallel; proving is timed serially.

## Reading the numbers (the pitch points)

- **Mint and verify are Ed25519** — sub-millisecond, and scale linearly with cores.
  The cleartext eight-step verify ≈ *(chain length)* signature-verifies + hashing,
  so divide the Ed25519-verify rate by the hop count for a conservative per-chain
  estimate.
- **The expensive ZK proving cost is amortized**: it happens once when a delegation
  chain is established, not on every action. The per-action privacy cost is the ZK
  *verify*, not the prove.
- **Biggest scaling lever**: use the cleartext chain for intra-org agent swarms
  (you control both ends), and reserve ZK chain proofs for cross-org or when the
  delegation path itself must stay private.
- **One stateful component** in the hot path is the DPoP anti-replay cache (bounded
  by TTL-window × action-rate, shardable by holder/agent); everything else in the
  verify path is stateless.

## Results

Machine: 10-core Apple-silicon Mac · Go 1.25.7 · 3-hop delegation chain · ZK circuit = 52,001 constraints (Groth16/BN254).

| Operation | Mode | Ops/sec | Latency |
|---|---|---|---|
| Ed25519 sign (mint) | 1 core | 75.8k | 13.2 µs |
| Ed25519 sign (mint) | 10 cores | 393.9k | — |
| Ed25519 verify | 1 core | 34.7k | 28.8 µs |
| Ed25519 verify | 10 cores | 186.2k | — |
| SHA-256 (256 B) | 1 core | 9.70M | 103 ns |
| SHA-256 (256 B) | 10 cores | 61.5M | — |
| ZK chain verify | 1 core | 1.9k | 514 µs |
| ZK chain verify | 10 cores | 6.7k | ~1.5 ms |
| ZK chain prove | 1 core | 6.3 | 159 ms |

Derived (the headline numbers):

- **Cleartext agentic authorization verify** ≈ Ed25519-verify ÷ hops ≈ **~62k full
  3-hop chain verifications/sec on a 10-core laptop** (186.2k ÷ 3), and it scales
  with cores.
- **Action-token minting** ≈ **~394k/sec** (10 cores).
- **Privacy path (ZK)**: **~1.5 ms per verify, ~6.7k/sec on 10 cores**; proof
  **generation ~159 ms, done once per delegation chain** and amortized over every
  action — not a per-action cost.

> Reference-POC measurements on a single host, not a tuned production deployment.
> They establish per-core costs; production throughput is those costs × horizontal
> replicas, since verification is stateless. No hardware acceleration
> (`acceleration=none`) — GPU/AVX proving would cut the 159 ms materially.
