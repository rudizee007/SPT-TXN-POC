# On-chain ZK verifier + agentic ZK chain proof — build plan

Two ZK extensions to the POC. The off-chain Groth16/BN254 stack already works
(`internal/zkproof`, three circuits: commitment, threshold, vasp). These two
items extend it on-chain and to the agentic layer. Both need the gnark toolchain
run on a build host (the export and circuit work can't be done from CI alone).

---

## 1. On-chain ZK verifier (the ESP deliverable)

Goal: let an Ethereum / EVM L2 contract verify an SPT-Txn selective-disclosure
proof **on-chain** — verify a predicate without seeing the data — then anchor the
root only if the proof checks out.

### What's built
- `Artifacts.ExportSolidity(w)` (`internal/zkproof/zkproof.go`) — emits a Solidity
  Groth16 verifier for a circuit's verifying key.
- `cmd/zk-export-solidity` — exports from a **pinned** verifying key (from
  `zk-setup`), so the on-chain verifier matches the prover's key.

### Flow (run on a build host with gnark)
```
go run ./cmd/zk-setup -dir /var/spt-txn/zk                      # once
go run ./cmd/zk-export-solidity -circuit threshold \
     -dir /var/spt-txn/zk -o solidity/src/Groth16Verifier.sol   # generate verifier
```
`threshold` (amount-over-threshold, amount hidden) is the cleanest single
predicate to demo first.

### Wrapper contract (write after the verifier is generated)
gnark's generated contract exposes a `verifyProof(...)` taking the proof points
and the public-input array. Add a thin wrapper that verifies, then anchors:

```solidity
interface IGroth16Verifier {
    // exact signature comes from the generated file — align the input[] size to
    // the circuit's public inputs (threshold circuit: commitment + threshold).
    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) external view returns (bool);
}

contract AttestationVerifier {
    IGroth16Verifier public immutable verifier;
    event Verified(address indexed submitter, bytes32 root);
    constructor(address v) { verifier = IGroth16Verifier(v); }

    function anchorVerified(uint256[8] calldata proof, uint256[2] calldata input, bytes32 root) external {
        require(verifier.verifyProof(proof, input), "invalid proof");
        emit Verified(msg.sender, root);   // or call into AttestationAnchor
    }
}
```
- Confirm the `input[]` size and order against `internal/zkproof/circuits.go`
  (the `gnark:",public"` fields of the chosen circuit) and the generated file's
  comment header — gnark prints the public-input layout.
- The proof bytes from `internal/zkproof` are gnark's native serialization;
  convert to the verifier's `uint256[...]` calldata with gnark's
  `solidity`/`MarshalSolidity` proof encoding (the same release that generated
  the verifier) — do this in a small Go helper or off-chain script.

### Milestones
1. Generate + deploy `Groth16Verifier.sol` on Sepolia.
2. Deploy `AttestationVerifier` wired to it.
3. Off-chain: produce a real `threshold` proof, encode it, call `anchorVerified`,
   confirm a tampered proof reverts.
This is the ESP "verify without revealing" deliverable end-to-end.

---

## 2. Agentic ZK chain proof ("prove the chain without revealing it")

> **STATUS: BUILT (2026-06-28).** Implemented as `ChainCircuit` in
> `internal/zkproof/circuits.go` (Groth16/BN254, `MaxHops=4`) with `ProveChain` /
> `VerifyChain` + `ChainHop` in `zkproof.go`, registered as `CircuitChain` and in
> `cmd/zk-setup`. Tests in `chain_test.go`: a valid 3-hop chain proves+verifies;
> widening (scope escalation), mid-chain currency switch, over-depth, and a wrong
> declared depth are all rejected. Design choices vs the sketch below: a single
> human-anchor preimage bound to the public `H0` commitment (the "propagates
> unchanged" property is inherent to one anchor); attenuation enforced by
> range-checking `parent - child` to 64 bits (no separate comparator); the
> inactive tail is padded so a fixed circuit handles chains up to MaxHops; the
> public leaf-scope commitment `CLeaf = Poseidon2(DomainAmount, leafMaxAmt,
> leafCurrency)` reveals only the leaf's effective scope. Signatures/issuer-trust
> stay native (kept out of the circuit), as planned. Pending: `go test` on the Mac
> + an optional `cmd/zk-bench` entry.

Goal: prove a delegation chain (CAT → CT → … → leaf) is **valid** — each child
scope is a subset of its parent, delegation depth decremented and never negative,
and the humanAnchor is consistent across every hop — **without revealing the
intermediate scopes**. Today the eight-step engine checks this in the clear; this
makes the chain itself zero-knowledge.

### Design choice: keep signatures out of the circuit
In-circuit Ed25519 verification is very expensive. Keep signature/issuer-trust
checks where they are (the native eight-step engine), and let the ZK circuit
prove only the **scope-attenuation + depth + human-anchor** invariants over the
chain. This keeps the circuit small and is the honest division of labor: crypto
identity stays native, the *policy monotonicity* goes to ZK.

### Public vs private
- **Public:** root humanAnchor commitment `H0`; a commitment to the leaf's
  effective scope `Cleaf`; the declared max delegation depth `D`; (optionally) the
  `spt_txn_context_hash` the leaf binds to.
- **Private (witness):** per-hop scope values `(max_amount_i, currency_i)` for
  `i = 0..n`; the humanAnchor preimage + blinding; the depth-remaining sequence.

### Constraints (gnark, fixed max hops, e.g. MAXHOPS = 4)
For each hop `i` from 1..n:
- `max_amount_i <= max_amount_{i-1}`            (`api.AssertIsLessOrEqual`) — attenuation
- `currency_i == currency_{i-1}`                (`api.AssertIsEqual`)
- `depth_i == depth_{i-1} - 1` and `depth_i >= 0`
- `anchor_i == anchor_0`                         (human-anchor consistency)
Then bind the public commitments:
- `H0 == Poseidon(anchor_0, salt0)`              (reuse `internal/zkhash` Poseidon2)
- `Cleaf == Poseidon(max_amount_n, currency_n)`  (leaf scope commitment)
Unused hops (n < MAXHOPS) are padded with a "no-op" flag that disables that hop's
asserts, so a single fixed circuit handles chains up to MAXHOPS.

### gnark skeleton (new circuit in internal/zkproof/circuits.go)
```go
const MaxHops = 4

type ChainCircuit struct {
    H0    frontend.Variable `gnark:",public"`  // root humanAnchor commitment
    Cleaf frontend.Variable `gnark:",public"`  // leaf scope commitment
    D     frontend.Variable `gnark:",public"`  // max delegation depth

    Anchor   frontend.Variable                 // private: anchor preimage
    Salt0    frontend.Variable                 // private
    Active   [MaxHops]frontend.Variable        // 1 if hop present, else 0
    MaxAmt   [MaxHops]frontend.Variable        // private per-hop ceiling
    Currency [MaxHops]frontend.Variable        // private per-hop currency code
    Depth    [MaxHops]frontend.Variable        // private depth-remaining
}

func (c *ChainCircuit) Define(api frontend.API) error {
    // H0 binds the public anchor commitment to the private preimage.
    api.AssertIsEqual(c.H0, poseidon2(api, c.Anchor, c.Salt0))
    for i := 1; i < MaxHops; i++ {
        on := c.Active[i]
        // attenuation: when active, child <= parent
        le := api.IsZero(api.Sub(1, cmpLE(api, c.MaxAmt[i], c.MaxAmt[i-1]))) // pseudo
        api.AssertIsEqual(api.Mul(on, api.Sub(le, 1)), 0)
        // currency equal when active
        api.AssertIsEqual(api.Mul(on, api.Sub(c.Currency[i], c.Currency[i-1])), 0)
        // depth_i == depth_{i-1} - 1 when active
        api.AssertIsEqual(api.Mul(on, api.Sub(c.Depth[i], api.Sub(c.Depth[i-1], 1))), 0)
    }
    // leaf commitment binds to the last active hop's scope (selector omitted here).
    api.AssertIsEqual(c.Cleaf, poseidon2(api, leafMaxAmt, leafCurrency))
    return nil
}
```
(Pseudocode — `cmpLE`/`AssertIsLessOrEqual`, the active-hop selector for the leaf,
and the Poseidon2 wrapper come from `internal/zkhash`. Expect iteration with the
prover to get the range checks and selectors exactly right.)

### Integration — DONE (2026-06-28)
- `CircuitChain` + `ProveChain` / `VerifyChain` + `ChainHop` in `internal/zkproof`. ✓
- Optional verifier seam: `verifier.ChainVerifierFunc` (injection — the verifier
  package stays gnark-free) + `Engine.ChainVerifier` + `Input.{ChainProof,ChainH0,
  ChainCLeaf,ChainDepth}` + an additive `step6ChainZK` branch that replaces the
  cleartext intermediate-chain walk with a ZK proof while still verifying the CAT
  and leaf-CT endpoints. The proven cleartext `step6Chain` is untouched.
  Injection tested in `internal/verifier/chainzk_test.go`. ✓
- `cmd/zk-bench -prod` reports constraints/setup/prove/verify/size for the
  commitment, threshold, and chain circuits. ✓

**Measured (BN254 / Poseidon2 / Groth16, on the Mac):**

| circuit | constraints | setup | prove | verify | proof |
|---|---|---|---|---|---|
| commitment | 373 | 34 ms | 5 ms | ~1.0 ms | 164 B |
| threshold | 2,026 | 86 ms | 7 ms | ~0.8 ms | 164 B |
| chain (4-hop) | 5,936 | 230 ms | 16 ms | ~0.8 ms | 164 B |

Verify is constant ~1 ms and the proof is a constant 164 B regardless of chain
length — the agentic chain proof is cheap to check anywhere, offline or on-chain.

**Remaining (documented seam):** cryptographically bind the ZK public inputs to
the tokens — migrate the token `human_anchor` to the Poseidon2 commitment (so it
equals `H0`) and add a leaf-scope commitment claim (so it equals `CLeaf`). Until
then `step6ChainZK` verifies the endpoints in clear + proves the hidden middle,
gated behind an operator-opted-in `ChainVerifier`.

### Why it matters
It's the privacy upgrade to the agentic layer: a verifier confirms an agent acted
within a valid, human-anchored delegation chain **without learning the
intermediate authority limits** — the natural ZK complement to the cleartext
N-hop verifier already shipped.
