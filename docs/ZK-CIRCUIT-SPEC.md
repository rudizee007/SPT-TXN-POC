# SPT-Txn ZK-circuit specification (audit-prep)

A precise, auditor-facing spec of every Groth16 circuit in `internal/zkproof`:
its public/private inputs, its constraints, what it proves, and the soundness
arguments behind the non-obvious parts. The intent is to make an independent
ZK-circuit audit fast and cheap — the reviewer should be able to map each
constraint here to the gnark code and check the claims.

## Common parameters

- **Proof system:** Groth16 over **BN254** (`gnark` v0.15, `gnark-crypto` v0.20).
- **Hash:** **Poseidon2** over BN254's scalar field, used both natively
  (`internal/zkhash`) and in-circuit (`gnark/std/hash/poseidon2`), matched by
  construction (one field element per `Write`, initial state 0).
- **Domain separation (CR-1):** every commitment hash absorbs a distinct domain
  tag as its FIRST input — `H(tag, a, b)` — so a value computed for one purpose
  cannot be replayed as another. Tags: `DomainAnchor=1`, `DomainAmount=2`,
  `DomainMerkleNode=3`, `DomainIssuer=4` (`internal/zkhash/zkhash.go`).
- **Field-wraparound discipline (CR-4):** every operand of an inequality is
  range-checked with `api.ToBinary(x, n)` before comparison, so a public input
  outside `[0, 2^n)` cannot force a spurious comparison via modular reduction.
- **Trusted setup:** `groth16.Setup` is randomized; a deployment runs it ONCE per
  circuit (`cmd/zk-setup`) and distributes the verifying key. Proofs verify only
  against the vk from the same setup. **Audit ask:** the setup ceremony /
  toxic-waste handling is out of POC scope and should be a funded MPC ceremony
  before any mainnet use.

## CommitmentCircuit  (≈373 constraints)

- **Public:** `Anchor`.
- **Private:** `ID`, `Randomness`.
- **Constraint:** `Anchor == Poseidon2(DomainAnchor, ID, Randomness)`.
- **Proves:** knowledge of the identity preimage behind the humanAnchor. **Hiding**
  (Randomness) and **binding** (collision-resistance of Poseidon2).

## ThresholdCircuit  (≈2,026 constraints)

- **Public:** `Commitment`, `Threshold`.
- **Private:** `Amount`, `Blinding`.
- **Constraints:** `Commitment == Poseidon2(DomainAmount, Amount, Blinding)`;
  `ToBinary(Amount, 64)`; `ToBinary(Threshold, 64)`; `Threshold ≤ Amount`.
- **Proves:** a committed amount is at/above a public threshold, amount hidden.
- **Soundness note:** both operands are range-checked to 64 bits, so the
  comparison cannot be satisfied by wraparound (CR-4).

## VASPCircuit  (≈3,001 constraints, depth 8)

- **Public:** `Root`.
- **Private:** `Leaf`, `Siblings[8]`, `PathBits[8]`.
- **Constraints:** a Poseidon2 Merkle authentication path from `Leaf` to `Root`;
  each `PathBits[i]` is boolean; node = `Poseidon2(DomainMerkleNode, left, right)`
  with `left/right` selected by the path bit.
- **Proves:** the (hidden) leaf is a member of the registered-VASP set.
- **Soundness note:** the inner-node domain tag is distinct from the commitment
  domains, so a commitment value can't be passed off as a Merkle node.

## ChainCircuit  (≈52,001 constraints, MaxHops=4, F1 closed)

Proves an agentic delegation chain (CAT → CT → … → leaf) is valid **without
revealing intermediate scopes**, AND that every active hop was signed by a
registered CT-issuer.

- **Public:** `H0` (human-anchor commitment), `CLeaf` (leaf-scope commitment),
  `D` (root delegation depth), `RegRoot` (registered-CT-issuer Merkle root).
- **Private (per hop i, 0..3):** `Active[i]`, `MaxAmt[i]`, `Currency[i]`,
  `Depth[i]`, `PubKey[i]` (Baby Jubjub), `Sig[i]` (EdDSA), `IssuerSib[i][8]`,
  `IssuerDir[i][8]`; plus `Anchor`, `Salt`.
- **Constraints:**
  1. `H0 == Poseidon2(DomainAnchor, Anchor, Salt)`.
  2. Root hop active, `Depth[0] == D`, amounts/depth range-checked.
  3. Per later hop: `Active` is boolean and a **contiguous prefix**
     (`Active[i] ≤ Active[i-1]`, no 0→1 reactivation); attenuation
     `MaxAmt[i-1] − amtEff ≥ 0` (64-bit range-checked); currency unchanged; depth
     decrements by one and stays ≥ 0; inactive hops fall back to the parent so
     their constraints hold trivially.
  4. Leaf = last active hop via selector `isLeaf[i] = Active[i]·(1−Active[i+1])`;
     `CLeaf == Poseidon2(DomainAmount, leafAmt, leafCur)`.
  5. **(F1) Per active hop:** verify a Baby Jubjub **EdDSA** signature
     (`std/signature/eddsa`, MiMC challenge) by `PubKey[i]` over the hop's scope
     commitment, and prove `Poseidon2(DomainIssuer, PubKey[i].X, PubKey[i].Y)` is a
     member of `RegRoot` (Merkle path). The signature check is gated:
     `Active[i]·(1 − valid_i) == 0` — active ⇒ valid; inactive ⇒ unconstrained.

- **Soundness asks for the auditor (the non-obvious parts):**
  - **Inactive-tail padding:** confirm a prover cannot use the inactive-hop
    fallbacks (parent values, RegRoot==RegRoot gate, IsValid gating) to smuggle an
    invalid active hop. The contiguous-prefix constraint is the linchpin.
  - **Leaf selector:** confirm `isLeaf` selects exactly one hop and that
    `leafAmt/leafCur` cannot be steered to a non-leaf hop.
  - **Range bounds:** confirm every comparison operand is range-checked (no
    64-bit/32-bit gap that allows wraparound).
  - **EdDSA gadget usage:** confirm the message passed to `IsValid` is the same
    field element the issuer signs natively (scope commitment), and that the MiMC
    challenge hash matches native `MIMC_BN254`.
  - **Membership ↔ signature binding:** confirm the same `PubKey[i]` is used for
    both the signature check and the membership leaf, so a valid signature from an
    unregistered key cannot pass.

## Known limitations (in scope to state, not defects)

- POC trusted setup (no MPC ceremony yet).
- Baby Jubjub + Groth16/BN254 are **classical-security only** (not post-quantum);
  the authoritative signature line is Ed25519 → planned PQ-hybrid.
- The conformance vectors (`docs/conformance-vectors.json`) cover the canonical
  hashes, not the proofs; circuit soundness is exactly what the independent audit
  should establish.
