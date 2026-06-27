# SPT-Txn Attestation Anchor (Ethereum / EVM)

A minimal Solidity contract that anchors SPT-Txn attestation roots (32-byte
SHA-256 values, as `bytes32`) on-chain. It's the on-chain half of the EVM
integration — the off-chain transaction-binding lives in
`internal/ledger/ethereum.go`. Because the major L2s are EVM-equivalent, the
**same bytecode deploys on Ethereum L1 and every EVM L2** (Arbitrum, Optimism,
Base, Scroll, Linea, …) — one contract, many chains.

No token, no owner, no upgradeability — a minimal public good (Apache-2.0).

## Interface
- `anchor(bytes32 root) → uint256 index` — append a root (anyone may call); emits `Anchored`.
- `getCount() → uint256` — number of anchors.
- `getAnchor(uint256 index) → Anchor{root, submitter, timestamp}` — read one back.

Layout: `foundry.toml` + `src/AttestationAnchor.sol` (a self-contained Foundry project, no dependencies).

## Build (Foundry)
```
# install Foundry once: curl -L https://foundry.paradigm.xyz | bash && foundryup
cd solidity
forge build
```

## Deploy to a testnet (Foundry) — same command, any EVM chain
Set an RPC + a funded testnet key (use a throwaway key; never a mainnet key).
```
export RPC=https://sepolia.infura.io/v3/<KEY>     # or Base Sepolia, Arbitrum Sepolia, Optimism Sepolia, …
export PK=0x<testnet-private-key>

forge create src/AttestationAnchor.sol:AttestationAnchor \
  --rpc-url "$RPC" --private-key "$PK" --broadcast
# → prints the deployed contract address (the on-chain footprint)
```
Repeat with a different `$RPC` to deploy on each EVM L2 — identical contract.

## Anchor a root + read it back (cast)
```
export ADDR=0x<deployed-address>

# anchor a 32-byte root (bytes32). Use a REAL SPT-Txn ContextHash.
cast send "$ADDR" "anchor(bytes32)" \
  0x4b505b308a910db95f580c5493a9c35d766516b7d12774e412a7ac53cb4b60b9 \
  --rpc-url "$RPC" --private-key "$PK"

cast call "$ADDR" "getCount()(uint256)" --rpc-url "$RPC"
cast call "$ADDR" "getAnchor(uint256)((bytes32,address,uint64))" 0 --rpc-url "$RPC"
```

## For the Ethereum Foundation ESP grant
- **Public good, no token, Apache-2.0** — meets ESP eligibility.
- **Benefits multiple L2s** — one contract + one adapter covers Ethereum + all EVM L2s, an explicit ESP selection criterion.
- **Next on-chain steps (grant scope):** an on-chain **ZK verifier** for the SPT-Txn selective-disclosure attestation (verify a proof without revealing the data), and a reusable **SDK/schema for scoped disclosure requests** — mapping to the ESP ZK "auditable privacy / compliant transparency" wishlist item.
- **Honest framing:** the off-chain transaction-binding is implemented + tested; this anchor contract is the first on-chain artifact; the ZK verifier + disclosure SDK are the funded deliverables, not built yet.
```
```
