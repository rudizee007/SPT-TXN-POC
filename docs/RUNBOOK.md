# SPT-Txn — operational runbook

Reproducible steps for the operational processes. All commands assume the repo
root and Go 1.25 + gnark v0.15 (build on the Mac/OpenBSD host, not the sandbox).
**Never use a mainnet key for any of this** — all on-chain steps use throwaway
testnet keys. Placeholders are in `<UPPERCASE>`.

## 1. ZK trusted setup (one-time per circuit)

```
go run ./cmd/zk-setup -dir ./zk
```
Writes `{commitment,threshold,vasp,chain}.{ccs,pk,vk}` to `./zk` (gitignored). The
prover loads ccs+pk; a verifier loads only the vk. Re-run if a circuit changes.

## 2. End-to-end anchoring (tie a real token to an on-chain anchor)

```
go run ./cmd/anchor -chain ethereum                 # mints CAT→CT→SPT-Txn, prints the real spt_txn_context_hash + calldata
go run ./cmd/anchor -chain ethereum -onchain <ROOT> # compare an on-chain root to the token's hash → MATCH/MISMATCH
```
Chains: ethereum, xdc, starknet, aptos, solana, stellar, hedera, algorand, xrpl,
arbitrum. The printed calldata is per-chain (EVM `bytes32`, Cairo `u256` low/high,
Move `hex:`, Solana memo).

## 3. Deploy the anchor + ZK verifier to an EVM chain (Foundry)

```
cd solidity && forge build
export RPC=<CHAIN_RPC>          # e.g. https://sepolia-rollup.arbitrum.io/rpc
export PK=0x<THROWAWAY_KEY>     # fund it first (faucet, or bridge — see §3a)
forge create src/Groth16Verifier.sol:Verifier --rpc-url "$RPC" --private-key "$PK" --broadcast
forge create src/AttestationVerifier.sol:AttestationVerifier --rpc-url "$RPC" --private-key "$PK" --broadcast --constructor-args <VERIFIER_ADDR>
forge create src/AttestationAnchor.sol:AttestationAnchor --rpc-url "$RPC" --private-key "$PK" --broadcast
```
The same bytecode deploys on Ethereum L1 and every EVM L2 — only `$RPC` changes.

### 3a. Funding an L2 testnet key via the canonical bridge (CLI, no wallet)

Get Sepolia L1 ETH (pk910 PoW faucet, no mainnet gate), then deposit to the L2 via
its Inbox `depositEth()` — credits the **same address** on L2:

```
# Arbitrum Sepolia Inbox (on Ethereum Sepolia L1):
cast send 0xaAe29B0366299461418F5324a79Afc425BE5ae21 "depositEth()" \
  --value 0.05ether --rpc-url https://ethereum-sepolia-rpc.publicnode.com --private-key "$PK"
# wait ~10–15 min, then: cast balance <ADDR> --rpc-url "$ARB_RPC"
```

## 4. Generate the on-chain ZK verifier (gnark → Solidity)

```
go run ./cmd/zk-export-solidity -circuit threshold -dir ./zk -o solidity/src/Groth16Verifier.sol
```
Exports from the PINNED vk so the on-chain verifier matches the prover's key. The
generated `verifyProof(bytes proof, uint256[2] input)` reverts on an invalid proof.

## 5. Prove a ZK predicate on-chain

```
export ADDR=<ATTESTATIONVERIFIER_ADDR>
go run ./cmd/zk-solcalldata -dir ./zk -amount 5000 -threshold 1000 -root <ROOT> -addr "$ADDR"
# run the printed `cast send …` (with $RPC/$PK exported)
cast call "$ADDR" "getCount()(uint256)" --rpc-url "$RPC"     # → increments on success
```
Tamper test: flip one hex char in the proof bytes and re-send (or `cast call`) — it
reverts (`0x7fcdd1f4`, the verifier's invalid-proof error).

## 6. Deploy to Starknet (sncast) / Aptos (aptos CLI)

```
# Starknet (Cairo): cd cairo/attestation_anchor — use sncast + scarb 2.18, NOT starkli 0.4.2
sncast --account spt declare --contract-name AttestationAnchor --network sepolia
sncast --account spt deploy --class-hash <HASH> --network sepolia
sncast --account spt invoke --contract-address <ADDR> --function anchor --calldata <LOW> <HIGH> --network sepolia

# Aptos (Move): cd move/attestation_anchor
aptos move publish --named-addresses spt_txn=default --assume-yes
aptos move run --function-id default::attestation_anchor::init_book --assume-yes
aptos move run --function-id default::attestation_anchor::anchor --args address:<BOOK_OWNER> hex:0x<ROOT> --assume-yes
```

## 7. Wire the optional ZK N-hop verifier mode (caller side)

The `verifier` package is gnark-free; inject a `ChainVerifierFunc` that derives the
leaf-scope commitment from the presented leaf scope and binds the proof to the
operator's OWN trusted registered-CT-issuer root (`regRoot`, captured in the
closure — not carried in the proof). The prover builds the proof with
`ProveChain(..., registry)` where each `ChainHop.Issuer` is a registry member:

```go
art, _ := zkproof.Load(zkproof.CircuitChain, "./zk")
regRoot := myIssuerRegistry.Root() // *big.Int — the operator's trusted CT-issuer set
eng.ChainVerifier = func(proof []byte, h0 *big.Int, leafMax uint64, leafCur string, d uint64) error {
    cleaf := zkproof.LeafScopeCommitment(leafMax, zkproof.CurrencyCode(leafCur))
    return art.VerifyChain(proof, h0, cleaf, regRoot, d)
}
```
Then a presentation with `Input.ChainProof`/`ChainH0` set runs `step6ChainZK`.

Note (F1, closed): each active hop now proves, in-circuit, a registered CT-issuer's
Baby Jubjub EdDSA signature over its scope (+ membership in `regRoot`). Build each
`ChainHop` with `IssuerPub` (the issuer's `eddsa.PublicKey.Bytes()`) and `Sig` (the
issuer's signature over `LeafScopeCommitment(MaxAmount, Currency)`, MiMC_BN254
challenge); build the registry over `zkproof.IssuerLeaf(pub).Bytes()`. Issuers
dual-key (Ed25519 for JWS/VC + Baby Jubjub for ZK). The chain circuit changed —
regenerate keys: `go run ./cmd/zk-setup -dir ./zk`.

## 8. Website deploy (OpenBSD host)

```
scp web/index.html tarzan@foss.violetskysecurity.com:/tmp/index.html
ssh tarzan@foss.violetskysecurity.com 'doas cp /tmp/index.html /var/www/htdocs/foss.violetskysecurity.com/index.html && doas chown root:wheel /var/www/htdocs/foss.violetskysecurity.com/index.html && doas chmod 644 /var/www/htdocs/foss.violetskysecurity.com/index.html && rm /tmp/index.html'
```
relayd changes: `scp configs/relayd.conf …`, then `doas relayd -n -f /etc/relayd.conf && doas rcctl reload relayd`.

## 9. Visitor analytics over SSH (GoAccess)

httpd `log style forwarded` (so XFF carries the real IP), then:
```
ssh -t tarzan@foss.violetskysecurity.com 'doas goaccess /var/www/logs/foss.access.log \
  --log-format="%v %h %^[%d:%t %^] \"%r\" %s %b \"%R\" \"%u\""'
```

## 10. Security audit (host)

```
doas sh scripts/security-audit.sh        # host-runnable checks; target FAIL=0
go test ./...                            # full suite, including the ZK + verifier tests
```
See `docs/SECURITY-REVIEW.md` and `docs/SECURITY-REVIEW-2026-06-28.md`.

## 11. Hedera HCS anchoring (milestone A1)

Anchor a real token-derived context hash to a Hedera Consensus Service topic. The
client is a **separate module** (`clients/hcs-anchor`) so the Hedera SDK never
enters the core. Design: `docs/HEDERA-HCS-ANCHORING.md`.

```
# build the client (own module)
cd clients/hcs-anchor && go get github.com/hiero-ledger/hiero-sdk-go/v2@latest && go mod tidy && go build .

# operator creds in the environment (never flags)
export HEDERA_OPERATOR_ID=0.0.XXXXX HEDERA_OPERATOR_KEY=302e0201...

./hcs-anchor create-topic -network testnet                       # → topic 0.0.YYYYY
HASH=$(cd ../.. && go run ./cmd/anchor -chain hedera | awk '/context_hash/{print $3}')
./hcs-anchor anchor -network testnet -topic 0.0.YYYYY -type ctx -hash "$HASH"
./hcs-anchor verify -network testnet -topic 0.0.YYYYY -hash "$HASH"   # keyless mirror-node proof
```
`verify` (and the equivalent mirror-node `curl`) needs no key and no HBAR.

## 12. First mainnet footprint (EVM L2)

Turns the POC from "testnet-only" into "production-touching" with one real,
permanent anchor. The Solidity is build-once-deploy-many, so this is §3 with a
mainnet RPC and a **real, funded, dedicated** key. This is YOUR action — Claude
cannot deploy contracts or move funds.

**Chain choice.** An L2 mainnet keeps fees to roughly cents. Default **Arbitrum
One** (continuity with the Arbitrum Sepolia work and the Multichain grant); **Base
mainnet** is a one-line RPC swap. Both reuse the exact bytecode already proven on
Sepolia.

```
# Arbitrum One:  RPC=https://arb1.arbitrum.io/rpc
# Base mainnet:  RPC=https://mainnet.base.org
export RPC=https://arb1.arbitrum.io/rpc
export PK=0x<DEDICATED_MAINNET_KEY>      # NEVER a testnet throwaway key; fund with a little real ETH

cast gas-price --rpc-url "$RPC"          # sanity-check current fees BEFORE deploying
cast balance <ADDR> --rpc-url "$RPC"     # confirm the key is funded

cd solidity && forge build
# Minimal, cheapest meaningful footprint: the plain append-only anchor.
forge create src/AttestationAnchor.sol:AttestationAnchor --rpc-url "$RPC" --private-key "$PK" --broadcast

# Anchor ONE real token-derived hash:
HASH=$(cd .. && go run ./cmd/anchor -chain arbitrum | awk '/context_hash/{print $3}')
cast send <ANCHOR_ADDR> "anchor(bytes32)" 0x$HASH --rpc-url "$RPC" --private-key "$PK"

# Verify the on-chain root equals the token's hash (read-only, free):
cd .. && go run ./cmd/anchor -chain arbitrum -onchain <ON_CHAIN_ROOT>   # → MATCH
```

Then record the address in `docs/STATUS.md` (Live on-chain footprints).

**Safeguards / honesty:**
- **Never reuse a testnet key on mainnet.** Generate a fresh key used only here,
  fund it with the minimum, and treat it as disposable-but-real.
- A mainnet anchor is **permanent and public** — but it is only a 32-byte hash, no
  PII, no token contents; nothing sensitive is exposed.
- The append-only anchor is open by design (finding F2): fine for a single
  footprint, but a production mainnet deployment should add access control or an
  anti-spam fee first.
- The on-chain **ZK verifier** (`Groth16Verifier` + `AttestationVerifier`) is
  heavier gas; deploy it to mainnet only if you specifically want a mainnet ZK
  demo — the plain anchor is enough for a footprint.
