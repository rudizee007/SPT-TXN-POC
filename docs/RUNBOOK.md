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
Note (F1, phase 1): the circuit now proves each hidden hop's issuer is a member of
`regRoot`, but does **not** yet prove the issuer *signed* the hop (see the security
review). The chain circuit changed — regenerate keys: `go run ./cmd/zk-setup -dir ./zk`.

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
