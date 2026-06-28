# hcs-anchor — Hedera Consensus Service anchoring (milestone A1)

Anchors an SPT-Txn `spt_txn_context_hash` (or an audit-log Merkle root) to a
Hedera Consensus Service (HCS) topic, and verifies anchors via the public mirror
node. Design rationale is in [`../../docs/HEDERA-HCS-ANCHORING.md`](../../docs/HEDERA-HCS-ANCHORING.md).

**Why a separate module.** The Hedera SDK is heavy and chain-specific. Keeping it
in its own module guarantees the SPT-Txn authorization core (the `internal/` and
`cmd/` packages of the main module) can never import a ledger SDK — the
blockchain-agnostic invariant, enforced by the module boundary, not just by
convention.

## Build

```
cd clients/hcs-anchor
go get github.com/hiero-ledger/hiero-sdk-go/v2@latest
go mod tidy
go build .
go test .          # envelope round-trip / validation (no network, no SDK calls)
```

## Use

`create-topic` and `anchor` need a funded testnet operator account; `verify` needs
nothing. Credentials come from the environment, never flags:

```
export HEDERA_OPERATOR_ID=0.0.XXXXX
export HEDERA_OPERATOR_KEY=302e0201...        # operator private key

# one-time: make a topic
./hcs-anchor create-topic -network testnet
# → created HCS topic 0.0.YYYYY on testnet

# anchor a real token-derived context hash (from the main module's cmd/anchor):
#   (cd ../../ && go run ./cmd/anchor -chain hedera)   # prints spt_txn_context_hash
./hcs-anchor anchor -network testnet -topic 0.0.YYYYY -type ctx -hash <64hex>

# verify — keyless, free, anyone can run it against the public mirror node:
./hcs-anchor verify -network testnet -topic 0.0.YYYYY -hash <64hex>
# → ANCHORED  ... consensus timestamp : 1750000000.123456789
```

### DID binding (milestone A2)

Anchor an issuer `did:hedera` whose document carries the CT-issuer key and binds
the humanAnchor, then resolve it keyless from the mirror node. Design:
[`../../docs/HEDERA-A2-DID-BINDING.md`](../../docs/HEDERA-A2-DID-BINDING.md).

```
# create a DID (generates a demo issuer key unless -issuer-pub is given; binds the humanAnchor)
./hcs-anchor did-create -network testnet -anchor <64hex-humanAnchor>
# → created DID: did:hedera:testnet:<key>_0.0.ZZZZZ

# resolve it — keyless, public mirror node
./hcs-anchor did-resolve -did did:hedera:testnet:<key>_0.0.ZZZZZ
```

Verify with no Go at all (pure mirror-node REST):

```
curl -s "https://testnet.mirrornode.hedera.com/api/v1/topics/0.0.YYYYY/messages?limit=100&order=asc" \
  | jq -r '.messages[].message' | base64 -d
# each line is a {"v":1,"t":"ctx","h":"<hash>","ts":...} envelope
```

## Message format

A tiny, self-describing, versioned JSON envelope (canonical field order):

```json
{"v":1,"t":"ctx","h":"<64-hex>","ts":1750000000}
```

`t` is `ctx` (an `spt_txn_context_hash`) or `audit` (an audit-log Merkle root).
`ts` is the submitter's clock and is informational only — the **authoritative**
anchoring time is the HCS consensus timestamp the network assigns, which `verify`
reports.

## Boundaries

- This client submits transactions and holds the operator key; the SPT-Txn core
  does not. Run it yourself — anchoring spends HBAR and is your action.
- Testnet by default. A mainnet anchor is permanent and public (a hash only, no
  PII), but is a deliberate, funded step.
- Custody `HEDERA_OPERATOR_KEY` carefully; prefer a throwaway testnet key.
