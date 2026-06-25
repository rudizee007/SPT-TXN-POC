# M3 + M4 implementation notes

Built fresh against the M2 (`internal/cattoken`) patterns: pure Go standard
library, EdDSA/Ed25519 compact JWTs, `txn_token_type` discriminator,
`human_anchor` propagated unchanged down the chain. Module path
`github.com/violetskysecurity/spt-txn-poc`.

## What was added

**M3 — Capability Token + scope attenuation**

- `internal/tbac/scope.go` — deterministic scope-containment check. Numbers are
  ceilings (child ≤ parent), strings/bools are equality, lists are subset,
  objects recurse. A dimension present in the child but absent in the parent is
  rejected (cannot grant unheld authority). This is the POC stand-in for the v2
  Cedar interop; the `Contains`/`Attenuate` API is what the swap must preserve.
- `internal/cttoken/cttoken.go` — verifies the parent CAT, attenuates scope,
  decrements `delegation_depth_remaining`, references the parent
  (`spt_cat_ref`, `spt_parent_hash`), signs with the `ct_issuer` key.

**M4 — SPT-Txn Token + DPoP + 30s TTL**

- `internal/dpop/dpop.go` — RFC 9449 subset. `Thumbprint` (RFC 7638 JWK SHA-256
  thumbprint of the Ed25519 holder key) is the `cnf.jkt` sender constraint;
  `Proof`/`Verify` handle proof-of-possession.
- `internal/txntoken/txntoken.go` — verifies the parent CAP, enforces the
  sender-constraint chain (holder must equal the CAP holder), checks the
  concrete transaction is within capability scope, binds it via
  `spt_txn_context_hash`, issues a 30-second token. Helpers `VerifyContextHash`
  (M5 Step 8) and `CheckSenderConstraint` (M5 Step 5) are included for the
  verifier.

## The blockchain-agnostic boundary (the important part)

`internal/ledger` is the adapter boundary. The token core never imports a
chain. It depends only on `ledger.Ledger`:

```
Name() string
Validate(TxnContext) error
Canonicalize(TxnContext) ([]byte, error)   // deterministic hash preimage
```

`spt_txn_context_hash = SHA-256(adapter.Canonicalize(tc))`, and the token
records `spt_txn_chain` so a verifier on another host selects the same adapter
and recomputes the identical hash. Two adapters ship:

- `Generic` (`"none"`) — chain-neutral default and the reference implementation.
- `XRPL` (`"xrpl"`) — canonicalizes the fields of an XRPL `Payment`
  (Account/Destination/Amount/Currency/DestinationTag). It can reference the
  on-ledger anchor from XRPL's Credentials amendment (activated 2025-09-04) and
  DID standard via `Extra["credential"]` / `Extra["did"]`, **complementing**
  that native KYC layer rather than duplicating it. It does not touch the
  network — submission/verification belong to a separate client.

Adding a chain = one new file implementing `Ledger` + `Register(...)` in
`init()`. SPT-Txn stays a target-integrator, never a dependent.

## Where the Travel Rule component plugs in (next)

The Travel Rule layer is itself chain-agnostic and sits on top of M3/M4: map
IVMS101 originator/beneficiary fields to selectively-disclosable claims (SD-JWT,
building on the `human_anchor` commitment already propagated), carry them in the
SPT-Txn token bound to the payment via `spt_txn_context_hash`, and prove the
private predicates (VASP registration, sanctions screen, threshold) with ZK
instead of shipping raw PII. The XRPL adapter's anchor reference is how the
off-ledger attestation links to on-ledger Credentials/DID.

## Honest POC caveats

- ZK proof verification is **stubbed** project-wide (commitment is real,
  SHA-256 substituting Poseidon per `internal/zkdid`). The "zero-knowledge"
  property of the Travel Rule story is architecturally placed but not yet
  cryptographically enforced — a v2 task (gnark/Groth16).
- DPoP omits `ath` binding and server-side replay/nonce state (v2).
- XRPL address validation is shape-only (no base58check) in the POC.
- Trust Registry remains mock/in-memory; the chain backend is the documented v2
  swap behind the existing `Registry` interface.

## Run the tests (on the OpenBSD host)

```sh
sh scripts/m3m4-test.sh
# or:
go test ./internal/...
```
