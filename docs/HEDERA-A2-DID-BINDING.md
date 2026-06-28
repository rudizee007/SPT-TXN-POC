# Hedera A2 — bind the humanAnchor / CAT to a Hedera DID (design, for sign-off)

Grant milestone A2 makes the SPT-Txn identity layer **resolvable on Hedera**: the
CAT issuer (and, optionally, the subject) is expressed as a `did:hedera` whose DID
document is anchored on the Hedera Consensus Service and resolved keyless via the
mirror node, and the privacy-preserving **humanAnchor** is bound into it. A1
anchored a *hash*; A2 anchors an *identity document* and ties the token chain's
root of trust to it.

## How the Hedera DID method works (and our scope)

The Hedera DID method (`did:hedera`) does **CRUD via HCS messages** and **Read
(resolution) via the mirror node** — exactly the mechanism A1 already uses. A DID
document is reconstructed by folding the create/update/delete events published to
the DID's topic. Identifier shape: `did:hedera:testnet:<key-multibase>_<topicId>`.

**Scope decision (be explicit):** the maintained DID SDKs are **JavaScript and
Java only — there is no Go DID SDK.** So our Go client cannot call a certified
implementation; it would implement the method's *mechanism* (HCS-anchored DID
events + mirror-node resolution) itself. We will therefore ship A2 as a **POC
interpretation that follows the method's mechanism faithfully** (DID document over
HCS, keyless mirror resolution), clearly labeled as not the certified
`did-sdk-js`/`did-sdk-java` envelope. Full method conformance (exact event/proof
format, interop with the canonical resolvers) is documented as a gap and a funded
follow-up. This mirrors how A1 was scoped: real mechanism, honest about what is and
isn't certified.

## What gets bound

- **Issuer DID.** The CT/CAT issuer's Ed25519 key — the same key the Trust
  Registry holds — becomes a `verificationMethod` in a `did:hedera` document. The
  CAT (already a W3C Verifiable Credential) then names that `did:hedera` as its
  `issuer`, so a verifier can resolve the issuer's key from Hedera rather than only
  from the local registry.
- **humanAnchor.** The subject's humanAnchor — a Poseidon2 **zero-knowledge
  commitment** to identity material, already threaded through every token — is
  bound into the DID document as a dedicated service/claim
  (`SptTxnHumanAnchor`). Because the anchor is a *hiding* commitment, publishing it
  on-ledger exposes **no PII**: it is safe to anchor, and it links the on-Hedera
  identity to the off-ledger zkDID without revealing the person.
- This is the zkDID concept made resolvable on Hedera. Toby Bolton's `.zkdid`
  remains an **integration target, not a dependency** — A2 uses Hedera's native DID
  rails; `.zkdid` interop is separate.

## Mechanism (reuses A1)

- `did-create` (operator action, needs key + HBAR): build a minimal W3C DID
  document — `id`, the issuer `verificationMethod` (Ed25519), `assertionMethod`,
  and the `SptTxnHumanAnchor` service carrying the commitment hex — and publish it
  as a DID-create event to a fresh HCS topic, yielding `did:hedera:testnet:…_<topic>`.
- `did-resolve` (keyless): GET the topic's messages from the public mirror node,
  fold the events, and return the resolved DID document — no key, no cost, anyone
  can verify, same as A1's `verify`.
- Implementation lives in the existing **separate module** `clients/hcs-anchor`
  (the SDK stays out of the core). The DID-document assembly is plain stdlib JSON;
  the submit path reuses the A1 SDK code; resolution reuses the A1 mirror client.

## Security

Only public keys and a hiding commitment are published — never PII, never private
keys. Testnet by default. The operator key comes from the environment as in A1.
The humanAnchor's secrecy rests on the commitment's hiding property (Poseidon2),
not on the ledger being private.

## Status / next

Built 2026-06-28 (issuer-DID, Go POC interpretation): `clients/hcs-anchor` gained
`did.go` (base58btc, Ed25519 `publicKeyMultibase`, `BuildIssuerDID`, the `DIDEvent`
encode/parse, and `ResolveFromEvents` fold), a `fetchTopicMessages` mirror reader,
and the `did-create` / `did-resolve` subcommands. The DID-document assembly,
event round-trip, resolution fold, and DID parsing are unit-tested with no network
(`did_test.go`).

Operator-side (your action, testnet): build, then
`did-create -anchor <humanAnchor>` (publishes the DID create event to a new HCS
topic) and `did-resolve -did …` (keyless mirror-node resolution) — producing a live
resolvable `did:hedera:testnet:…` whose document carries the SPT-Txn issuer key +
humanAnchor, a second Hedera milestone footprint alongside the A1 anchor (topic
`0.0.9357269`). Honest gaps for full conformance: certified did-sdk event/proof
format, subject DID + CAT-VC issuer linkage, and update/revoke events (only
create + a generic update fold are implemented). A3 (Hedera Guardian policy
interop) builds on this.
