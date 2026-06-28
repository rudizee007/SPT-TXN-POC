# Scaling & storage substrate (architecture direction)

A decision record for "how does SPT-Txn scale beyond one OpenBSD host, and what
should the off-hot-path storage substrate be." Direction, not a finished build —
some items (anchor frequency, chain choice) are deliberately left open.

## The principle that drives every decision

SPT-Txn's strategic value is that **verification is offline, cryptographic, and
stateless** — a verifier checks signature, scope chain, humanAnchor, and
transaction binding without phoning home. That is what makes the one-sided
adoption model work. So the scaling rule is absolute: **the verification path
stays stateless and horizontally scalable; nothing in the hot path requires a
single authoritative server.** Preserve that and scaling is easy; violate it and
you've rebuilt the chokepoint the design exists to avoid.

## The one host does three jobs that scale differently

- **Verifier — stateless.** Token + cached registry snapshot + transaction
  context → verify → done. Sub-millisecond, remembers nothing. Scales
  horizontally without limit; the strongest form is **shipping it as a library**
  that runs inside each consumer's own infrastructure, so there is no server to
  scale or pay for. This part must never be a bottleneck.
- **Issuer (`catsvc`) — per-participant.** Holds signing keys, so its constraints
  are **key custody / HSM / threshold signing / audit**, not throughput. In
  production each VASP / agent platform runs its own issuer — there is no global
  issuer to scale. The operational hard problem here is keys, not load.
- **Trust Registry — the real question.** Authoritative, tamper-evident, globally
  readable — but **hot-path reads must hit a local cache**, never the authoritative
  source, or offline verification dies. Clean split: the authoritative root lives
  on a tamper-evident substrate (an L1/L2 Merkle root), updates are rare, and every
  verifier holds a **synced, signed snapshot it reads locally**. Writes rare/slow;
  reads local/instant.

## Stateless ≠ serverless

- **Stateless** is an architectural property (no persistent state between
  requests). The verifier has it.
- **Serverless** (Lambda / Cloud Functions) is a hosting/billing model.
- Stateless components *can* run serverless, but needn't. The strongest option
  here is **library-embedded** (zero servers), then **N small Go daemons behind
  relayd**, with serverless only as a later convenience for participants who won't
  embed the library — and even then only for the stateless half, never storage.
  Don't reach for GCP/Azure serverless yet: it solves an elasticity problem we
  don't have at one-host scale and pulls us back toward being a chokepoint/service
  rather than a library others embed.

## Storage substrate comparison (off the hot path only)

Scored for a security-positioned, OpenBSD-based, solo-maintained project:
assurance/audit burden, OpenBSD fit, and how much trust-critical code we own vs.
inherit.

| Substrate | Assurance / audit | OpenBSD fit | Trust-critical code ownership |
|---|---|---|---|
| **On-chain Merkle root** | Strong — tamper-evidence from chain consensus; our part (compute root, post, verify inclusion) is tiny and self-auditable | Good — a light client / RPC call; the heavy node is someone else's | High (our anchoring/verify) + trust root delegated to a well-understood chain |
| **Signed snapshots in Go** | Strong — almost nothing inherited; Ed25519 over a canonical blob, small enough to fully review | **Best** — pure Go, no cgo, pledge/unveil-clean, no new daemon | **Maximal** — we wrote every security-relevant line |
| **IPFS / content-addressed** | Moderate — CID=hash is sound; the libp2p/DHT/pinning stack is large and not for the trust core | Mediocre — kubo is Go but a heavy daemon with networking surface | Integrity yes (verify CIDs); availability delegated |
| **DWN (`dwn-sdk-js`)** | **Weakest** — DRAFT spec, **0 npm maintainers**, never audited; the permission/revocation logic (the relevant part) is exactly what's unvetted; crypto primitives (@noble) are fine, the DWN layer on top is not | Poor — Node stack, polyfill-heavy deps, stateful sync daemon; no clean pledge/unveil | Lowest — authorization/revocation semantics would live in inherited, unmaintained code |

## Mapping to the four stateful needs

- **Audit / Merkle trail (M6)** → **on-chain Merkle root.** Append-only,
  tamper-evident, no PII (commitments only); makes the blockchain-agnostic claim
  *true* — the chain does exactly one well-scoped job. Build the tree in Go,
  anchor the root periodically. (`cmd/auditverify` already recomputes + checks it.)
- **Registry snapshot distribution** → **signed snapshots in Go**, optionally with
  the snapshot root also anchored on-chain for public verifiability. Verifiers
  pull, check the signature locally, read locally — hot path stays offline.
- **Escrow envelopes (M7)** → **storage we control** (own signed/encrypted blobs).
  This is an encryption-scheme question (ECIES / t-of-n threshold), not a substrate
  one; the most sensitive data must not sit behind a third party's unvetted
  access-control logic.
- **Human-anchor data** → **storage we control, encrypted.** PII-adjacent; the
  *commitment* may be anchored or carried in the token, but the data itself never
  goes to IPFS or DWN. A liability decision as much as a technical one.

## Verdict

A **two-substrate design**: an **on-chain Merkle root** as the tamper-evident
anchor for the audit trail and (optionally) registry-snapshot roots, plus
**signed snapshots / replicated storage in Go** for the actual bytes (registry
contents, escrow, human-anchor). This maximizes assurance (we own or self-audit
nearly all trust-critical code), fits OpenBSD natively (pure Go, no heavy
daemons), and makes "blockchain-agnostic" genuine — the chain anchors roots and
nothing more.

- **IPFS** earns a conditional place only if decentralized *public availability* of
  non-sensitive blobs is later needed — and then only its content-addressing, not
  its networking.
- **DWN** is **design inspiration, not infrastructure.** Its DID-native,
  owner-controlled, capability-delegation + message-encryption patterns are worth
  studying for M7. Do not take a code or spec dependency: a DRAFT spec with a
  never-audited, zero-maintainer reference implementation (and the Google Cloud
  community node being explicitly non-production, with TBD wound down) is exactly
  the dependency/assurance risk we rejected the Python issuer and SQLite to avoid.

## The one action to take now (cheap, high-value)

On the single OpenBSD host, **split verifier / issuer / registry-sync into
separate sandboxed, single-purpose daemons with clean interfaces.** Then "scaling"
becomes "run more of the stateless ones + pick the registry substrate" rather than
"re-architect a monolith." This is discipline, not infrastructure, and it
preserves the OpenBSD security narrative (small, pledged, single-purpose daemons).

## Open items (research not finished)

- Anchor frequency (every N records vs. time-based) — a cost/tamper-evidence
  tradeoff; the only place chain choice actually bites (pick a chain whose finality
  + cost suit infrequent small writes; anchoring is off the hot path so it never
  touches verification latency).
- Threshold/HSM signing for issuers and the escrow t-of-n custody across
  jurisdictions — the real operational scaling constraint (security, not throughput).
- Whether to publish a reference verifier library (Go) as the primary "stateless"
  artifact, with any hosted endpoint as a secondary convenience.
