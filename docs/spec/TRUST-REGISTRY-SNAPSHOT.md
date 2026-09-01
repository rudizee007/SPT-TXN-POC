# Trust Registry Snapshot — format & verification

**Status:** DRAFT. Specifies the trust-registry snapshot format and the offline
verifier's obligations. Trust-boundary component: spec → implement → adversarial
review in a fresh context → tests → maintainer line-by-line.

**Normative language:** MUST / MUST NOT / SHOULD as in RFC 2119.

---

## 1. Purpose

A trust-registry snapshot is the **root of trust for every offline
verification**: it is the locally held set of issuer keys a PEP evaluates a
presentation against, with no network call. Because it is the root of trust, a
verifier MUST establish its **authenticity** before trusting any record in it. A
snapshot accepted on filesystem permissions alone is not a root of trust — anyone
who can write the file can add an issuer key and every downstream check will pass
against a key they chose. Verifying that a snapshot merely *exists* is not
verifying that it is *authentic*.

Reproducing the signed bytes is a canonicalization problem across two
implementations: the bytes are produced by the signer and MUST be reproduced
exactly by the verifier. §3 pins those bytes; the vectors in
`trust-snapshot-signing-v1.kat.json` are the executable form and MUST be a CI
gate wherever a snapshot is signed or verified.

---

## 2. Two artifacts: manifest and body

A snapshot has two parts, and conflating them is an error.

| | **Manifest** | **Body** |
|---|---|---|
| Shape | `{id, issued_ms, issuer_ids[], digest_hex, prev_snapshot_id}` | `{version, records[]}` |
| Contents | issuer **ids** + a digest | full records (keys, validity, status) |
| Signed | **yes**, detached ed25519 | no |
| Chained | **yes** (`prev_snapshot_id`) | no |

The manifest states *what is in the set, chained, and signed*. The body holds
*the actual records*. The manifest commits to the body through `digest_hex`: a
verifier checks the signature over the manifest, then checks that the body it
holds hashes to `digest_hex`. A conforming distribution ships **both**. A verifier
handed only a body has no root of trust and MUST fail closed.

---

## 3. Manifest signing input (NORMATIVE)

The detached signature covers exactly these bytes:

```
{"digest_hex":<s>,"domain":"spt-cp/trust-snapshot-v1","id":<s>,"issued_ms":<u64>,"issuer_ids":[<s>,...],"prev_snapshot_id":<s|null>}
```

The signature is `ed25519(publication_private_key, signing_input)`, hex-encoded,
detached, and verified strictly. The domain tag `spt-cp/trust-snapshot-v1` is a
field inside the signed object, giving cross-artifact domain separation (a
snapshot signature can never be replayed as another artifact type that uses a
different tag).

### 3.1 Canonicalization rules — the entire trap surface

These rules are load-bearing; a mismatch on any one produces different bytes and
a signature that will not verify.

1. **Object keys are SORTED** (lexicographic by UTF-8 byte), NOT in
   struct/field declaration order. The order is: `digest_hex`, `domain`, `id`,
   `issued_ms`, `issuer_ids`, `prev_snapshot_id`. Build the signing input from a
   sorted-key map, never from a struct whose fields serialize in declaration
   order.
2. **`prev_snapshot_id` is ALWAYS present**, as JSON `null` when there is no
   predecessor. ⚠️ The manifest's on-the-wire form MAY omit this field when
   absent, but the **signing input MUST include it as null**. An implementation
   that mirrors the wire form (drops the field when empty) will fail to verify
   every first-ever snapshot.
3. **Compact:** no whitespace between tokens.
4. **No HTML escaping:** `<`, `>`, `&` are emitted literally. (In Go, the
   standard encoder escapes these by default; disable it.)
5. **`/` is not escaped** — the domain tag contains one.
6. **`issued_ms` is a JSON integer** (unsigned 64-bit). Never a float, never a
   string. Beware decoders that turn JSON numbers into floats and corrupt large
   millisecond values.
7. **`issuer_ids` is an array in the given order.** Arrays are NOT sorted; only
   object keys are. The producer fixes the order and the signature binds it.

### 3.2 Charset constraint

`id`, `issuer_ids[]`, and `prev_snapshot_id` MUST be ASCII and traversal-free
(alphanumerics plus `-_.:`, sufficient for `did:web:` identifiers). Producers
MUST reject out-of-charset values. This removes any residual JSON-escaping
divergence surface before it can affect the signed bytes.

### 3.3 Known-answer vectors

`trust-snapshot-signing-v1.kat.json` fixes the golden signing-input bytes, their
SHA-256, the content digest, and the detached signature under a pinned test seed,
across four vectors: a first-ever snapshot (`prev` null), a chained snapshot, an
empty issuer set, and integers above 2^53.

**What the vectors are and are not evidence of.** An earlier version of this
paragraph said "two independent implementations have been confirmed
byte-identical on these vectors". That claim was inherited rather than verified,
and it is withdrawn. What has been established, on 2026-08-12, is narrower and
was tested rather than asserted: an implementation written in a fresh context
from `canonicalization_rules` and the vector inputs alone — with the reference
implementation, every `expected_*` value and every canonical byte fragment
withheld from its author — reproduced every positive vector byte-for-byte. So
the field sets are *derived from the rules*, not transcribed.

The negative vectors are **not** covered by that. They specify a mistake in
prose rather than in bytes, no trap names its base vector, and
`trapA_declaration_order` cannot be reproduced from this document at all — no
struct declaration order appears in it, and rule 1 explicitly disclaims the field
lists as orderings. The two traps this repository exercises
(declaration-order keys; dropped null `prev`) are confirmed to fail closed here,
against a golden this package computes itself.
Every repo that signs or verifies a snapshot MUST load these vectors as a CI gate:
assert the produced signing input equals `expected_signing_input_hex` and that
signing it with the seed yields `expected_signature_hex`.

The current vectors pin the format as it stands today (no algorithm field —
§3.4). Adopting §3.4 is a signing-input change and supersedes these vectors with
a `-v2` set; that is a deliberate, pre-deployment format bump, not a drift, and
the gate is regenerated with it.

### 3.4 Algorithm binding (NORMATIVE)

**Implemented 2026-08-15.** The signing input carries `alg` under domain
`spt-cp/trust-snapshot-v2`, in both the Go reference implementation and the Rust
control plane, gated by the regenerated cross-language vectors.

Registered values, matching `internal/suite` and the IANA JOSE/COSE spellings:

| `alg` | Construction |
|---|---|
| `EdDSA` | Ed25519 (RFC 8032). |
| `HYBRID-Ed25519-ML-DSA-65` | Ed25519 **and** ML-DSA-65 (FIPS 204). Two signatures, both present. |
| `HYBRID-Ed25519-ML-DSA-87` | Ed25519 **and** ML-DSA-87 (FIPS 204). NSS track. |
| `ML-DSA-87` | ML-DSA-87 alone. CNSA 2.0 end state — that suite contains no classical algorithm. |

Allowlist, byte-exact and case-sensitive. A verifier MUST reject a value outside
the set, MUST reject one outside its own accept-set (which may be narrower), and
MUST verify under exactly the named suite — never trial-verify against each
accepted suite, which reintroduces the ambiguity `alg` removes.

The `HYBRID-*` entries are **dual-signature envelopes**, not the composite
signatures of `draft-ietf-jose-pq-composite-sigs`: a composite cannot be verified
partially, and this profile needs verify-either during transition.

**What this closes, and what it does not.** `alg` is inside the signed object, so
relabelling fails — an attacker cannot take a hybrid-signed snapshot, call it
`EdDSA`, drop the ML-DSA component and present it to a verifier accepting both.
It does **not** prevent a publisher genuinely signing with a weaker suite; that
is the accept-set, which is policy. The format removes the ambiguity, the
deployment removes the permission.

`alg` is populated from the **signer**, never from configuration, and
`sign_snapshot` refuses to sign a snapshot whose declaration does not match the
signer it is handed. A declaration contradicting its own signature is worse than
none: it is a signed statement about how it was signed that is false.

The signing input MUST carry an explicit algorithm/suite identifier (`alg`),
covered by the signature. Without it, the choice of signature suite is not a
signed statement, and a verifier that accepts more than one suite cannot detect a
**downgrade**: an attacker presents a snapshot signed with the weaker of two
accepted algorithms and the verifier has no signed record of which suite was
intended. The domain tag `spt-cp/trust-snapshot-v1` versions the *format*; it
does not name the *suite*, and crypto-agility (classical → hybrid → PQC) is a
first-class requirement here.

This matters more for this artifact than almost any other because the publication
key is the **longest-lived key in the system**: air-gapped verifiers may pin it
for years, and OT assets run 20–30. Adding `alg` while nothing is deployed costs
nothing; retrofitting it after deployment is a format break on the one key that
cannot be rotated cheaply. Fold `alg` into the signing input as part of the
format definition (§5's session), bump the domain to `-v2`, and regenerate the
KAT. The verifier MUST reject a snapshot whose `alg` is not in its accepted set,
and MUST verify under exactly the named suite — never "whichever suite the
signature happens to satisfy."

---

## 4. Verifier flow (NORMATIVE)

A verifier loading a snapshot MUST, in order, and MUST fail closed on any
failure:

1. Load the manifest and the body.
2. Reconstruct the manifest signing input per §3 and verify the detached ed25519
   signature against the **pinned publication key** (§6). Reject on decode error,
   signature length ≠ 64 bytes, unknown key, or verification failure.
3. Recompute the body digest (§5) and compare it to `manifest.digest_hex`
   (plain equality — an integrity tag, not a secret). Reject on mismatch.
4. Enforce staleness (§7) against `issued_ms`.
5. Only then use the records for issuer-key lookups.

A verifier MUST NOT become usable from an unsigned snapshot or one whose body
digest does not match. A zero-record snapshot is a valid fail-closed fixture, not
a substitute for verification.

---

## 5. Body digest MUST commit to key material (NORMATIVE)

`digest_hex` MUST be a digest over the **full record set, including each record's
public-key bytes** (id, role, public key, key type, validity window, status), and
over the body's **`version`** field. It MUST NOT be computed over issuer *ids*
alone.

This requirement is the whole point of the body digest. If `digest_hex` covers
only the issuer ids and fields already present in the signed manifest, it binds
nothing the signature did not already bind, and an attacker can serve a body with
the same ids but **different public keys**: the signature is valid, the digest
matches, and the keys are the attacker's. The signature would then prove only
*which ids, and when* — never *what key material those ids map to*. A verifier
MUST NOT trust records whose key material is not covered by `digest_hex`.

**`version` must be inside the digested bytes.** The body carries a `version`
field, but a format version is not a binding — it protects against mis-parsing,
it authenticates nothing. If `version` is outside the digest, an attacker flips
it and the body is reinterpreted under different parsing rules while the digest
still matches. As it stands there is a signed manifest that says nothing about
key material and a versioned body that nothing vouches for: two halves with no
join. Digesting `version` with the records is what joins them.

Digest input canonicalization (its own trap surface, its own KAT):

- `digest_hex = hex(SHA-256(canonical_body))`.
- `canonical_body` MUST be **JCS (RFC 8785)** — the same canonicalizer already
  used for receipts and intents. Reuse it; do not invent a third canonical scheme
  (a novel scheme is exactly how a cross-language canonicalization bug — threat
  #1 — gets in). Byte fields (public keys) MUST be **hex-encoded**, not base64;
  timestamps MUST be integer milliseconds, not formatted date strings. The
  human-readable on-disk body (pretty-printed, HTML-escaped, base64 keys, date
  strings) is a separate artifact and MUST NOT be used as the digest input.
- The body-digest input MUST have its own cross-language KAT, CI-gated like §3.

---

## 6. Publication key pinning

Once verification exists, the **publication key** is the real root of trust and
deserves the scrutiny of key custody.

- **Config-pinned hex (RECOMMENDED):** the operator places the publication public
  key(s) in verifier config — explicit, auditable, rotatable. A self-hosted
  operator generates a snapshot, signs it with their own key, and pins that key
  in every PEP.
- **Build-embedded:** strongest against tampering, worst for rotation.
- **Trust-on-first-use:** MUST NOT be used — it reintroduces "accept whatever key
  appears," which is the failure this spec closes.

A verifier MUST accept a **set** of pinned keys so rotation has an overlap
window. An empty pin set MUST fail closed.

### 6.1 Rotation & overlap

Pin `{old, new}` during overlap; the publisher signs with `new` (or dual-signs)
once every verifier holds `new`; `old` is removed only after the last snapshot it
signed has aged out. A key MUST NOT leave the pin set while any still-fresh
snapshot was signed by it.

### 6.2 Rollback

A signature proves who published a snapshot, not that it is the current one:
an older snapshot restored to the snapshot directory carries a valid signature.
A long-running verifier therefore keeps its own **acceptance record** — the
`id` and `issued_ms` of the last snapshot it accepted — on a path outside the
snapshot directory that the snapshot distribution cannot write. On every load
it MUST refuse a snapshot whose `issued_ms` is earlier than the record's (or
equal with a different `id`), MUST accept the recorded snapshot again (a
restart), and MUST advance the record only on a newer acceptance. A record it
cannot read or write is a refusal, not an absence. A verifier with no record
(a one-shot tool, a test) compares against nothing and MUST say so in its
documentation. `issued_ms` more than a small tolerance ahead of the verifier's
clock is refused: a future-dated snapshot would never go stale.

`prev_snapshot_id` is the publisher's audit chain. It is signed, and an auditor
can walk it; a verifier does not enforce continuity across it, because a
verifier that was offline through several publications legitimately loads only
the latest.

---

## 7. Staleness

- Every verifier has a configurable `max_age`. If `now - issued_ms > max_age`,
  the snapshot is stale.
- Staleness is evaluated **whenever the snapshot is consulted**, not only when
  it is loaded: a process that runs past `max_age` stops resolving keys from
  it, so a revocation published since cannot be missed indefinitely by a
  verifier that simply never restarted.
- Default posture is **fail-closed**: a stale snapshot is refused.
- An operator MAY configure a **hold-last-known-good** degrade mode for
  disconnected/air-gapped segments, in which a stale snapshot keeps authorizing
  while the verifier surfaces staleness in its output. This is an explicit,
  logged operator choice, never a silent default.

---

## 8. Open-core boundary

Snapshot **verification**, digest **pinning**, the **format**, and the
**generator** (export a signed snapshot from a registry) are free and belong in
the open verifier: a verifier that cannot check its own root of trust is not a
security product. **Hosting and distributing** snapshots at fleet scale is a
separate, paid concern. The format is public by necessity — interoperability
requires it — and is fully specified here.
