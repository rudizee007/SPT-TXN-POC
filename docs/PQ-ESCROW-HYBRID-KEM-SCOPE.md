# Scope: hybrid X25519 + ML-KEM-768 for the escrow envelope (PQ step 1)

> **STATUS — IMPLEMENTED (host `go test` pending on the Mac).** `internal/escrow/envelope.go`
> now defaults new seals to the hybrid Scheme 2; `Open` dispatches v1/v2; `deanon.go` holds
> the hybrid `*escrow.Key`. Tests added: `hybrid_test.go` (v2 round-trip, scheme/kemCT
> assertions, wrong-key fail, transcript-binding via kemCT swap, tampered-AAD fail) +
> `envelope_internal_test.go` (v1 back-compat). The API change is contained to the escrow
> package (no other repo caller).
>
> **Registry wiring DONE (2026-07-02):** `trustregistry.Record` now carries
> `MlkemEncapKey []byte` + `KeyType` `X25519+ML-KEM-768`; `validateRecord` enforces the
> hybrid shape (escrow-role-only, 32B X25519 + 1184B ML-KEM), persists via JSON, and the
> trsvc `/tr/register` endpoint + `regkey -mlkem` register it. `cmd/escrowkeygen` generates the
> hybrid keypair and emits the two public halves + a 96-byte private key (`escrow.Bytes`/
> `ParseKey`). Issuers rebuild the pub with `escrow.NewPublicKey(rec.PublicKey, rec.MlkemEncapKey)`.
>
> Remaining: (a) threshold-PQ custody (§5); (b) one-time re-seal of any stored v1 envelopes;
> (c) wire the deanon `Handler` into a live service that loads the escrow key via `ParseKey`.


> The one PQ change worth doing before the standards timelines force it. The escrow
> human-anchor envelopes are **stored** (keyed by humanAnchor, for lawful deanon) —
> i.e. long-lived ciphertext, the classic **harvest-now-decrypt-later (HNDL)** target.
> Token *signatures* are short-lived and are deliberately deferred (see FIPS/PQ notes).
> Companion to `FIPS-140-3-PLAN.md`; touches only `internal/escrow` + the escrow record.

---

## 1. Current design (`internal/escrow/envelope.go`)

Single-party ECIES: ephemeral **X25519** ECDH to the escrow public key →
**HKDF-SHA256** (info `ESC-2`) → **AES-256-GCM** with `(humanAnchor|issuer|iat)` as AAD.
`Seal(identity, escrowPub *ecdh.PublicKey, …)`, `Open(escrowPriv *ecdh.PrivateKey)`,
`NewEscrowKey() *ecdh.PrivateKey`. Envelope = `EphemeralPub, Nonce, Ciphertext, + AAD`.

Quantum exposure: an adversary who harvests stored envelopes today can, with a future
quantum computer, break X25519 and recover the sealed identities. That's the risk to close.

## 2. Target design — hybrid KEM (safe if EITHER primitive holds)

Recipient (escrow authority) holds **two** keys: X25519 (as now) **and** ML-KEM-768.
Go stdlib `crypto/mlkem` (Go 1.24+, pure Go, no external dep — and ML-KEM-768 is **FIPS 203**,
inside the Go FIPS module, so this is FIPS-approvable on the KEM side).

**Seal:**
1. `eph := X25519.GenerateKey()`, `ss1 := eph.ECDH(escrowX25519Pub)` (as today).
2. `ss2, kemCT := escrowMlkemEncapKey.Encapsulate()` (ML-KEM-768; `ss2`=32B, `kemCT`=1088B).
3. `key := HKDF-SHA256(secret = ss1 ‖ ss2, salt = eph.Pub ‖ kemCT, info = "spt-txn-escrow-aead-v2-hybrid")`.
   Binding both transcript elements (eph pub, kemCT) in the salt prevents mix-and-match /
   re-encapsulation attacks — this is the standard concatenation-KEM combiner.
4. AES-256-GCM as today (same AAD tuple).

**Open:** `ss1 := escrowX25519Priv.ECDH(eph.Pub)`; `ss2 := escrowMlkemDecapKey.Decapsulate(kemCT)`;
same HKDF + AES-GCM. Fails closed on any tampered field.

## 3. Envelope format + crypto-agility

Add a scheme version so classical (v1) and hybrid (v2) envelopes coexist and `Open`
dispatches on it — this is the crypto-agility property, not a hard cutover:

```go
type Envelope struct {
    Scheme       uint8  // 1 = X25519-ECIES (legacy), 2 = X25519+ML-KEM-768 hybrid
    EphemeralPub []byte // X25519 ephemeral (32B)
    KemCiphertext []byte // ML-KEM-768 ciphertext (1088B) — empty for Scheme 1
    Nonce        []byte
    Ciphertext   []byte
    HumanAnchor  string; Issuer string; IssuedAt int64 // AAD (unchanged)
}
```
`Open` reads `Scheme`: v1 → current path; v2 → hybrid path. Default new seals to v2.

## 4. Key + registry changes

- `NewEscrowKey()` → returns a small struct holding both the X25519 `*ecdh.PrivateKey`
  and the `*mlkem.DecapsulationKey768` (public side = X25519 pub + ML-KEM encapsulation
  key bytes, 1184B).
- The **Trust Registry** `escrow`-role record must carry **both** public keys (add an
  `MlkemEncapKey []byte` field beside the existing X25519 key). Verifiers of the escrow
  role that only seal (issuers) need both to build a v2 envelope.
- `deanon.go` handler holds the hybrid private key struct instead of `*ecdh.PrivateKey`.

## 5. Threshold — the honest open item

The escrow is meant to be **t-of-n threshold** (FROST is the classical plan). **Threshold
ML-KEM is not standardized** — you cannot Shamir-split an ML-KEM decapsulation key the way
you can an X25519/ECDSA scalar. Options, documented, not decided:
- **(a) interim:** threshold the classical X25519 half (FROST/Shamir) and hold the ML-KEM
  decapsulation key under a smaller quorum or in an HSM — the PQ half is not yet t-of-n.
- **(b) wait:** adopt a threshold-KEM once standardized.
Either way, the **hybrid envelope (this scope) is independent of and prerequisite to** the
threshold work — do the HNDL fix now; solve threshold-PQ custody later.

## 6. Effort, tests, migration

- **Effort:** ~1–2 days. Localized to `internal/escrow` (`envelope.go`, `deanon.go`, key
  helper) + the escrow registry record + `zk`/nothing else. No protocol change elsewhere.
- **Tests:** v2 round-trip; tamper each AAD field → fail; wrong key → fail; v1 envelope
  still opens (back-compat); combiner transcript-binding (swap kemCT → open fails).
- **Migration of stored envelopes:** because they're persisted, re-seal existing v1
  envelopes to v2 under the new hybrid escrow key (batch, one-time) so harvested pre-migration
  ciphertext is the only residual classical exposure — and rotate the escrow key at the same time.

## 7. Strict-FIPS variant (optional)

For a deployment whose scope forbids non-approved algorithms, swap the classical half from
X25519 to **ECDH P-256** (FIPS-approved) → P-256 + ML-KEM-768 hybrid, both inside the FIPS
boundary. The combiner and envelope are otherwise identical. Default stays X25519 (faster,
and the hybrid is safe regardless).

## 8. Why this and not signatures now

Signatures (Ed25519 → ML-DSA) are deferred: tokens are short-lived (CAT hours, SPT-Txn 30s),
so a post-quantum signature forgery in the 2030s can't retroactively help against an
expired token — HNDL doesn't apply to signatures. The `crypto.Signer` refactor already makes
that a small swap when ML-DSA (FIPS 204, Go 1.26 module) matures. Encrypted stored escrow
data is the real HNDL target, so it goes first.
