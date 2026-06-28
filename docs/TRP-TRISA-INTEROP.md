# SPT-Txn ↔ Travel Rule Protocol (TRP) and TRISA Interop

Status: TRP transport **implemented and green on host**; TRISA **payload bridge implemented** (`internal/trisa`, round-trip tested) — only the sealed gRPC **transport** is deferred to a separate module.
Scope: privacy-preserving FATF Recommendation 16 (the "Travel Rule") for SPT-Txn.

## 1. The two protocols SPT-Txn must speak to

Live VASP-to-VASP Travel Rule traffic runs over two dominant protocols. SPT-Txn is
positioned to interoperate with both rather than invent a third network.

| | **TRISA** | **OpenVASP TRP** |
| --- | --- | --- |
| Transport | gRPC | HTTPS POST |
| Message | Protocol Buffers | JSON |
| Data model | IVMS101 | IVMS101 |
| Transport encryption | mTLS 1.3 | mTLS 1.3 |
| Payload privacy / at-rest | **Sealed Secure Envelopes** (per-message AES key sealed to recipient's public key) | **none** (transport-only) |
| Non-repudiation | Signed envelopes | Signed JSON (extension) |
| Discovery | Global Directory Service (GDS) | Travel Address (sender-provided) |
| Authentication | X.509 KYV certificates via GDS | mTLS, CA unspecified |

The decisive difference for a privacy product: **plain TRP carries the originator and
beneficiary IVMS101 identity in cleartext to the counterparty.** Its only confidentiality
is the mTLS tunnel; once the JSON arrives, the receiving VASP holds the full PII. TRISA
closes this with sealed envelopes (encrypted at rest, erasable by deleting keys). TRP does
not.

## 2. What SPT-Txn contributes

SPT-Txn closes the same gap differently — and more strongly than encryption. Instead of
shipping the PII at all, the originator ships a **payload-level zero-knowledge attestation**:

- a selectively-disclosable **SD-JWT** of the IVMS101 fields (reveal a surname to a
  regulator, keep the given name and DOB hidden), and
- three **Groth16 proofs** bound to the specific SPT-Txn payment via its context hash:
  identity-commitment knowledge (the `human_anchor`), amount ≥ reporting threshold (amount
  stays hidden), and beneficiary-VASP registration (which VASP stays hidden).

The beneficiary learns *"this transfer is reportable, between registered counterparties,
with an authenticated identity"* without receiving the amount or the identity fields it is
not entitled to see. This is the layer TRISA approximates with encryption-at-rest and TRP
omits entirely — provided here with zero-knowledge rather than trusted decryption.

## 3. TRP transport — implemented (`internal/trp`)

A real TRP-compatible HTTPS/JSON transport carrying the SPT-Txn attestation as a TRP
**extension** (`extensions["spt-txn"]`) in place of the cleartext IVMS101 blocks.

- **`TransferRequest` / `TransferResponse`** — TRP `asset`/`amount`/`callback` plus the
  `extensions.spt-txn` object (`version`, `attestation`, `txn_context_hash`, `disclose`).
- **Headers** — `Api-Version` and `Request-Identifier` on every message; the beneficiary
  echoes `Request-Identifier` and the client verifies the echo, per spec. Major-version
  compatibility is enforced.
- **Travel Address** — opaque, URL-safe encoding of the beneficiary's inbound endpoint
  (`ta_` + base64url). *Deferred:* standard TRP uses a bech32m `ta` address.
- **Originator client** (`Client.Send`) → `cmd/tr-svc` `POST /trp/originate`: builds the
  attestation and sends it to a beneficiary Travel Address.
- **Beneficiary handler** (`trp.Handler`) → `cmd/tr-svc` `POST /trp/transfer`: validates the
  envelope, verifies the attestation, replies `approved` + `disclosed` or `rejected`.
- **Policy: cleartext-only refused.** A transfer with no `spt-txn` extension is rejected
  `422` — this VASP requires payload-level ZK and will not accept plain-IVMS101 TRP. That is
  the security-by-design stance: privacy is not optional for counterparties of this node.

Verified on host (OpenBSD): originator and beneficiary run as **separate processes** (the
beneficiary holds only the verifying key); a transfer crosses a real TRP hop and returns
`trp_status: 200 / approved` with only the surname and currency disclosed. Unit tests cover
travel-address round-trip, approval, bad-binding rejection, and cleartext-only rejection.

### Field mapping

| SPT-Txn attestation | TRP carrier | TRISA carrier (planned) |
| --- | --- | --- |
| SD-JWT (IVMS101, selective) | `extensions.spt-txn.attestation.SDJWT` | `Payload.identity` (IVMS101) + extension |
| Commitment / threshold / VASP proofs | `extensions.spt-txn.attestation.*Proof` | `Payload.transaction` (generic) extension |
| `txn_context_hash` (payment binding) | `extensions.spt-txn.txn_context_hash` | envelope `id` / transaction ref |
| disclosure request | `extensions.spt-txn.disclose` | out-of-band policy |

## 4. TRISA bridge — designed, deferred

TRISA's `SecureEnvelope` already has the right shape to carry SPT-Txn: a `Payload` with an
IVMS101 `identity`, a generic `transaction`, and timestamps, wrapped in per-message AES-GCM
and sealed to the recipient's public key. The bridge:

1. Put the SD-JWT (IVMS101 selective disclosure) in `Payload.identity`.
2. Put the three proofs + public inputs + `txn_context_hash` in a TRISA generic
   `transaction` (or a registered envelope extension).
3. Seal per the TRISA flow: generate the AES key + HMAC secret, encrypt and HMAC the
   payload, seal the key/secret with the recipient's public sealing key (obtained via the
   `KeyExchange` RPC or the GDS directory), send via the unary `Transfer` RPC.

Because the SPT-Txn proofs already provide payload-level privacy and non-repudiation,
running them *inside* a sealed envelope yields defence in depth: ZK for what the counterparty
may compute, sealing for confidentiality at rest and crypto-erasure.

**Deferred dependencies** (real-network, not POC-blocking): mTLS certificate registration at
`trisa.directory`, GDS counterparty lookup, protobuf codegen for the TRISA messages, and the
bech32m Travel Address for full TRP addressing.

## 5. Security notes

- **`txn_context_hash` provenance.** The beneficiary must derive the expected payment hash
  from the on-chain transaction it independently observes, **not** trust the value in the
  request. The handler accepts an `expectedHash` resolver for exactly this; the POC uses the
  request value for convenience and this is called out in code.
- **Transport security.** TRP/TRISA both mandate mTLS 1.3. Here transport TLS is terminated
  at relayd; mutual-TLS client-cert verification is the remaining transport hardening for a
  cross-org deployment (CA policy is a deliberate node choice — TRISA CA vs. public CA).
- **Pledge.** The originator dials outbound (TRP client) and so carries the `dns` promise and
  read-only resolver unveil; the beneficiary never dials out and keeps the tighter
  `stdio rpath inet`.
- **Disclosure minimisation.** The `disclose` set is the only PII the beneficiary receives;
  everything else stays inside the proofs. Default to the FATF minimum, widen only on a
  regulator's lawful request.

## 6. Standards positioning

SPT-Txn does not replace TRP or TRISA; it rides them as a privacy-preserving payload, which
is the right posture for IETF/NIST engagement: an attestation format and proof system that
existing Travel Rule networks can carry unchanged, closing the cleartext-PII gap that plain
TRP leaves open and that TRISA only addresses with trusted decryption.
