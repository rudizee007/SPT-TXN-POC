# SPT-Txn ↔ EU Transfer of Funds Regulation (TFR) & MiCA

How SPT-Txn maps to the EU's crypto Travel Rule — **Regulation (EU) 2023/1113**
(the recast Transfer of Funds Regulation, "TFR") — and where it sits relative to
**MiCA** (Regulation (EU) 2023/1114). Written honestly: SPT-Txn carries the
required information privacy-preservingly; the CASP still does KYC, wallet
verification, and recordkeeping. SPT-Txn complements, it does not replace, the
CASP's obligations.

## 0. Why this is timely

MiCA's CASP regime is fully in force (transitional windows closing through 2026),
and the EU TFR has applied to crypto-asset transfers since **30 December 2024**.
A CASP authorised under MiCA and passporting across the EEA is simultaneously
bound by the TFR (the Travel Rule) **and** by the GDPR's data-minimisation
principle. That pairing is the exact tension SPT-Txn is built to resolve:
transmit the FATF/TFR-required information between CASPs **without** shipping PII
in cleartext or writing it on-ledger.

This is not US market-structure law. The US **CLARITY Act** (H.R.3633) is
separate, concerns token classification (SEC/CFTC), and at time of writing is not
yet law. The EU lever relevant to SPT-Txn is the **TFR + MiCA + GDPR** stack.

## 1. What the EU TFR actually requires

The EU TFR is stricter than the generic FATF Recommendation 16 in two ways that
matter here:

1. **No de-minimis threshold for the information requirement.** Unlike the
   $/€1000 threshold many jurisdictions apply, the EU TFR requires the
   originator and beneficiary information to accompany **every** crypto-asset
   transfer between CASPs, regardless of amount. (The €1000 figure survives only
   for the *self-hosted-wallet verification* obligation below — not for whether
   information must travel.)
2. **Self-hosted (unhosted) wallet handling.** For transfers to or from a
   self-hosted address **above €1000**, the CASP must verify that the
   self-hosted wallet is owned or controlled by its own customer.

Required originator information (Art. 14): name; distributed-ledger address (or
account number); and, depending on the transfer, customer identification number
**or** address + official personal document number / customer ID / date and
place of birth. Required beneficiary information: name; DLT address / account.

Both CASPs must keep these records and make them available to competent
authorities — and must do so **consistent with GDPR** (Art. 5(1)(c)
data-minimisation; the TFR explicitly does not authorise broader processing than
necessary).

## 2. The GDPR contradiction SPT-Txn resolves

Plain Travel Rule transports (e.g. cleartext TRP) satisfy the TFR by **delivering
the full identity payload to the counterparty CASP**. That maximises the PII the
receiving side holds — in direct tension with GDPR data-minimisation and storage
limitation. Encryption-in-transit (TRISA's sealed envelopes) protects the data on
the wire and at rest, but the counterparty still **decrypts and holds** the full
fields.

SPT-Txn closes the gap differently: instead of shipping the identity, the
originator ships a **selective-disclosure SD-JWT** (reveal only the fields a
counterparty or regulator is lawfully entitled to) plus **zero-knowledge proofs**
bound to the specific payment — proving the transfer is between registered CASPs,
that an identity is attested (the `human_anchor`), and that the amount relates to
a threshold, **without revealing the amount or the hidden identity fields**. That
is data-minimisation enforced cryptographically, not by policy promise.

## 3. Field-by-field mapping

| EU TFR (Reg 2023/1113) requirement | SPT-Txn mechanism | Status |
|---|---|---|
| Originator + beneficiary **identity fields** (Art. 14) | IVMS101 fields in a **selective-disclosure SD-JWT**; disclose only the lawful minimum | ✅ implemented |
| Information must accompany **every** CASP transfer (no de-minimis) | Attestation is produced per transfer; carried in the TRP `spt-txn` extension (TRISA bridge built) | ✅ implemented |
| **DLT address** of originator / beneficiary | Bound into the transaction context (`txn_context_hash`) the proofs commit to | ✅ implemented |
| Data-minimisation / GDPR (Art. 5(1)(c)) | ZK proofs + SD-JWT: amount hidden, counterparty-VASP hidden, non-disclosed identity fields never transmitted | ✅ differentiator |
| **Self-hosted wallet ≥ €1000** — verify customer owns/controls the address | **`internal/walletproof`**: signed-challenge proof-of-control (Ed25519) bound to the `human_anchor`; the customer cryptographically proves key control. Mapping the verified address to the KYC'd customer remains the CASP's | ✅ control proof / ◐ KYC link |
| **Missing-information procedures** (risk-based handling of incomplete transfers) | **`internal/tfrpolicy`**: configurable ACCEPT / HOLD / REJECT / REQUEST_MORE decision engine | ✅ implemented |
| **Counterparty protocol coverage** (the "sunrise problem") | **`internal/negotiate`**: picks the strongest shared mode ≥ a security floor (ZK → sealed-TRISA → cleartext-TRP); refuses below floor | ✅ implemented |
| Recordkeeping + availability to authorities | Hash-chained, signed-Merkle-root audit log; keyless re-verify (`cmd/auditverify`); selective disclosure to a regulator on lawful request | ✅ implemented |
| Beneficiary CASP must detect missing/incomplete info and apply policy | TRP handler **refuses cleartext-only / missing-attestation transfers (422)** — privacy is mandatory for this node's counterparties | ✅ implemented |

## 4. Honest division of responsibility

What **SPT-Txn** does: carries the TFR-required information between CASPs
privacy-preservingly; binds it to the on-chain payment; proves registration,
identity attestation, and threshold relationship in zero knowledge; keeps a
re-verifiable audit trail; refuses non-private counterparties.

What **remains the CASP's** (SPT-Txn does not and should not do): the underlying
**KYC/CDD**; the **self-hosted-wallet ownership verification** itself; sanctions
screening; the MiCA authorisation, governance, capital, and complaints
obligations; the lawful basis and retention policy under GDPR. SPT-Txn is the
*transmission and proof* layer, capturing IVMS101 fields **upstream** at the
issuer / KYC pipeline.

## 5. Positioning for grants and CASP engagement

For a MiCA-authorised CASP passporting across the EEA, SPT-Txn is the component
that lets them meet the TFR **and** GDPR at once instead of trading one off
against the other. That is a sharper, time-bound hook than generic "regulatory
clarity": the obligation is live (since Dec 2024), the deadline pressure is real
(MiCA transitionals closing through 2026), and the privacy-vs-Travel-Rule
contradiction is concrete. Use this framing in the XRPL/EU-facing grant materials;
keep the claims exact — *carries* the data, does not *perform* KYC; TFR is the
Travel Rule, MiCA is the licensing regime, CLARITY is US and pending.

## 6. The CASP Travel Rule Compliance Kit (modules)

Packaged for a CASP, the kit is the issuer + embeddable verifier (`pkg/verify`) +
transport, plus four TFR-specific modules built to close the gaps above:

- `internal/walletproof` — self-hosted wallet proof-of-control (TFR ≥ €1000):
  signed-challenge, Ed25519, bound to the `human_anchor`.
- `internal/negotiate` — sunrise/fallback mode negotiation that picks the
  strongest shared payload mode at or above a security floor, refusing below it.
- `internal/tfrpolicy` — the missing-information decision engine
  (ACCEPT / HOLD / REJECT / REQUEST_MORE).
- `internal/regdisclosure` — minimal, verifiable disclosure to a competent
  authority: an SD-JWT selective reveal of only the entitled fields plus a Merkle
  inclusion proof of the audit entry under a signed root.

All four are dependency-light pure Go (no proving backend), so they embed
anywhere the verifier does.

## References

- Regulation (EU) 2023/1113 — recast Transfer of Funds Regulation (crypto Travel Rule).
- Regulation (EU) 2023/1114 — Markets in Crypto-Assets (MiCA).
- EBA Guidelines on the "travel rule" information accompanying transfers of funds
  and certain crypto-assets.
- Regulation (EU) 2016/679 — GDPR (Art. 5(1)(c) data-minimisation).
- FATF Recommendation 16 (the international Travel Rule baseline).
- See also `docs/TRP-TRISA-INTEROP.md` (transport) and `docs/ZK-CIRCUIT-SPEC.md`
  (the proofs).
