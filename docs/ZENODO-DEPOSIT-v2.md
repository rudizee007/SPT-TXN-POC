# Zenodo Deposit — SPT-Txn v2 Working Paper (paste-ready)

Everything below is ready to paste into the Zenodo upload form. The file to upload is
**`docs/WORKING-PAPER-v2.pdf`** (current; regenerate with the pandoc line at the bottom if
you edit the `.md` first). I can't publish to your Zenodo account — you do the final
upload + "Publish" — but every field is pre-written here.

## How to publish (recommended path)

This paper is the evolved **framework** paper, so deposit it as a **New version of the
existing framework record** to keep one citable concept-DOI across versions:

1. Go to the framework preprint **10.5281/zenodo.18917439** → **"New version"**.
2. Upload `WORKING-PAPER-v2.pdf` (remove the old file if Zenodo carries it over).
3. Paste the metadata below, set **Version = v2**, **Publication date = 2026-06**.
4. Save → **Publish**. Zenodo mints a new version DOI under the same concept DOI.

(Alternative: if you'd rather it stand alone, create a **New upload** instead — then add
`10.5281/zenodo.18917439` and `10.5281/zenodo.19299787` as *related identifiers* with
relation **"is new version of"** / **"references"** so the lineage is still linked.)

---

## Metadata (copy field-by-field)

**Resource type:** Publication → *Preprint* (or *Working paper*)

**Title:**
```
Sovereign Policy Token Transactions (SPT-Txn): A Privacy-Preserving, Crypto-Agile Authorization Framework for Regulated and Agentic Systems
```

**Authors:**
```
Coetzee, Rudolf J.  |  Affiliation: Violet Sky Security SEZC (Cayman Islands SEZC)  |  ORCID: 0009-0009-6557-8843
```

**Publication date:** `2026-06`  **Version:** `v2`  **Language:** `English`

**Description / Abstract** (paste):
```
Every regulated interaction — opening an account, transacting a tokenised asset, authorising an AI agent to act on a person's behalf — today requires identity and eligibility to be re-verified from scratch, at every platform, at a cost of tens of dollars and days of latency per check. The data exhaust of that model is a standing breach liability, and it does not survive the move to autonomous agents, where the accountable human dissolves within one or two delegation hops.

SPT-Txn is an authorization framework that verifies once and proves everywhere. A user holds a Compliance Attestation Token (CAT) — a W3C Verifiable Credential, issued by a regulated KYC/compliance provider, that binds zero-knowledge-provable compliance attributes to a zkDID commitment. A platform evaluates a zero-knowledge proof of the CAT against a representation-agnostic policy object and, on a match, issues a scope-bounded Capability Token (CT); an AI agent receives a strictly attenuated, delegation-depth-bounded CT carrying an immutable humanAnchor back to the accountable person. Each action emits a transaction-bound SPT-Txn token (~30 s lifetime, sender-constrained per DPoP), and every step is recorded to a tamper-evident audit trail. No personally identifiable information is transmitted or stored at the point of use.

The paper covers the full architecture and the design alternatives considered; the cryptographic choices and their measured trade-offs (Groth16 over BN254, MiMC→Poseidon2 migration, BN254 vs BLS12-381); a privacy-preserving FATF Travel Rule deployment (IVMS101 + selective-disclosure SD-JWT + zero-knowledge predicates over the OpenVASP Travel Rule Protocol); a decentralised naming and private-resolution layer (zkDNS); a lifetime-triaged hybrid post-quantum migration plan (FIPS 203/204/205) with a CycloneDX Cryptographic Bill of Materials; and the regulatory/standards context. It is a companion to, and deliberately distinct in scope from, the IETF Internet-Draft draft-coetzee-oauth-spt-txn-tokens. A reference implementation in Go on a hardened OpenBSD host accompanies the paper (open source, Apache-2.0).
```

**Keywords** (comma-separated):
```
zero-knowledge proofs, verifiable credentials, FATF Travel Rule, ABAC, TBAC, authorization, capability tokens, DPoP, zkDID, zkDNS, post-quantum cryptography, crypto-agility, agentic AI, Groth16, Poseidon2, OpenBSD, privacy-preserving compliance
```

**License:** `Creative Commons Attribution 4.0 International (CC-BY-4.0)`
*(Standard for an open preprint; lets others cite/reuse with attribution. The accompanying source code is separately licensed Apache-2.0.)*

**Related identifiers:**
| Relation | Identifier |
|---|---|
| is new version of | `10.5281/zenodo.18917439` (SPT-Txn framework preprint) |
| references | `10.5281/zenodo.19299787` (transaction-binding security theory) |
| is supplement to | `https://datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens/` (IETF I-D) |
| is supplemented by | `https://github.com/rudizee007/SPT-TXN-POC` (reference implementation) |
| references | `https://foss.violetskysecurity.com` (live demo / project site) |

**Funding (optional):** leave blank, or note an applied-for XRPL Grant once submitted.

---

## After publishing

- Add the new DOI to the website Publications card and the README.
- Update the IETF I-D's informative references if you cite the framework paper there.
- Use the new version DOI in the XRPL grant form's "links / prior work" field.

## Regenerate the PDF (only if you edit the .md first)

```sh
cd ~/Claude/Projects/"SPT-TXN POC"/spt-poc
pandoc docs/WORKING-PAPER-v2.md -o docs/WORKING-PAPER-v2.pdf \
  --pdf-engine=xelatex -V geometry:margin=1in -V fontsize=11pt --toc
```
(The committed PDF is already current — only needed if the source changes.)
