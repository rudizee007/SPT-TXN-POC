# SPT-Txn scoped-disclosure schema

A small, language-agnostic schema for **time-limited, scope-selected, consented**
selective disclosure over an SD-JWT credential. It is the selective-disclosure
half of the SPT-Txn "auditable privacy / compliant transparency" primitive;
zero-knowledge predicates (amount-over-threshold, VASP membership, identity
commitment) ride alongside as proofs (see `internal/zkproof` / `internal/travelrule`).

Reference implementation: `internal/disclosure` (Go). The shapes below are plain
JSON so a TypeScript/Python client can interoperate.

## Flow

```
requester ──Request──▶ holder ──(consent: Grant)──▶ Respond ──Response──▶ requester ──Verify──▶ disclosed claims
```

1. The **requester** (counterparty, auditor, institution) sends a `Request`
   naming exactly the fields it needs, why, and for how long.
2. The **holder** decides via a `Grant` which requested fields to release.
3. `Respond` discloses only `Request.fields ∩ Grant.allow` — never more.
4. `Verify` binds the response to the request, enforces the expiry, authenticates
   the SD-JWT, and rejects any field outside the request.

## DisclosureRequest

```json
{
  "id": "9f1c…",                  // unique per-exchange id / nonce (hex)
  "audience": "beneficiary-vasp", // who is asking (optional)
  "purpose": "FATF Travel Rule check", // human-readable reason, shown to the holder for consent (optional)
  "fields": ["name", "account"],  // requested disclosable claim names
  "predicates": ["amount_over_threshold", "vasp_registered"], // optional ZK predicates to also prove
  "expires_at": 1782600000        // unix seconds; the request is invalid at/after this
}
```

## Grant (holder consent — local, not transmitted)

```json
{ "allow": ["name"] }             // the subset of fields the holder releases; the rest are withheld
```

## DisclosureResponse

```json
{
  "request_id": "9f1c…",          // must equal the Request id
  "presentation": "<JWT>~<disc>~", // SD-JWT presentation carrying ONLY the granted fields
  "disclosed": ["name"],          // field names actually released
  "issued_at": 1782599700
}
```

## Semantics (the guarantees)

- **Scope selection.** The response discloses at most `fields ∩ allow`. The
  holder cannot be made to over-share; the requester cannot receive a field it
  did not request (`Verify` rejects any out-of-scope claim).
- **Consent.** Disclosure is opt-in per field via `Grant`; `purpose` gives the
  holder the context to decide. Withheld fields are reported back to the
  requester as `withheld` so it knows what it did not get.
- **Time-limited.** `expires_at` bounds the validity window; both `Respond` and
  `Verify` refuse an expired request. `id` is a per-exchange nonce.
- **Authenticated, minimal.** Disclosed values are authenticated against the
  issuer-signed SD-JWT `_sd` digest set; undisclosed values leak nothing (only a
  salted hash was ever signed).
- **Predicates (ZK).** `predicates` names facts to prove while the value stays
  fully hidden; the proofs are produced by `internal/zkproof` and attached to the
  exchange out of band (e.g. inside the SPT-Txn token / Travel Rule attestation).

## Holder-binding / replay

A `Response` is only safe inside a holder-/transaction-bound outer envelope (the
SPT-Txn token, which carries `cnf.jkt` + DPoP and a transaction-context hash).
The request `id` is a nonce and `expires_at` bounds the window, but key-binding
and replay protection come from that outer token — a bare `Response` must not be
trusted standalone (same invariant as `internal/sdjwt`).
