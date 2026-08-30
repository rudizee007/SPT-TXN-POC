# Scope — Keycloak → SPT-Txn: the definitive identity-provider proof

> **Status note, 2026-08-27.** This is a SCOPE document — what was planned. Several
> of its acceptance criteria describe behaviour the implementation does not have.
> Adversarial review #6 lists them; the ones to know before quoting this file:
> the holder key is not DPoP-bound and possession is never proved; `subject_token_type`
> was accepted and discarded until 2026-08-27; `cmd/idp-verify` checks the signature,
> expiry and token type and nothing else — not Trust Registry membership, not the
> human anchor, not scope; the issuer key is not registered in any Trust Registry;
> and the demo's negative tests are one of the three this document specifies.
> Read the review before treating any line here as a description of the code.

*A reference integration proving an existing OAuth/OIDC identity provider can mint SPT-Txn credentials via standard RFC 8693 Token Exchange — no rip-and-replace.*

## What it proves (the one sentence)

> A user authenticates at **Keycloak** (a real, unmodified IdP). Their OIDC token is exchanged, over standard **RFC 8693**, for a **SPT-Txn Compliance Attestation Token** that is **verified offline** (no IdP contact), carries a **privacy-preserving human anchor**, and can be **delegated to an AI agent** with attenuating, revocable authority.

That is the whole IdP thesis, demonstrated end-to-end against software an architect already recognises — not a bespoke scheme.

## Why this is small (what already exists)

| Already built | Where |
|---|---|
| CAT issuer HTTP service (`POST /cat/issue`, verifies a subject token, calls `cattoken.Issue`) | `cmd/catsvc/main.go` |
| CAT type = standard EdDSA JWT + human anchor | `internal/cattoken` |
| Offline eight-step verifier + delegation (CAT→CT→TXN) | `internal/verifier`, `cmd/agentdemo` |
| DPoP sender-constraint (RFC 9449) | `internal/dpop` |
| Trust Registry (issuer keys, roles, revocation) | `internal/trustregistry` |
| OAuth standards map (8693 / 9449 / 9396 / 9700 / SD-JWT) | `docs/SPT-Txn-OAuth-Standards-Alignment.md` |

The insertion point is precise: `catsvc` `handleIssue` today calls `verifySubjectToken(req.SubjectToken, issuerPub)` (an internal token). We add a second, configurable subject-token verifier: **OIDC/JWT from Keycloak.**

## What to build

**1. OIDC subject-token verifier — `internal/oidc/` (new, ~1 day).**
Given a Keycloak realm issuer URL: fetch `/.well-known/openid-configuration` → `jwks_uri`, cache the JWKS, and verify an incoming access/ID token: signature (**RS256** — Keycloak default — and ES256), `iss` (exact realm URL), `aud`, `exp`/`nbf`. Return the validated claims. Keep it dependency-light (stdlib `crypto/rsa` + JWKS parse) to match the project's minimal-deps ethos; `github.com/coreos/go-oidc/v3` is the drop-in alternative if preferred. JWKS is cached, so this stays **out of the hot path** (issuance-time only).

**2. RFC 8693 token-exchange endpoint on `catsvc` — (~1 day).**
Accept the standard grant:
```
POST /token
grant_type        = urn:ietf:params:oauth:grant-type:token-exchange
subject_token     = <Keycloak access token>
subject_token_type= urn:ietf:params:oauth:token-type:access_token
```
Route `subject_token` to the OIDC verifier (when `subject_token_type` is a JWT/OIDC type) instead of the internal verifier. Respond in RFC 8693 shape:
```json
{ "access_token": "<CAT JWT>",
  "issued_token_type": "urn:violetsky:token-type:spt-cat",
  "token_type": "N_A",
  "expires_in": 86400 }
```
Keep the existing `/cat/issue` for backward-compatibility.

**3. Claims → CAT mapping — (~0.5 day).**
`Subject`/`PrincipalName` ← Keycloak `sub` / `preferred_username`; `Scope` ← a realm/client role set or a custom `spt_scope` claim, or RFC 9396 `authorization_details`; `HolderPublicKey` ← the DPoP-bound holder key the client presents; `DelegationDepthMax`/`TTL` ← policy defaults. Optionally derive the **human anchor** from a stable subject id via `internal/zkdid` so no PII lands in the token.

**4. Turnkey Keycloak + demo — `deploy/keycloak/` + `scripts/idp-demo.sh` — (~1 day).**
A `docker compose` Keycloak with a pre-imported realm export (`realm.json`: one client, one user, roles) so the whole thing is one command. The issuer signing key registered in the Trust Registry (existing flow).

**5. Tests + a short `docs/IDP-INTEGRATION.md` — (~1 day).**

**Total: ~1 focused week (part-time).** No changes to the token format, verifier, or crypto — this is an ingress adapter.

## The proof (acceptance criteria — what a skeptic runs)

`scripts/idp-demo.sh` performs, and prints, each step:

1. **Stand up Keycloak** (`docker compose up`) with the demo realm.
2. **Authenticate** — obtain a user access token from Keycloak (standard OIDC password or client-credentials grant). *This is the unmodified IdP doing its normal job.*
3. **Token exchange** — `curl` `catsvc` `/token` (RFC 8693) with the Keycloak token → receive a **SPT-Txn CAT**.
4. **Verify offline** — the existing verifier checks the CAT with **no Keycloak contact**: signature against the Trust-Registry issuer key, human anchor, scope. *Proves portability + offline verification.*
5. **Delegate to an agent** — issue a CT (narrower scope) then a transaction-bound TXN, and run the eight-step engine. *Proves the IdP-authenticated identity flows into bounded, revocable agent authority — the M2M bridge.*
6. **Negative tests** — a tampered Keycloak token → exchange **rejected**; a revoked issuer in the registry → CAT verify **fails**; a scope-exceeding delegation → **denied**. *Proves it actually enforces, not rubber-stamps.*

If all six print as expected, the IdP claim is beyond argument: **Keycloak in, offline-verifiable human-anchored agent-delegatable capability out, over standard OAuth.**

## Honest boundaries (state these, don't hide them)

- **Keycloak authenticates; SPT-Txn attests capability.** The exchange *binds* an IdP's authenticated identity to a compliance/capability attestation — it does not turn Keycloak into a KYC provider. In production the KYC/compliance issuer is the trusted party; here `catsvc` plays that role to demonstrate the flow.
- **DPoP is a documented POC subset** — the demo binds the CAT holder via a presented key; production would bind the DPoP key proven by the Keycloak client.
- **Claims→scope mapping is deployment-specific** — the demo ships a simple, explicit mapping; real deployments define their own.
- **This is a reference integration, not a productised Okta/Ping/Auth0 connector** — it proves interoperability and the flow; a hardened commercial connector is separate work. (But because it's standard RFC 8693 + OIDC, the same pattern points at Okta/Auth0/Ping unchanged — Keycloak is chosen because it's open-source and reproducible.)

## Deliverables

1. `internal/oidc/` — OIDC/JWKS subject-token verifier (+ tests).
2. `cmd/catsvc/` — RFC 8693 `/token` endpoint + OIDC subject-token path + claims mapping.
3. `deploy/keycloak/` — `docker-compose.yml` + `realm.json`.
4. `scripts/idp-demo.sh` — the one-command end-to-end proof.
5. `docs/IDP-INTEGRATION.md` — how it works + the RFC map + how to point it at Okta/Auth0.

## The claim it unlocks (for the deck / architects / sales)

*"Your existing identity provider issues SPT-Txn compliance credentials through standard OAuth 2.0 Token Exchange (RFC 8693) — no migration. The credential then verifies offline anywhere, carries a privacy-preserving human anchor, and an AI agent can act under it with authority that can only narrow and is bounded by its TTL (per-token revocation is NOT wired on this path: the bridge sets no status claim and registers no issuer key). Demonstrated end-to-end against Keycloak; the same flow targets Okta, Auth0, and Ping unchanged."*
