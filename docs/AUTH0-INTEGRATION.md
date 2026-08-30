# Auth0 as an identity root for `cmd/idp-bridge`

**Status:** hermetic conformance proven in CI (`internal/oidc/auth0_test.go`).
**Not** proven against a live tenant. Do not write "live" anywhere until a
recorded run says otherwise — see `ADVERSARIAL-REVIEW-6` A-18.

Auth0 needs no new code path. `internal/oidc` is a generic OIDC verifier and
Auth0 is a conforming provider, so the integration is configuration plus the
conformance test that proves the configuration is the right one. What follows is
the part that is Auth0-specific and is not obvious.

---

## 1. Configuration

```
SPT_IDP_OIDC_ISSUER=https://<tenant>.<region>.auth0.com
SPT_IDP_AUDIENCE=<the Auth0 API Identifier>
```

**`SPT_IDP_AUDIENCE` must be the API Identifier, never the client id.** This is
the single most consequential line in this document.

An Auth0 API access token carries `aud` = the API identifier. An Auth0 **ID
token** carries `aud` = the **client id** — and `azp` carries the client id on
both. Bind the audience to the client id and the ID token becomes exchangeable
for a root CAT: the same outcome as review-6 finding A-1, reached by
configuration rather than by code. The verifier cannot tell the two apart;
only the operator can.

`TestAuth0_AudienceBoundToTheClientIDAdmitsTheIDToken` asserts that this is
reachable, so the trap is visible in the suite rather than discovered in a
deployment.

**Trailing slash.** Auth0's `iss` claim and its discovery `issuer` member both
end in `/`; the configured issuer conventionally does not. Both are normalised
(`oidc.go` trims on the configured value, the discovery value and the claim), so
either spelling works. Tested.

**Discovery and JWKS.** `https://<tenant>/.well-known/openid-configuration` and
`https://<tenant>/.well-known/jwks.json` share an origin, so the `sameOrigin`
constraint on `jwks_uri` is satisfied without exception. No
`SPT_IDP_INSECURE_*` variable is needed for Auth0 — it is HTTPS with a public
CA. If you find yourself setting one for Auth0, something else is wrong.

**Algorithm.** Auth0 signs RS256 by default, which is the only algorithm this
build accepts. An API configured for HS256 will not work, and should not be
made to.

---

## 2. The two token profiles

Auth0 offers two, per API, and both verify identically here.

| | Auth0 profile (**default**) | RFC 9068 profile (opt-in) |
|---|---|---|
| header `typ` | `JWT` | `at+jwt` |
| client identity | `azp` | `client_id` |
| grant marker | `gty` | *absent* |
| also present | `iss` `aud` `sub` `scope` | `iss` `aud` `sub` `scope` `jti` |

The header `typ` is **not inspected** by the verifier — recorded, not defended,
in `TestAuth0_HeaderTypIsNotInspected`. Discrimination is by claims.

---

## 3. Machine-to-machine, and the thing to fix before shipping it

`cmd/idp-bridge/main.go` derives the subject as `sub`, falling back to
`client_id`, then `azp`, on this reasoning:

> A machine-to-machine or agent token minted via client_credentials has no
> `sub` — the authenticated principal IS the OAuth client

**That is not true of Auth0.** An Auth0 client-credentials token carries `sub`,
and its value is `<client_id>@clients`. So the fallback never fires, and an M2M
token takes the human path: the CAT is minted with `PrincipalName` set to a
machine identity and a `humanAnchor` committing to something that is not a
human. Nothing rejects it and nothing downstream can tell.

The discrimination has to be positive, not an absence:

- Auth0 profile: `gty == "client-credentials"` → machine.
- RFC 9068 profile: `client_id` present → machine.
- Otherwise → human, and `sub` is the OIDC subject.

Do not use the `@clients` suffix as the test. It is a formatting convention, not
a guarantee, and putting a security property in a string suffix is the failure
`tbac/scope.go` already refuses by name ("a guess that fails open for every name
that does not match the pattern").

`TestAuth0_M2MTokenCarriesSubSoAbsenceIsNotTheDiscriminator` pins all three
shapes so the premise cannot drift.

**Where an M2M token should go.** `cmd/workload-bridge` exists for the
non-human case: it seals an attestation and does not pretend to a human anchor.
Routing Auth0 M2M into `idp-bridge` gets a root CAT with a fabricated human
behind it. Deciding which bridge owns Auth0 M2M is a design decision, and it is
owed before the M2M half of this is claimed anywhere.

---

## 4. What is proven, and what is not

**Proven, hermetically, in CI** — `internal/oidc/auth0_test.go`, no tenant, no
network, no secrets:

- discovery against an Auth0-shaped document, trailing-slash issuer included;
- an Auth0-profile M2M access token verifies;
- an Auth0-profile user access token verifies;
- an RFC 9068 access token verifies;
- an Auth0 ID token is refused when the audience is bound correctly;
- a token for another API is refused even though its `azp` matches the bound
  audience;
- the claim shapes the human/machine discrimination depends on.

**Not proven:**

- anything against a live tenant. Discovery, JWKS retrieval over real TLS, key
  rotation, and rate limiting are untested.
- the M2M routing question in §3.
- replay: one captured Auth0 access token still exchanges for unbounded root
  CATs (review-6 A-10), and that is provider-independent.

Before any document says "live against Auth0": run it against a free-tier
tenant, record the run, and log it in `DISCLOSURE-INVENTORY.md`. Until then the
accurate sentence is *"hermetic conformance tests for Keycloak, PingOne and
Auth0 shapes; live-proven against Keycloak."*
