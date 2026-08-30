# Runbook — standing up an Auth0 test tenant for `cmd/idp-bridge`

**Purpose:** produce a real Auth0 tenant and three real artifacts — an M2M access
token, a user access token, and an ID token — so the hermetic conformance tests
in `internal/oidc/auth0_test.go` can be checked against the live provider, and so
`docs/HOW-WE-MAKE-MONEY.md` can say "live" without it being false.

**Companion:** `docs/AUTH0-INTEGRATION.md` (what the integration is and what it
is not). Read §1 of that first — the audience rule is the whole ballgame.

**Everything here is free.** Auth0 has a free plan; check current terms at
<https://auth0.com/pricing> before you rely on any figure. Nothing in this
runbook needs a paid feature.

---

## 0. What you end up with

Two configuration values:

```
SPT_IDP_OIDC_ISSUER=https://<tenant>.<region>.auth0.com
SPT_IDP_AUDIENCE=https://api.spt-txn.local/v1        # the API Identifier
```

and three tokens to test with: an M2M access token, a user access token, and an
ID token that **must be refused**.

**Do not send me any of it.** Not the client secret, not the tokens. A token is a
bearer credential and a chat transcript is not a place to keep one. Paste
*decoded claim shapes* if you want me to look at something, with the signature
stripped.

---

## 1. Create the tenant (5 min)

1. Sign up at <https://auth0.com/signup>. A free account creates your first
   tenant during onboarding.
2. Tenant name: something obviously disposable — ` ` — because you will
   delete it.
3. Region: pick the one nearest you. It becomes the locality in the domain.
4. Environment tag: **Development**. This is a label, not a security boundary, but
   it keeps the dashboard honest.

Your domain is `{tenant}.{locality}.auth0.com` — e.g. `spt-txn-dev.eu.auth0.com`.

> Older US tenants are `{tenant}.auth0.com` with no locality. **Do not construct
> the domain from the pattern — read it off the dashboard**, then confirm it:
>
> ```
> TENANT=https://spt-txn-dev.eu.auth0.com
> curl -s "$TENANT/.well-known/openid-configuration" | jq '{issuer, jwks_uri}'
> ```
>
> Expect `issuer` to end with a trailing slash and `jwks_uri` to be
> `$TENANT/.well-known/jwks.json`. Both are already handled — the trailing slash
> is normalised, and same-origin `jwks_uri` satisfies the discovery constraint.
> If `jwks_uri` is on a different host, stop and tell me; that would be new.

---

## 2. Create the API — this is the audience (5 min)

**Applications → APIs → Create API.**

| Field | Value | Why |
|---|---|---|
| Name | `SPT-Txn Exchange` | cosmetic |
| Identifier | `https://api.spt-txn.local/v1` | **this is `SPT_IDP_AUDIENCE`** |
| Signing Algorithm | **RS256** | the only algorithm this build accepts |

The Identifier is never resolved as a URL. It must not be a real endpoint you
own, and it must never be the client id — see `AUTH0-INTEGRATION.md` §1 for what
happens if it is.

**Then add permissions** so the `scope` claim is populated (it feeds the
capability-scope intersection):

- API → **Permissions** tab → add `payments:execute`.
- API → **Settings** → enable **RBAC** and **Add Permissions in the Access
  Token**. Without both, `scope` comes back empty and you will be testing a
  different thing than you think.

Creating an API auto-creates a machine-to-machine test application. You can use
it or make your own in step 3.

---

## 3. Machine-to-machine token (10 min)

**Applications → Applications → Create Application → Machine to Machine.**
Authorize it for the API from step 2 and tick the `payments:execute` permission.

From **Settings**, copy the Client ID and Client Secret into a shell — not into a
file, and not into the repo:

```
read -r AUTH0_CLIENT_ID
read -rs AUTH0_CLIENT_SECRET        # -s: not echoed, not in your shell history
API=https://api.spt-txn.local/v1
```

Get a token:

```
M2M=$(curl -s --request POST "$TENANT/oauth/token" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=client_credentials \
  --data client_id="$AUTH0_CLIENT_ID" \
  --data client_secret="$AUTH0_CLIENT_SECRET" \
  --data audience="$API" | jq -r .access_token)
```

Decode it locally — no network, no jwt.io, no paste anywhere:

```
jwt() { echo "$1" | cut -d. -f"$2" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .; }
jwt "$M2M" 1      # header
jwt "$M2M" 2      # claims
```

**Check these four things.** They are the premises the code depends on:

- `iss` ends with `/` — the trailing slash is real.
- `aud` is the API Identifier, **not** the client id.
- `sub` is `<client_id>@clients` — **present**, which is the finding: the bridge's
  "M2M has no `sub`" assumption is false here.
- `gty` is `client-credentials` — the discriminator the fix should use.

If `gty` is absent and `client_id` is present instead, this API is on the RFC 9068
profile (`typ: at+jwt` in the header). Both are supported; note which one you got.

---

## 4. User-login token, without standing up a web server (10 min)

Use the Device Authorization Flow — no redirect URI, no callback handler.

**Create Application → Native.** Then:

- **Settings → Advanced → Grant Types**: tick **Device Code**.
- **Settings → Advanced → OAuth**: **OIDC Conformant** on.
- **Token Endpoint Authentication Method**: **None**.
- Create a test user under **User Management → Users**.

```
read -r NATIVE_CLIENT_ID

DEV=$(curl -s --request POST "$TENANT/oauth/device/code" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data client_id="$NATIVE_CLIENT_ID" \
  --data scope='openid profile payments:execute' \
  --data audience="$API")

echo "$DEV" | jq -r '.verification_uri_complete'
```

Open that URL, log in as the test user, approve. Then poll once:

```
TOK=$(curl -s --request POST "$TENANT/oauth/token" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=urn:ietf:params:oauth:grant-type:device_code \
  --data device_code="$(echo "$DEV" | jq -r .device_code)" \
  --data client_id="$NATIVE_CLIENT_ID")

USER_AT=$(echo "$TOK" | jq -r .access_token)
ID_TOKEN=$(echo "$TOK" | jq -r .id_token)
```

Because `scope` included `openid`, you get **both** — and the ID token is the
artifact you need for the negative test. Check:

- `USER_AT`: `sub` starts `auth0|`, `aud` is the API Identifier, no `gty`.
- `ID_TOKEN`: **`aud` is the client id**, and there is no `scope`. That is the
  whole reason the audience must be bound to the API Identifier.

---

## 5. Run the bridge against the tenant (10 min)

```
export SPT_IDP_OIDC_ISSUER="$TENANT"
export SPT_IDP_AUDIENCE="$API"
export SPT_IDP_CAT_SEED_OUT=/tmp/spt-cat-seed.hex   # 0600; never a log line
go run ./cmd/idp-bridge
```

Startup proves discovery and JWKS retrieval over real TLS — the part the hermetic
tests cannot reach.

A holder key, in another shell:

```
HOLDER=$(go run - <<'GO'
package main
import ("crypto/ed25519";"crypto/rand";"encoding/hex";"fmt")
func main(){ pub,_,_ := ed25519.GenerateKey(rand.Reader); fmt.Println(hex.EncodeToString(pub)) }
GO
)
```

Then the four exchanges that matter. Use `dry_run=true` first — it runs the whole
evaluation and returns the decision **without issuing a token**:

```
ex() { curl -s -X POST http://127.0.0.1:8090/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d holder_key_hex="$HOLDER" -d dry_run=true \
  -d subject_token="$1" | jq .; }

ex "$M2M"        # expect ALLOW  — and look at what subject it chose
ex "$USER_AT"    # expect ALLOW
ex "$ID_TOKEN"   # expect DENY, audience mismatch  ← the one that matters
```

**The third one is the test.** If the ID token is allowed, `SPT_IDP_AUDIENCE` is
set to the client id rather than the API Identifier. Fix the configuration, do not
work around it.

**On the first one, read the chosen subject.** If the M2M exchange returns a CAT
whose principal is `<client_id>@clients` and it went down the human path, that is
the §3 finding reproduced live — capture it, because it is the evidence for
whichever way you decide the M2M routing question.

---

## 6. Record it, then tear it down

Record in `DISCLOSURE-INVENTORY.md`: the date, the tenant domain, which token
profile the API used, and the three verdicts. That record is what licenses the
word "live" in any public document — and per review-6 A-18, nothing may say it
until this exists.

Then:

1. **Rotate or delete the M2M client secret.** It was in a shell; treat it as
   spent.
2. Delete the Native application and the test user.
3. `unset AUTH0_CLIENT_SECRET M2M USER_AT ID_TOKEN` and close the shells.
4. `rm /tmp/spt-cat-seed.hex` — it signs CATs.
5. Keep the tenant if you want to re-run it; it costs nothing and holds no
   secrets once the applications are gone.

---

## 7. What this does and does not prove

**Proves:** discovery and JWKS over real TLS against a real provider; that Auth0's
actual token shapes match the fixtures in `auth0_test.go`; that the ID token is
refused under the correct configuration; whether `gty` or `client_id` is the live
discriminator.

**Does not prove:** key rotation, rate limiting under load, Auth0 Organizations,
or anything about replay — one captured access token still exchanges for unbounded
root CATs (review-6 A-10), and that is provider-independent and still open.
