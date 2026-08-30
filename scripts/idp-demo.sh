#!/bin/sh
# idp-demo.sh — the definitive identity-provider proof, end to end.
#
# Proves: an existing IdP (Keycloak) mints an SPT-Txn CAT over standard RFC 8693
# Token Exchange; the CAT verifies OFFLINE with no IdP contact; a tampered CAT is
# rejected; and the same CAT format feeds the agent-delegation engine.
#
# Prerequisites: docker, go, curl, jq, openssl.
#
# Run (from the repo root):
#   1) start Keycloak:   (cd deploy/keycloak && docker compose up -d)   # wait ~30s
#   2) start the bridge: go run ./cmd/idp-bridge                        # separate terminal
#   3) run this:         sh scripts/idp-demo.sh
set -eu

# Always run from the repo root, so `go run ./cmd/...` resolves regardless of
# where this script was invoked from.
cd "$(dirname "$0")/.."

# The bridge requires these; it refuses to start without them, and the earlier
# version of this script did not set them, so the documented demo could not run.
export SPT_IDP_AUDIENCE="${SPT_IDP_AUDIENCE:-account}"
export SPT_IDP_PERMITTED_SCOPE="${SPT_IDP_PERMITTED_SCOPE:-{\"action\":\"transfer\",\"max_amount\":10000,\"currency\":\"USD\"}}"

KC="${KC:-http://localhost:8080}"
REALM="${REALM:-spt}"
BRIDGE="${BRIDGE:-http://127.0.0.1:8090}"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

say "1. Identity provider reachable?"
if curl -sf "$KC/realms/$REALM/.well-known/openid-configuration" >/dev/null; then
  echo "  Keycloak realm '$REALM' is up at $KC"
else
  echo "  Keycloak not reachable. Start it:  (cd deploy/keycloak && docker compose up -d)"
  echo "  (first boot takes ~30s; watch 'docker compose logs -f')"
  exit 1
fi

say "2. Bridge reachable?"
if curl -sf "$BRIDGE/health" >/dev/null; then
  echo "  idp-bridge is up at $BRIDGE"
else
  echo "  Bridge not reachable. Start it:  go run ./cmd/idp-bridge"
  exit 1
fi

say "3. Authenticate alice at Keycloak (standard OIDC password grant)"
TOK=$(curl -sf -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=spt-agent \
  -d username=alice -d password=alice | jq -r .access_token)
if [ -z "$TOK" ] || [ "$TOK" = null ]; then echo "  auth failed"; exit 1; fi
echo "  got a Keycloak access token (${#TOK} chars) — the unmodified IdP doing its normal job"

say "4. Generate a real Ed25519 keypair for the agent and take its public key"
# A real keypair, not 32 random bytes. The previous version used `openssl rand`,
# which produces a value with no private half — so the step that the demo calls
# holder binding bound the credential to entropy nobody could ever possess.
KEYDIR=$(mktemp -d)
trap 'rm -rf "$KEYDIR"' EXIT
openssl genpkey -algorithm ed25519 -out "$KEYDIR/agent.pem" 2>/dev/null
HOLDER=$(openssl pkey -in "$KEYDIR/agent.pem" -pubout -outform DER | tail -c 32 | xxd -p -c 64)
echo "  holder public key: ${HOLDER%${HOLDER#????????}}…  (private half in $KEYDIR)"
echo "  NOTE: the bridge does not ask the agent to PROVE it holds the private half."
echo "        Possession is not demonstrated here; the key is simply sealed into the CAT."

say "5. RFC 8693 Token Exchange: Keycloak token  ->  SPT-Txn CAT"
RESP=$(curl -sf -X POST "$BRIDGE/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOK" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "holder_key_hex=$HOLDER")
CAT=$(echo "$RESP" | jq -r .access_token)
echo "  issued_token_type: $(echo "$RESP" | jq -r .issued_token_type)"
echo "  human_anchor:      $(echo "$RESP" | jq -r .human_anchor)"
echo "  CAT issued (${#CAT} chars)"
# The issuer public key. In the demo it is fetched from the bridge, and that is
# the one step here that does NOT resemble a real deployment: the party that
# minted the token is also supplying the key that validates it, over plaintext
# HTTP. Anyone able to answer this request supplies both halves. In a real
# deployment the issuer key arrives out of band — a trust-registry snapshot,
# pinned configuration — and never from the issuer over the wire.
ISSKEY="${SPT_DEMO_ISSUER_KEY:-$(curl -sf "$BRIDGE/issuer" | jq -r .public_key_hex)}"

say "6. Check the CAT with local crypto only (no Keycloak, no network) + tamper test"
echo "  (issuer key came from the bridge — see the note above; set SPT_DEMO_ISSUER_KEY to supply it out of band)"
go run ./cmd/idp-verify -cat "$CAT" -issuer-key "$ISSKEY"

say "7. The delegation mechanics, shown SEPARATELY on their own fixture"
echo "  agentdemo takes no input: it mints its own CAT and shows CAT -> CT ->"
echo "  transaction-bound token, attenuation, and the offline revocation cascade."
echo "  It does NOT consume the Keycloak-issued CAT above. Read it as an"
echo "  illustration of the mechanics, not as a continuation of steps 1-6."
go run ./cmd/agentdemo

printf '\n\033[1mWHAT THIS RUN SHOWED:\033[0m an existing identity provider (Keycloak) minted an\n'
printf 'SPT-Txn credential over standard OAuth Token Exchange; its signature and expiry\n'
printf 'checked out with local crypto; a tampered copy was rejected.\n'
printf '\n\033[1mWHAT IT DID NOT SHOW:\033[0m that the IdP-issued CAT drives the delegation chain\n'
printf '(step 7 runs on its own fixture), that the holder proved possession (nobody asked),\n'
printf 'or that the issuer is one anybody should trust (the key came from the bridge).\n'
