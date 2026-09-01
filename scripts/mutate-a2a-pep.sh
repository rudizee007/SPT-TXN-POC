#!/usr/bin/env bash
# Mutation check for cmd/a2a-pep -- the HTTP transport in front of the A2A
# enforcement point.
#
# internal/a2apep and internal/decision carry their own mutation coverage. What
# is new here is the transport: which requests exist at all, what is refused
# before the enforcement point is consulted, what the wrapped agent receives,
# and what the PEP publishes about itself. Every mutation below leaves a proxy
# that still proxies and still answers, which is exactly why reading the tests
# is not enough to know they hold.
#
#   T-1  the JSON-RPC path stops being checked -- POST anywhere is enforced-and-forwarded
#   T-2  GET on the JSON-RPC path is accepted
#   T-3  the Content-Type check is dropped
#   T-4  the request body cap is removed
#   T-5  a request may go unanswered
#   T-6  a refused notification is answered anyway
#   T-8  a streamed answer from the agent is relayed
#   T-9  a redirect from the agent is followed
#   T-10 a non-2xx answer is treated as an answer
#   T-11 the agent card is relayed with no -public-url to advertise
#   T-12 the relayed card keeps the wrapped agent's url
#   T-13 the relayed card keeps additionalInterfaces
#   T-14 the upstream scheme check is dropped
#   T-15 -upstream stops being required
#   T-16 a bad tts public key no longer stops startup
#
# NOT COVERED BY MUTATION, and why:
#
#   * T-7, "no client header reaches the wrapped agent"
#     (TestForward_NoClientHeaderReachesTheWrappedAgent). There is no anchor to
#     mutate, because forward never receives the client's *http.Request: it is
#     handed the token-stripped BODY and nothing else, so there is no header
#     map in scope to copy. The property is structural rather than checked, and
#     that is the stronger form of it. The test is a regression guard aimed at
#     a future refactor -- swapping in httputil.ReverseProxy, or threading the
#     request down to reuse a trace header -- which would put the headers back
#     in scope and reopen the hole in one line.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=cmd/a2a-pep/main.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  cp "$BAK" "$F"
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green. Assert it passes before trusting that it failed.
  if ! go test ./cmd/a2a-pep/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$F"; then
    echo "FAIL      $name: anchor not found -- the mutation was never applied"
    return 1
  fi
  if ! python3 - "$F" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(a) == 1, f"anchor appears {s.count(a)} times"
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly once -- the mutation was"
    echo "          NOT applied, so a pass below would mean nothing. Re-anchor it."
    return 1
  fi
  if ! go build -o /dev/null ./cmd/a2a-pep/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test ./cmd/a2a-pep/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "T-1 JSON-RPC path no longer checked" \
  "TestRoute_EverythingButTheTwoKnownRequestsIs404" \
  "	case r.Method == http.MethodPost && r.URL.Path == p.rpcPath:" \
  "	case r.Method == http.MethodPost:" || rc=1

run_mutation "T-2 GET accepted on the JSON-RPC path" \
  "TestRoute_EverythingButTheTwoKnownRequestsIs404" \
  "	case r.Method == http.MethodPost && r.URL.Path == p.rpcPath:" \
  "	case (r.Method == http.MethodPost || r.Method == http.MethodGet) && r.URL.Path == p.rpcPath:" || rc=1

run_mutation "T-3 Content-Type check dropped" \
  "TestServeRPC_RefusesANonJSONContentType" \
  "	if !isJSON(r.Header.Get(\"Content-Type\")) {" \
  "	if false && !isJSON(r.Header.Get(\"Content-Type\")) {" || rc=1

run_mutation "T-4 request body cap removed" \
  "TestServeRPC_RefusesAnOversizeBody" \
  "	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageBytes))" \
  "	raw, err := io.ReadAll(r.Body)" || rc=1

run_mutation "T-5 a request may go unanswered" \
  "TestServeRPC_ARequestNeverGoesUnanswered" \
  "		if !isRequest {" \
  "		if true || !isRequest {" || rc=1

run_mutation "T-6 a refused notification is answered anyway" \
  "TestServeRPC_ANotificationStaysUnanswered" \
  "		if !isRequest {" \
  "		if false && !isRequest {" || rc=1

run_mutation "T-8 streamed answer relayed" \
  "TestForward_RefusesAStreamedAnswer" \
  "	if isEventStream(resp.Header.Get(\"Content-Type\")) {" \
  "	if false && isEventStream(resp.Header.Get(\"Content-Type\")) {" || rc=1

run_mutation "T-9 redirect from the wrapped agent followed" \
  "TestForward_RefusesARedirect" \
  "		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New(\"a2a-pep: the wrapped agent redirected. Following it would send \" +
				\"an authorized request to a host the operator never configured\")
		}," \
  "		CheckRedirect: nil," || rc=1

run_mutation "T-10 non-2xx treated as an answer" \
  "TestForward_RefusesANon2xxAnswer" \
  "	if resp.StatusCode < 200 || resp.StatusCode > 299 {" \
  "	if false && (resp.StatusCode < 200 || resp.StatusCode > 299) {" || rc=1

run_mutation "T-11 agent card relayed with nothing to advertise" \
  "TestCard_RelayIsOffWithoutAPublicURL" \
  "	if p.publicURL == \"\" {" \
  "	if false && p.publicURL == \"\" {" || rc=1

run_mutation "T-12 relayed card keeps the wrapped agent's url" \
  "TestCard_RelayAdvertisesThePEPAndDropsAlternateInterfaces" \
  "	obj[\"url\"] = enc" \
  "	_ = enc" || rc=1

run_mutation "T-13 relayed card keeps additionalInterfaces" \
  "TestCard_RelayAdvertisesThePEPAndDropsAlternateInterfaces" \
  "	delete(obj, \"additionalInterfaces\")" \
  "	_ = obj" || rc=1

run_mutation "T-14 upstream scheme check dropped" \
  "TestValidateUpstream" \
  "	if u.Scheme != \"http\" && u.Scheme != \"https\" {" \
  "	if false && u.Scheme != \"http\" && u.Scheme != \"https\" {" || rc=1

run_mutation "T-15 -upstream stops being required" \
  "TestMissingRequired_NamesEachFailOpenSetting" \
  "		{\"-upstream\", upstream}," \
  "" || rc=1

run_mutation "T-16 bad tts public key no longer stops startup" \
  "TestBuildEngine_FailsClosedOnBadConfiguration" \
  "	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if err != nil {" \
  "	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if false && err != nil {" || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply -- see above"
fi
exit "$rc"
