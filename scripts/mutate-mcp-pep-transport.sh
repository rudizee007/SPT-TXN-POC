#!/usr/bin/env bash
# Mutation check for cmd/mcp-pep — the stdio transport in front of the MCP
# enforcement point.
#
# internal/mcppep and internal/decision carry their own mutation coverage. What
# is new here is the transport: the code that decides which bytes are this
# call's answer, which are relayed, which never reach the wrapped server, and
# which configuration refuses to start. That code is where a passing suite is
# easiest to mistake for a working guard, because every one of these mutations
# leaves a proxy that still proxies.
#
#   M-A  a message that is not this call's answer is returned as if it were
#   M-B  the id match is dropped — the first message to arrive wins
#   M-C  a notification is treated as a request
#   M-D  a closed upstream stream produces a response instead of an error
#   M-E  a closed upstream stream loses its diagnosis
#   M-F  a null id is treated as a request
#   M-G  the stdout framing lock is dropped
#   M-H  a request may go unanswered
#   M-I  -audience stops being required
#   M-J  a bad tts public key no longer stops startup
#   M-K  the denial stops carrying the PEP's denied code
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=cmd/mcp-pep/main.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  cp "$BAK" "$F"
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green. Assert it passes before trusting that it failed.
  if ! go test ./cmd/mcp-pep/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$F"; then
    echo "FAIL      $name: anchor not found — the mutation was never applied"
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
    echo "FAIL      $name: anchor did not match exactly the expected"
    echo "          number of times -- the mutation was NOT applied, so a"
    echo "          pass below would mean nothing. Re-anchor the mutation."
    return 1
  fi
  if ! go build -o /dev/null ./cmd/mcp-pep/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test ./cmd/mcp-pep/ -run "$want_test" >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "M-A out-of-band message returned as the answer" \
  "TestChildConn_UnrelatedMessageIsRelayedNotReturned" \
  "		c.oob(msg)" \
  "		return msg, nil" || rc=1

run_mutation "M-B id match dropped, first message wins" \
  "TestChildConn_UnrelatedMessageIsRelayedNotReturned" \
  "ok && bytes.Equal(bytes.TrimSpace(rid), bytes.TrimSpace(id))" \
  "ok && (true || bytes.Equal(bytes.TrimSpace(rid), bytes.TrimSpace(id)))" || rc=1

run_mutation "M-C notification treated as a request" \
  "TestChildConn_NotificationGetsNoReplyAndDoesNotBlock" \
  "	if !isRequest {
		return nil, nil
	}" \
  "	if false && !isRequest {
		return nil, nil
	}" || rc=1

run_mutation "M-D closed stream answers anyway" \
  "TestChildConn_ClosedStreamIsAnErrorNotASilentNil" \
  "	return nil, errors.New(\"wrapped server closed its stream before answering\")" \
  "	return []byte(\"{}\"), errors.New(\"wrapped server closed its stream before answering\")" || rc=1

run_mutation "M-E closed stream loses its diagnosis" \
  "TestChildConn_ClosedStreamIsAnErrorNotASilentNil" \
  "	return nil, errors.New(\"wrapped server closed its stream before answering\")" \
  "	return nil, errors.New(\"upstream\")" || rc=1

run_mutation "M-F null id treated as a request" \
  "TestRPCID" \
  "	if len(m.ID) == 0 || string(bytes.TrimSpace(m.ID)) == \"null\" {" \
  "	if len(m.ID) == 0 {" || rc=1

run_mutation "M-G stdout framing lock dropped" \
  "TestLineWriter_ConcurrentWritesStayFramed" \
  "	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(bytes.TrimSpace(b))" \
  "	l.w.Write(bytes.TrimSpace(b))" || rc=1

run_mutation "M-H a request may go unanswered" \
  "TestServe_ARequestNeverGoesUnanswered" \
  "		if id, isRequest := rpcID(raw); isRequest {
			out.write(denial(id))
		}" \
  "		if id, isRequest := rpcID(raw); isRequest && false {
			out.write(denial(id))
		}" || rc=1

run_mutation "M-I -audience stops being required" \
  "TestMissingRequired_NamesEachFailOpenSetting" \
  "		{\"-audience\", audience}," \
  "" || rc=1

run_mutation "M-J bad tts public key no longer stops startup" \
  "TestBuildEngine_FailsClosedOnBadConfiguration" \
  "	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if err != nil {" \
  "	ttsPub, err := parseHexKey(c.ttsPubHex, ed25519.PublicKeySize)
	if false && err != nil {" || rc=1

run_mutation "M-K denial loses the denied code" \
  "TestDenial_IsWellFormedAndUniform" \
  "\"code\": mcppep.CodeDenied," \
  "\"code\": -32000," || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply — see above"
fi
exit "$rc"
