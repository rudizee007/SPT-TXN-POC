#!/usr/bin/env bash
# Mutation check for internal/a2apep -- the A2A Policy Enforcement Point.
#
# internal/decision carries its own mutation coverage; this script covers what
# is NEW here: the wire binding. Which A2A Message fields the intent digest
# covers, which params the PEP will forward at all, and what happens to a
# method it does not model. Every mutation below leaves a middleware that still
# proxies traffic and still answers requests, which is exactly why reading the
# tests is not enough to know they hold.
#
#   A-1  the credential is not stripped before forwarding
#   A-2  metadata is left on the wire as {} after stripping
#   A-3  `parts` leaves the intent binding
#   A-4  `taskId` leaves the intent binding
#   A-5  `contextId` leaves the intent binding
#   A-6  an unmodelled message/* method is proxied instead of refused
#   A-7  an unbound params sibling (configuration) is forwarded
#   A-8  an unrecognised Message member is forwarded
#   A-9  a duplicated Message member is accepted
#   A-10 the jsonrpc version check is dropped
#   A-11 an empty method is proxied
#
# A-3, A-4 and A-5 mutate the json TAG on the `bound` struct rather than the
# call site. That is deliberate. The test rig mints against the same struct, so
# a mutation at the call site alone would make BOTH sides disagree and every
# request would be denied -- and a test asserting denial would then pass for
# the wrong reason and score as SURVIVED. Mutating the tag moves both sides
# together, which is the honest question: is this field part of the binding?
#
# NOT COVERED BY MUTATION, and why:
#
#   * the agent-identity target binding (TestTokenForAnotherAgentDenied). No
#     single-anchor mutation makes the PEP accept a token minted for another
#     agent without rewriting it to take its identity from the request, which
#     is a redesign, not a mutation. The digest's coverage of `target` is
#     mutation-tested in internal/intent.
#   * the empty-`parts` rejection (TestWellFormedRequestWithEmptyMessageDenied).
#     Removing that guard still denies, because a message with no metadata
#     carries no token. It is defence in depth, and the test says so.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=internal/a2apep/a2apep.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  cp "$BAK" "$F"
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green. Assert it passes before trusting that it failed.
  if ! go test ./internal/a2apep/ -run "$want_test" -count=1 >/dev/null 2>&1; then
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
  if ! go build -o /dev/null ./internal/a2apep/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test ./internal/a2apep/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "A-1 credential not stripped before forwarding" \
  "TestAuthorizedSendForwardedWithTokenStripped" \
  "		delete(meta, TokenMetaKey)" \
  "		_ = TokenMetaKey" || rc=1

run_mutation "A-2 emptied metadata left on the wire as {}" \
  "TestAuthorizedSendForwardedWithTokenStripped" \
  "		if len(meta) == 0 {
			delete(msg, \"metadata\")" \
  "		if false && len(meta) == 0 {
			delete(msg, \"metadata\")" || rc=1

run_mutation "A-3 parts leaves the intent binding" \
  "TestMutatedPartsDenied" \
  "type bound struct {
	Parts     json.RawMessage \`json:\"parts\"\`" \
  "type bound struct {
	Parts     json.RawMessage \`json:\"-\"\`" || rc=1

run_mutation "A-4 taskId leaves the intent binding" \
  "TestRedirectedTaskDenied" \
  "	TaskID    string          \`json:\"taskId,omitempty\"\`" \
  "	TaskID    string          \`json:\"-\"\`" || rc=1

run_mutation "A-5 contextId leaves the intent binding" \
  "TestRedirectedContextDenied" \
  "	ContextID string          \`json:\"contextId,omitempty\"\`" \
  "	ContextID string          \`json:\"-\"\`" || rc=1

run_mutation "A-6 unmodelled message/* method proxied" \
  "TestUnmodelledMessageMethodDenied" \
  "		if len(req.Method) >= 8 && req.Method[:8] == \"message/\" {" \
  "		if false && len(req.Method) >= 8 && req.Method[:8] == \"message/\" {" || rc=1

run_mutation "A-7 unbound params sibling forwarded" \
  "TestUnboundParamsSiblingDenied" \
  "var allowedSendParams = map[string]bool{\"message\": true}" \
  "var allowedSendParams = map[string]bool{\"message\": true, \"configuration\": true}" || rc=1

run_mutation "A-8 unrecognised Message member forwarded" \
  "TestUnknownMessageMemberDenied" \
  "	\"taskId\": true, \"contextId\": true, \"metadata\": true, \"kind\": true," \
  "	\"taskId\": true, \"contextId\": true, \"metadata\": true, \"kind\": true, \"surprise\": true," || rc=1

run_mutation "A-9 duplicated Message member accepted" \
  "TestDuplicateMessageMemberDenied" \
  "		if seen[key] {" \
  "		if false && seen[key] {" || rc=1

run_mutation "A-10 jsonrpc version check dropped" \
  "TestMalformedNotForwarded" \
  "	if err := json.Unmarshal(raw, &req); err != nil || req.Jsonrpc != \"2.0\" || req.Method == \"\" {" \
  "	if err := json.Unmarshal(raw, &req); err != nil || req.Method == \"\" {" || rc=1

run_mutation "A-11 empty method proxied" \
  "TestMalformedNotForwarded" \
  "	if err := json.Unmarshal(raw, &req); err != nil || req.Jsonrpc != \"2.0\" || req.Method == \"\" {" \
  "	if err := json.Unmarshal(raw, &req); err != nil || req.Jsonrpc != \"2.0\" {" || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply -- see above"
fi
exit "$rc"
