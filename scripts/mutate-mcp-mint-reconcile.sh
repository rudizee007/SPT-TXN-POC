#!/usr/bin/env bash
# Mutation check for the ceiling/intent reconciliation in cmd/mcp-mint.
#
# A minted token makes two independent statements about money:
#
#   TxnContext.Amount   what the CAT -> CT ceiling chain constrains, and what
#                       nothing downstream ever executes;
#   the tool arguments  what DOES execute, bound byte-exact by the intent digest
#                       and enforced at the PEP (internal/decision: "the actual
#                       call must match the declared action").
#
# Both were enforced. Neither was checked against the other, so
#   -amount 3000 -args '{"amount":"99999999"}'
# minted cleanly and every control in the path reported success. reconcile()
# is the join. These mutations remove it and require the test to notice.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=cmd/mcp-mint/main.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  cp "$BAK" "$F"
  if [ -z "$(go test ./cmd/mcp-mint/ -list "$want_test" 2>/dev/null | grep -E '^Test')" ]; then
    echo "FAIL      $name: $want_test matches no test -- fix the mapping, do not skip it"
    return 1
  fi
  # A test that fails on the CLEAN tree also fails under mutation and scores as
  # "killed" -- a false green.
  if ! go test ./cmd/mcp-mint/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  # The apply step MUST fail loudly. A bare heredoc discards python's exit
  # status, so a stale anchor leaves the file untouched, the test passes against
  # clean code, and the script prints SURVIVED. That bug produced six phantom
  # findings in this repo on 2026-08-30.
  if ! python3 - "$F" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(a) == 1, f"anchor appears {s.count(a)} times, expected 1"
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly once -- the mutation was NOT"
    echo "          applied, so a pass below would mean nothing. Re-anchor it."
    return 1
  fi
  if ! go build -o /dev/null ./cmd/mcp-mint/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test ./cmd/mcp-mint/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

# N-1 -- the declared amount and the executed amount need not agree.
run_mutation "N-1 the ceiling and the args need not agree" "TestReconcile" \
  "	if got != amount {" \
  "	if false && got != amount {" || rc=1

# N-2 -- a call with no amount in its arguments mints without the explicit flag,
#        so the ceiling bounds a value the tool never sees.
run_mutation "N-2 an unpriced call mints without the explicit flag" "TestReconcile" \
  "		if allowUnpriced {
			return nil
		}" \
  "		if true {
			return nil
		}" || rc=1

# N-3 -- a ceiling in one currency stops bounding the currency actually spent.
run_mutation "N-3 currency need not match" "TestReconcile" \
  "		if gotCur != currency {" \
  "		if false && gotCur != currency {" || rc=1

cp "$BAK" "$F"
echo
if [ $rc -eq 0 ]; then
  echo "All mutations killed. The ceiling/intent join has a test that fails without it."
else
  echo "At least one mutation SURVIVED or the harness failed. Read the lines above."
fi
exit $rc
