#!/usr/bin/env bash
# Mutation check for guards in internal/tbac that NO TEST WOULD MISS.
#
# This is a different question from the one the other tbac scripts ask. They ask
# "does a named test notice this guard being broken". This asks "would ANYTHING
# notice", and it exists because an audit on 2026-09-01 found three guards where
# the answer is no -- one of them on the money ceiling, and one of them reported
# as covered by the existing harness.
#
#   W-1  the max_cumulative branch projects an amount without parsing it
#   W-2  a sub-band division stops validating its parent scope
#   W-3  Merkle leaves are hashed under the internal-node domain tag
#
# EXPECTED ON FIRST RUN: all three SURVIVE. That is the finding.
#
# W-1 IS THE SERIOUS ONE, AND IT IS A DEFECT IN THE HARNESS AS WELL AS IN THE
# TESTS. tbac.TxnScope parses the transaction amount twice, once in the
# max_amount branch and once in the max_cumulative branch, and the two lines are
# byte-identical:
#
#     if _, err := ledger.ParseAmount(tc.Amount); err != nil {
#
# scripts/mutate-amount-and-ceiling-guards.sh C2 and
# scripts/mutate-numeric-and-enforcement-guards.sh E2 both anchor on that line
# with want_n 2. They therefore mutate BOTH occurrences at once, and are killed
# by tests that only ever exercise the max_amount branch:
# TestTxnScope_RefusesNonPositiveAmounts and
# TestTxnScope_RefusesNonCanonicalAmounts both use
# parent = {max_amount: 5000, currency: USD}, with no cumulative dimension.
# Every cumulative-only call in the suite passes a VALID amount. So both scripts
# print "killed" while the cumulative guard is untested.
#
# What that guard holds: a cumulative-only slice is exactly the sub-band case --
# a $3/day band with no max_amount. Without the parse, TxnScope projects
# json.Number(tc.Amount) verbatim, and big.Rat is happy to read "-5000" as a
# number. "-5000 <= 3" is true. The slice clears a transaction it does not
# authorize. The guard is present and correct today; what is missing is anything
# that would notice its removal, on the one path the sub-band design exists for.
#
# W-2: ValidateSubbandDivision's own doc comment promises that "a parent budget
# that bounds 100 in every currency at once is refused here". Every one of the
# twenty call sites in the suite passes a well-formed, currency-qualified
# parent, so nothing tests the promise.
#
# W-3: TestSubbandCommit_DomainSeparation asserts that tagLeaf, tagNode and
# tagParentCommit are different CONSTANTS. It computes its own hashes and never
# calls SubbandLeaf or node, so it says nothing about whether those functions
# USE the tags. Hash a leaf under the node tag and every leaf changes
# consistently: round-trip, tamper and cross-parent tests all still pass,
# because none of them pins a digest. The second-preimage property the file's
# own comment claims is unevidenced.
#
# Once each is covered, every mutation here must be KILLED, and the want_n 2
# anchors in the two scripts named above must be split so each occurrence is
# mutated on its own.
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FILES=(internal/tbac/scope.go internal/tbac/subband.go internal/tbac/subband_commit.go)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"; done
restore() { for f in "${FILES[@]}"; do cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"; done; }
trap 'restore; rm -rf "$BAKDIR"' EXIT INT TERM

run_mutation() {
  local name="$1" pkg="$2" want_test="$3" file="$4" from="$5" to="$6" want_n="${7:-1}"
  restore
  if ! go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$file"; then
    echo "FAIL      $name: anchor not found in $file — the mutation was never applied"
    return 1
  fi
  if ! python3 - "$file" "$from" "$to" "$want_n" <<'PY'
import sys
p, a, b, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = open(p).read()
assert s.count(a) == n, f"anchor appears {s.count(a)} times, expected {n}"
open(p, "w").write(s.replace(a, b))
PY
  then
    echo "FAIL      $name: anchor did not match exactly the expected"
    echo "          number of times -- the mutation was NOT applied, so a"
    echo "          pass below would mean nothing. Re-anchor the mutation."
    return 1
  fi
  if ! go build -o /dev/null ./... >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test "$pkg" -run "$want_test" >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

# The anchor carries the line AFTER the guard, which is what makes it the
# cumulative occurrence rather than the max_amount one. The two guards are
# identical text; only their context distinguishes them, which is precisely the
# property that let a want_n 2 anchor conflate them.
run_mutation "W-1 max_cumulative projects an unparsed amount" \
  ./internal/tbac/ "TestTxnScope_Cumulative" \
  internal/tbac/scope.go \
  "		if _, err := ledger.ParseAmount(tc.Amount); err != nil {
			return nil, fmt.Errorf(\"transaction amount: %w\", err)
		}
		out[cumulativeDim] = json.Number(tc.Amount)" \
  "		out[cumulativeDim] = json.Number(tc.Amount)" || rc=1

run_mutation "W-2 sub-band division stops validating its parent" \
  ./internal/tbac/ "TestSubband" \
  internal/tbac/subband.go \
  "	if err := ValidateIssuance(parent); err != nil {" \
  "	if err := ValidateIssuance(parent); err != nil && false {" || rc=1

run_mutation "W-3 leaves hashed under the internal-node tag" \
  ./internal/tbac/ "TestSubbandCommit" \
  internal/tbac/subband_commit.go \
  "	pre = append(pre, tagLeaf)" \
  "	pre = append(pre, tagNode)" || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply — see above"
fi
exit "$rc"
