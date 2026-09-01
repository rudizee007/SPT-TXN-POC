#!/usr/bin/env bash
# Mutation check for the LAYERING of internal/verifier -- not for the guards
# themselves, which scripts/mutate-verifier-guards.sh covers.
#
# The eight-step engine is layered defence: several independent guards stand in
# front of the same property, in a fixed order. A test that asserts only that
# verification FAILED, or that names only the step, is satisfied by whichever
# guard fires first -- which is often not the guard the test was written to
# evidence. The test then reads correct, is correct about the outcome, and
# evidences nothing about its target. Adding a guard can hollow out a test that
# was genuine the day before: the code gets safer and the evidence gets weaker
# in the same commit, and only mutation can tell the two apart.
#
# Note that d.Step is a STEP path, not a rule path. Steps 1-5, 7 and 8 are one
# or two guards each, so d.Step nearly identifies the control. Step 6 contains
# roughly twenty guards in sequence, so `d.Step == 6` is the weakest assertion
# available in this package, and two of the three mutations below live there.
#
#   V-1  attenuation monotonicity is deleted   (CT scope may exceed its parent)
#   V-2  per-hop CT issuer resolution is ignored
#   V-3  the empty-window temporal check is deleted
#   V-4  the transaction context binding is deleted
#
# HISTORY, kept because the "before" is the point. On 2026-09-01 the first three
# of these SURVIVED against the tests as they then stood. None was an
# exploitable hole -- every guard was present and working. What was wrong was
# the evidence: five tests that would not have caught the removal of the thing
# they were written to protect.
#
#   V-1  TestSec_OverScopedCT_Forged built its forged CT with
#        "spt_parent_hash": "x", which the VER-1 parent-hash binding rejected
#        thirty-five lines BEFORE tbac.Contains was reached. The most
#        load-bearing property in the package -- a delegation may only narrow --
#        was not evidenced by the test named for it. Fixed by binding the
#        forgery to the real parent hash and asserting the Reason.
#   V-2  TestVerify_RevokedCTKey_DeniedAtChain revoked issCT, which in that
#        fixture signs the CAT as well as the CT; the CAT resolves first, so the
#        per-hop resolution the test named never ran. That test now asserts what
#        it actually evidences (CAT-side resolution), and V-2 is mapped to
#        TestAgentic_RevokeSubAgentIssuer_Cascades, where the revoked key signs
#        exactly one CT and nothing else.
#   V-3  TestCheckTemporal_NbfEmptyWindow_Refused passed nbf = exp = now+50,
#        which is both an empty window AND in the future, so the not-yet-valid
#        check eight lines later refused it either way. Fixed with the substring
#        assertion its three siblings already had.
#   V-4  TestVerifyForSettlement_RefusesAForgedContext forged an amount of
#        999999, which step 7 refused for exceeding the leaf ceiling, so step 8
#        never ran -- and the assertion accepted either step. Fixed with an
#        in-scope amount and a strict step-8 assertion.
#
# Two findings from the same audit are NOT scripted here, and are recorded so
# they are not mistaken for oversights:
#
#   * TestNonConformingIssuer_NonPositiveCeilingIsRefused asserted only !Allow.
#     There is no dedicated non-positive-ceiling guard on the verify path; the
#     refusal comes from the ordinary ceiling comparison in internal/tbac, which
#     is a different file than this script mutates. The test now asserts step 7
#     and the ceiling-comparison Reason, and says in its own comment that no
#     specific guard exists.
#   * No test in this package asserts d.Step == 4. Deleting step4Revocation
#     outright would break nothing here. That is a coverage gap, not a layering
#     defect, and it needs a test rather than a mutation.
#
# Every mutation below must now be KILLED. A SURVIVED line from here on is a
# regression, not a known state.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=internal/verifier/engine.go
BAK=$(mktemp)
cp "$F" "$BAK"
trap 'cp "$BAK" "$F"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" want_test="$2" from="$3" to="$4"
  cp "$BAK" "$F"
  if ! go test ./internal/verifier/ -run "$want_test" -count=1 >/dev/null 2>&1; then
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
  if ! go build -o /dev/null ./internal/verifier/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test ./internal/verifier/ -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "V-1 attenuation monotonicity deleted" \
  "TestSec_OverScopedCT_Forged" \
  "		if err := tbac.Contains(parentScope, ctScope); err != nil {" \
  "		if err := tbac.Contains(parentScope, ctScope); err != nil && false {" || rc=1

run_mutation "V-2 per-hop CT issuer resolution ignored" \
  "TestAgentic_RevokeSubAgentIssuer_Cascades" \
  "		ctClaims, err := e.verifyChainToken(ctx, ctTok, cttoken.Verify)
		if err != nil {
			return nil, fmt.Errorf(\"CT[%d]: %w\", i, err)
		}" \
  "		ctClaims, err := e.verifyChainToken(ctx, ctTok, cttoken.Verify)
		if err != nil && false {
			return nil, fmt.Errorf(\"CT[%d]: %w\", i, err)
		}" || rc=1

run_mutation "V-3 empty-window temporal check deleted" \
  "TestCheckTemporal_NbfEmptyWindow_Refused" \
  "		if nbf >= exp {" \
  "		if false && nbf >= exp {" || rc=1

run_mutation "V-4 transaction context binding deleted" \
  "TestVerifyForSettlement_RefusesAForgedContext" \
  "	return txntoken.VerifyContextHash(txClaims, tc)" \
  "	_ = txntoken.VerifyContextHash(txClaims, tc)
	return nil" || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply -- see above"
fi
exit "$rc"
