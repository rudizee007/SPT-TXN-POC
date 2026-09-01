#!/usr/bin/env bash
# Mutation check for the chain, single-use, ledger, PEP-surface and snapshot
# guards added 2026-09-01. Each mutation removes exactly one control and the
# test that claims to cover it MUST go red; a test that has never been seen to
# fail is a claim, not a control.
#
#   C-1  a budgeted parent's non-slice child is accepted (verifier)
#   C-2  a budgeted parent's non-slice child is minted (cttoken.Issue)
#   C-3  Verify records nothing on ALLOW
#   C-4  VerifyForSettlement records nothing on ALLOW
#   C-5  the slice is not recorded, only the SPT-Txn
#   C-6  the single-use record never refuses
#   L-1  step 8 ignores the transaction's chain
#   P-1  the MCP method allowlist is not consulted
#   P-2  A2A metadata members other than the token are forwarded
#   P-3  A2A role is not pinned
#   S-1  an older snapshot loads with an acceptance record present
#   S-2  the acceptance record is not advanced
#   S-3  a future-dated snapshot is accepted
#   S-4  Lookup ignores the snapshot's max_age
#   A-1  agentsvc accepts an audience from the request body
#
# NOT COVERED BY MUTATION, and why:
#
#   * the ZK chain path refusing a budgeted CAT or leaf. Exercising it needs an
#     injected ChainVerifier that passes EnableChainZK's binding probes, which
#     the gnark harness provides and this script does not build. The refusal
#     is three lines in step6ChainZK and is held by reading until a ZK-mode
#     regression test exists.
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
FILES=(
  internal/verifier/engine.go
  internal/cttoken/cttoken.go
  internal/txntoken/txntoken.go
  internal/mcppep/mcppep.go
  internal/a2apep/a2apep.go
  pkg/trustsnapshot/verify.go
  internal/trustregistry/persist.go
  cmd/agentsvc/main.go
)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"; done
restore() { for f in "${FILES[@]}"; do cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"; done; }
trap 'restore; rm -rf "$BAKDIR"' EXIT INT TERM

run_mutation() {
  local name="$1" pkg="$2" want_test="$3" file="$4" from="$5" to="$6"
  restore
  if [ -z "$(go test "$pkg" -list "$want_test" 2>/dev/null | grep -E "^Test")" ]; then
    echo "FAIL      $name: $want_test matches no test in $pkg -- fix the mapping, do not skip it"
    return 1
  fi
  if ! go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$file"; then
    echo "FAIL      $name: anchor not found in $file -- the mutation was never applied"
    return 1
  fi
  if ! python3 - "$file" "$from" "$to" <<'PY'
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
  if ! go build "$pkg" >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile -- rewrite it, do not skip it"
    return 1
  fi
  if go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "SURVIVED  $name -- $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0
V=./internal/verifier/

run_mutation "C-1 budgeted parent's non-slice child accepted" "$V" \
  "TestChain_ChildOfBudgetedParentMustBeASlice" internal/verifier/engine.go \
  "	if !childBudgeted {
		return nil, fmt.Errorf(\"parent holds a cumulative budget" \
  "	if false && !childBudgeted {
		return nil, fmt.Errorf(\"parent holds a cumulative budget" || rc=1

run_mutation "C-2 budgeted parent's non-slice child minted" "$V" \
  "TestChain_ChildOfBudgetedParentMustBeASlice" internal/cttoken/cttoken.go \
  "	if (tbac.DeclaresCumulativeBudget(parentScope) || committed) && req.Subband == nil {" \
  "	if false && (tbac.DeclaresCumulativeBudget(parentScope) || committed) && req.Subband == nil {" || rc=1

run_mutation "C-3 Verify records nothing" "$V" \
  "TestSingleUse_SPTTxn" internal/verifier/engine.go \
  "	if err := e.consumeOnAllow(txClaims, ctClaims); err != nil {
		return deny(8, err)
	}
	return Decision{Allow: true}" \
  "	return Decision{Allow: true}" || rc=1

run_mutation "C-4 VerifyForSettlement records nothing" "$V" \
  "TestSingleUse_Settlement" internal/verifier/engine.go \
  "	if err := e.consumeOnAllow(txClaims, ctClaims); err != nil {
		return facts, deny(8, err)
	}" \
  "" || rc=1

run_mutation "C-5 the slice is not recorded" "$V" \
  "TestSingleUse_SliceIdentityIsTheCommittedTuple" internal/verifier/engine.go \
  "	if sl, ok := ctClaims[leafSliceClaim].(*sliceIdentity); ok && sl != nil {" \
  "	if sl, ok := ctClaims[leafSliceClaim].(*sliceIdentity); ok && sl != nil && false {" || rc=1

run_mutation "C-6 the single-use record never refuses" "$V" \
  "TestSingleUse_ConcurrentPresentationsAllowExactlyOne" internal/verifier/engine.go \
  "		if exp, ok := c.seen[it.key]; ok && now.Before(exp) {
			return false
		}" \
  "		_ = it" || rc=1

# The load-bearing line is the adapter selection: every adapter writes its own
# chain tag into the preimage, so selecting by tc.Chain makes a mismatched
# chain a digest mismatch. The explicit tc.Chain != chain compare above it is
# a clearer error for the same refusal, not a second control, so it is not
# mutated on its own.
run_mutation "L-1 step 8 selects the adapter from the token" ./internal/txntoken/ \
  "TestVerifyContextHash_ChainMustMatchTheExecutor" internal/txntoken/txntoken.go \
  "	if tc.Chain != chain {
		return fmt.Errorf(\"transaction chain %q does not match the token's spt_txn_chain %q\", tc.Chain, chain)
	}
	l, err := ledger.Get(tc.Chain)" \
  "	l, err := ledger.Get(chain)" || rc=1

run_mutation "P-1 MCP allowlist not consulted" ./internal/mcppep/ \
  "TestMethodsOffTheAllowlistAreDenied" internal/mcppep/mcppep.go \
  "		if !observableMethods[req.Method] {" \
  "		if false && !observableMethods[req.Method] {" || rc=1

run_mutation "P-2 A2A uncovered metadata forwarded" ./internal/a2apep/ \
  "TestUncoveredMetadataAndRoleAreRefused" internal/a2apep/a2apep.go \
  "		if k != TokenMetaKey {
			m.Engine.RecordDeny(\"rpc.metadata-uncovered\", false, \"\")" \
  "		if false && k != TokenMetaKey {
			m.Engine.RecordDeny(\"rpc.metadata-uncovered\", false, \"\")" || rc=1

run_mutation "P-3 A2A role not pinned" ./internal/a2apep/ \
  "TestUncoveredMetadataAndRoleAreRefused" internal/a2apep/a2apep.go \
  "	if msg.Role != \"\" && msg.Role != \"user\" {" \
  "	if false && msg.Role != \"\" && msg.Role != \"user\" {" || rc=1

run_mutation "S-1 an older snapshot loads with a record present" ./internal/trustregistry/ \
  "TestOpenVerified_StateRefusesAnOlderSnapshot" pkg/trustsnapshot/verify.go \
  "			case m.IssuedMs < st.IssuedMs:" \
  "			case false && m.IssuedMs < st.IssuedMs:" || rc=1

run_mutation "S-2 the record is not advanced" ./internal/trustregistry/ \
  "TestOpenVerified_StateIsRecordedAndUnwritableStateRefuses" pkg/trustsnapshot/verify.go \
  "		if !found || m.IssuedMs > st.IssuedMs {" \
  "		if !found {" || rc=1

run_mutation "S-3 a future-dated snapshot accepted" ./internal/trustregistry/ \
  "TestOpenVerified_RefusesAFutureDatedSnapshot" pkg/trustsnapshot/verify.go \
  "	if issued.After(now.Add(skew)) {" \
  "	if false && issued.After(now.Add(skew)) {" || rc=1

run_mutation "S-4 Lookup ignores max_age" ./internal/trustregistry/ \
  "TestLookup_RefusesOnceTheSnapshotIsPastMaxAge" internal/trustregistry/persist.go \
  "	if !r.freshUntil.IsZero() && now.After(r.freshUntil) {" \
  "	if false && !r.freshUntil.IsZero() && now.After(r.freshUntil) {" || rc=1

run_mutation "A-1 agentsvc accepts a body audience" ./cmd/agentsvc/ \
  "TestHandleVerify_AudienceIsConfiguration" cmd/agentsvc/main.go \
  "		if req.Audience != \"\" {" \
  "		if false && req.Audience != \"\" {" || rc=1

if [ $rc -eq 0 ]; then
  echo
  echo "All mutations killed."
else
  echo
  echo "At least one mutation SURVIVED or could not be applied. See above."
fi
exit $rc
