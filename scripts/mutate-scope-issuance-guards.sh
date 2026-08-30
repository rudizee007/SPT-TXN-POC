#!/usr/bin/env bash
# Mutation check for the two scope guards on the ISSUANCE path.
#
# Both close the same shape of bug: a request the issuer cannot honour producing
# a WIDER grant instead of a refusal.
#
#   F1-A  a malformed requested scope looks like an absent one   (idp-bridge)
#   F1-B  a `null` scope looks like an absent one                (idp-bridge)
#   F1-C  a non-object spt_scope claim is silently ignored       (idp-bridge)
#   F1-D  a malformed requested scope looks like an absent one   (workload-bridge)
#   F1-E  a `null` scope looks like an absent one                (workload-bridge)
#   F5-A  a monetary ceiling needs no currency                   (tbac)
#   F5-B  a non-string currency qualifies a ceiling              (tbac)
#   F5-C  the root CAT issuer stops checking its scope           (cattoken)
#   F5-D  a delegated scope stops inheriting its parent's unit    (cttoken)
#   F5-E  a delegated scope stops being validated                (cttoken)
#
# Each mutation must turn at least one NAMED test red. A mutation that does not
# compile, or whose anchor is not found, is a bug in THIS script — never a pass.
# (The anchor check exists because a `sed` whose pattern silently fails to match
# reports as a surviving mutation, which reads as reassuring and is not.)
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FILES=(
  internal/tbac/issuance.go
  internal/cattoken/cattoken.go
  internal/cttoken/cttoken.go
  cmd/idp-bridge/main.go
  cmd/workload-bridge/main.go
)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do
  cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"
done
restore() {
  for f in "${FILES[@]}"; do
    cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"
  done
}
trap 'restore; rm -rf "$BAKDIR"' EXIT INT TERM

run_mutation() {
  local name="$1" pkg="$2" want_test="$3" file="$4" from="$5" to="$6" want_n="${7:-1}"
  restore
  # A test that fails on the CLEAN tree also fails under mutation, and scores as
  # "killed" -- a false green in the reassuring direction. The -list check above
  # catches a test that does not exist; this catches one that never passes.
  if ! go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$file"; then
    echo "FAIL      $name: anchor not found in $file — the mutation was never applied"
    return 1
  fi
  python3 - "$file" "$from" "$to" "$want_n" <<'PY'
import sys
p, a, b, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
s = open(p).read()
assert s.count(a) == n, f"anchor appears {s.count(a)} times, expected {n}"
open(p, "w").write(s.replace(a, b))
PY
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

run_mutation "F1-A malformed scope looks absent (idp)" \
  ./cmd/idp-bridge/ "TestIDPExchange_MalformedScope" \
  cmd/idp-bridge/main.go \
  "		return nil, fmt.Errorf(\"scope is not a JSON object: %w\", err)" \
  "		return nil, nil" || rc=1

run_mutation "F1-B null scope looks absent (idp)" \
  ./cmd/idp-bridge/ "TestIDPExchange_MalformedScopeIsDeniedNotWidened" \
  cmd/idp-bridge/main.go \
  "	if m == nil {
		return nil, fmt.Errorf(\"scope must be a JSON object, not null\")" \
  "	if false && m == nil {
		return nil, fmt.Errorf(\"scope must be a JSON object, not null\")" || rc=1

run_mutation "F1-C non-object spt_scope ignored (idp)" \
  ./cmd/idp-bridge/ "TestIDPExchange_NonObjectSptScopeClaimIsDenied" \
  cmd/idp-bridge/main.go \
  "		s, ok := raw.(map[string]any)
		if !ok {" \
  "		s, ok := raw.(map[string]any)
		if false && !ok {" || rc=1

run_mutation "F1-D malformed scope looks absent (workload)" \
  ./cmd/workload-bridge/ "TestExchange_MalformedScope" \
  cmd/workload-bridge/main.go \
  "		return nil, fmt.Errorf(\"scope is not a JSON object: %w\", err)" \
  "		return nil, nil" || rc=1

run_mutation "F1-E null scope looks absent (workload)" \
  ./cmd/workload-bridge/ "TestExchange_MalformedScopeIsDeniedNotWidened" \
  cmd/workload-bridge/main.go \
  "	if m == nil {
		return nil, fmt.Errorf(\"scope must be a JSON object, not null\")" \
  "	if false && m == nil {
		return nil, fmt.Errorf(\"scope must be a JSON object, not null\")" || rc=1

run_mutation "F5-A ceiling needs no currency" \
  ./internal/tbac/ "TestValidateIssuance_MoneyCeilingRequiresCurrency" \
  internal/tbac/issuance.go \
  "	cur, declared := s[\"currency\"]
	if !declared {" \
  "	cur, declared := s[\"currency\"]
	if false && !declared {" || rc=1

run_mutation "F5-B non-string currency accepted" \
  ./internal/tbac/ "TestValidateIssuance_CurrencyMustBeANonEmptyString" \
  internal/tbac/issuance.go \
  "	cs, ok := cur.(string)
	if !ok || cs == \"\" {" \
  "	cs, ok := cur.(string)
	if false && (!ok || cs == \"\") {" || rc=1

run_mutation "F5-C root CAT stops checking its scope" \
  ./internal/cattoken/ "TestIssue_RefusesMoneyCeilingWithoutCurrency" \
  internal/cattoken/cattoken.go \
  "	if err := tbac.ValidateIssuance(tbac.Scope(req.Scope)); err != nil {" \
  "	if err := tbac.ValidateIssuance(tbac.Scope(req.Scope)); false && err != nil {" || rc=1

run_mutation "F5-D the parent's unit is not carried down" \
  ./internal/cttoken/ "TestIssue_CarriesParentCurrencyDownWithTheCeiling" \
  internal/tbac/issuance.go \
  "	out[\"currency\"] = inherited" \
  "	_ = inherited" || rc=1

run_mutation "F5-E a ceiling with no unit anywhere is tolerated" \
  ./internal/tbac/ "TestInheritMoneyUnit_FailsWhenThereIsNoUnitAnywhere" \
  internal/tbac/issuance.go \
  "	inherited, ok := parent[\"currency\"]
	if !ok {" \
  "	inherited, ok := parent[\"currency\"]
	if false && !ok {" || rc=1

run_mutation "F5-F the delegated scope is never validated" \
  ./internal/cttoken/ "TestIssue_CarriesParentCurrencyDownWithTheCeiling" \
  internal/cttoken/cttoken.go \
  "	attenuated, err = tbac.InheritMoneyUnit(parentScope, attenuated)" \
  "	_, _ = tbac.InheritMoneyUnit(parentScope, attenuated)" 2 || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "OK — every scope guard on the issuance path is load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
