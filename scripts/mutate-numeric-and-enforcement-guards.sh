#!/usr/bin/env bash
# Mutation check for the NUMERIC-REPRESENTATION guards and the enforcement-side
# checks that a non-conforming issuer is the only way to reach.
#
# Everything here came out of an adversarial review, and most of it exists
# because a conversion that looks total is not: Go's float-to-integer conversion
# is implementation-defined out of range, so the same signed token can verify on
# one machine and not the other.
#
#   Z1  a negative ZK ceiling is converted anyway          (verifier.uint64Ceiling)
#   Z2  a ceiling wider than 64 bits is converted anyway   (verifier.uint64Ceiling)
#   Z3  a fractional ceiling truncates silently            (verifier.uint64Ceiling)
#   Z4  a claim outside int64 is converted anyway          (verifier.intClaim)
#   Z5  a non-positive delegation depth reaches the proof  (verifier.step6ChainZK)
#   P1  a negative ceiling is sealable                     (tbac.ValidateIssuance)
#   P2  an undeclared numeric dimension is sealable        (tbac.ValidateIssuance)
#   P3  an object-valued ceiling is recursed past          (tbac.validateIssuance)
#   P4  a deep inherited unit is discarded                 (tbac.inheritMoneyUnit)
#   E1  an unqualified ceiling is enforced anyway          (end to end, forged chain)
#   E2  a non-canonical amount clears the ceiling          (end to end, forged chain)
#   T1  the travel-rule wire gets its own amount grammar   (trp.ValidAmount)
#
# E1 and E2 run against a FORGED chain, because the issuers now refuse to mint
# the inputs — which is exactly why the enforcement-side guard needs its own
# coverage rather than inheriting the issuer's.
#
# A mutation that does not compile, or whose anchor is not found, is a bug in
# THIS script — never a pass.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FILES=(internal/verifier/engine.go internal/tbac/issuance.go internal/tbac/scope.go internal/trp/trp.go)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"; done
restore() { for f in "${FILES[@]}"; do cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"; done; }
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

run_mutation "Z1 negative ZK ceiling converted" \
  ./internal/verifier/ "TestUint64Ceiling_RefusesEverythingTheConversionCannotCarry" \
  internal/verifier/engine.go \
  "	if r.Sign() < 0 {
		return 0, fmt.Errorf(\"must not be negative, got %s\", r.RatString())" \
  "	if false && r.Sign() < 0 {
		return 0, fmt.Errorf(\"must not be negative, got %s\", r.RatString())" || rc=1

run_mutation "Z2 over-wide ZK ceiling converted" \
  ./internal/verifier/ "TestUint64Ceiling_RefusesEverythingTheConversionCannotCarry" \
  internal/verifier/engine.go \
  "	if n.BitLen() > 64 {" \
  "	if false && n.BitLen() > 64 {" || rc=1

run_mutation "Z3 fractional ZK ceiling truncated" \
  ./internal/verifier/ "TestUint64Ceiling_RefusesEverythingTheConversionCannotCarry" \
  internal/verifier/engine.go \
  "	if !r.IsInt() {" \
  "	if false && !r.IsInt() {" || rc=1

run_mutation "Z4 out-of-int64 claim converted" \
  ./internal/verifier/ "TestIntClaim_RefusesValuesItCannotRepresent" \
  internal/verifier/engine.go \
  "	if math.IsNaN(f) || math.IsInf(f, 0) || f < math.MinInt64 || f >= math.MaxInt64 {" \
  "	if false && (math.IsNaN(f) || math.IsInf(f, 0) || f < math.MinInt64 || f >= math.MaxInt64) {" || rc=1

run_mutation "Z5 non-positive depth reaches the proof" \
  ./internal/verifier/ "TestUint64Depth_RefusesANonPositiveBudget" \
  internal/verifier/engine.go \
  "	if n < 1 {" \
  "	if false && n < 1 {" || rc=1

run_mutation "P1 negative ceiling sealable" \
  ./internal/tbac/ "TestValidateIssuance_RefusesNegativeCeilings" \
  internal/tbac/issuance.go \
  "	if r.Sign() < 0 {
		return fmt.Errorf(\"scope dimension %q: %w (value is %v)\", name, ErrCeilingNegative, v)" \
  "	if false && r.Sign() < 0 {
		return fmt.Errorf(\"scope dimension %q: %w (value is %v)\", name, ErrCeilingNegative, v)" || rc=1

run_mutation "P2 undeclared numeric sealable" \
  ./internal/tbac/ "TestValidateIssuance_RefusesUndeclaredNumericDimensions" \
  internal/tbac/issuance.go \
  "			if _, declaredDir := directionOf(dim); !declaredDir {" \
  "			if _, declaredDir := directionOf(dim); false && !declaredDir {" || rc=1

run_mutation "P3 object-valued ceiling recursed past" \
  ./internal/tbac/ "TestValidateIssuance_ObjectValuedCeilingIsDiagnosedNotRecursedPast" \
  internal/tbac/issuance.go \
  "		if moneyCeilings[dim] {
			if err := validateMoneyCeiling(s, name, v, path); err != nil {
				return err
			}
			continue
		}
		if nested, ok := asObject(v); ok {" \
  "		if nested, ok := asObject(v); ok {" || rc=1

run_mutation "P4 deep inherited unit discarded" \
  ./internal/tbac/ "TestInheritMoneyUnit_CarriesTheUnitDownThroughTwoLevels" \
  internal/tbac/issuance.go \
  "			if scopesEqual(fixed, nested) {" \
  "			if len(fixed) == len(nested) {" || rc=1

run_mutation "E1 unqualified ceiling enforced anyway" \
  ./internal/verifier/ "TestNonConformingIssuer_UnqualifiedCeilingAtTheRootIsRefused" \
  internal/tbac/scope.go \
  "		if _, qualified := parent[\"currency\"]; !qualified {" \
  "		if _, qualified := parent[\"currency\"]; false && !qualified {" || rc=1

run_mutation "E2 non-canonical amount clears the ceiling" \
  ./internal/verifier/ "TestNonConformingIssuer_NonCanonicalAmountIsRefusedAtTheScopeStep" \
  internal/tbac/scope.go \
  "		if _, err := ledger.ParseAmount(tc.Amount); err != nil {" \
  "		if _, err := ledger.ParseAmount(tc.Amount); false && err != nil {" || rc=1

run_mutation "T1 travel-rule wire re-grows its own grammar" \
  ./internal/trp/ "TestValidAmount" \
  internal/trp/trp.go \
  "	if _, err := ledger.ParseAmount(s); err != nil {
		return fmt.Errorf(\"trp: %w\", err)
	}" \
  "	if _, err := ledger.ParseAmount(s); err != nil && s == \"\" {
		return fmt.Errorf(\"trp: %w\", err)
	}" || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "OK — every numeric-representation and enforcement-side guard is load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
