#!/usr/bin/env bash
# Mutation check for the ENFORCEMENT-side guards on the amount and the ceiling.
#
# These sit on the trust boundary: tbac.TxnScope is shared by the issuer
# (txntoken) and the verifier engine (step 7), and ledger.ParseAmount is the one
# grammar every adapter's Validate goes through. A guard here that no test
# notices is a guard a refactor deletes.
#
#   A1  a non-positive amount is accepted                 (ledger.ParseAmount)
#   A2  the grammar check is skipped entirely             (ledger.ParseAmount)
#   A3  leading zeros are tolerated                       (ledger.ParseAmount)
#   A4  junk after the integer part is tolerated          (ledger.ParseAmount)
#   A5  a bare "." fraction with no digits is tolerated   (ledger.ParseAmount)
#   A6  the adapters stop sharing the one grammar         (ledger.validAmount)
#   C1  an unqualified ceiling is projected anyway        (tbac.TxnScope)
#   C2  the amount is projected without being parsed      (tbac.TxnScope)
#
# Each mutation must turn at least one NAMED test red. A mutation that does not
# compile, or whose anchor is not found, is a bug in THIS script — never a pass.
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FILES=(internal/ledger/amount.go internal/ledger/ledger.go internal/tbac/scope.go)
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

run_mutation "A1 non-positive amount accepted" \
  ./internal/ledger/ "TestParseAmount_RejectsNonPositive" \
  internal/ledger/amount.go \
  "	if r.Sign() <= 0 {" \
  "	if false && r.Sign() <= 0 {" || rc=1

run_mutation "A2 grammar check skipped" \
  ./internal/ledger/ "TestParseAmount_RejectsTheWiderBigRatGrammar" \
  internal/ledger/amount.go \
  "	if err := checkAmountGrammar(s); err != nil {" \
  "	if err := checkAmountGrammar(s); false && err != nil {" || rc=1

run_mutation "A3 leading zeros tolerated" \
  ./internal/ledger/ "TestParseAmount_LeadingZeroIsDiagnosedAsSuch" \
  internal/ledger/amount.go \
  "		if i < len(s) && s[i] != '.' {
			return bad(\"leading zero\")" \
  "		if false && i < len(s) && s[i] != '.' {
			return bad(\"leading zero\")" || rc=1

run_mutation "A4 junk after the integer part tolerated" \
  ./internal/ledger/ "TestParseAmount_RejectsTheWiderBigRatGrammar|TestParseAmount_RejectsMalformed" \
  internal/ledger/amount.go \
  "	if s[i] != '.' {
		return bad(\"unexpected character after the integer part\")" \
  "	if false && s[i] != '.' {
		return bad(\"unexpected character after the integer part\")" || rc=1

run_mutation "A5 empty fraction tolerated" \
  ./internal/ledger/ "TestParseAmount_RejectsMalformed" \
  internal/ledger/amount.go \
  "	if i == len(s) {
		return bad(\"no digits after the decimal point\")" \
  "	if false && i == len(s) {
		return bad(\"no digits after the decimal point\")" || rc=1

run_mutation "A6 adapters stop sharing the one grammar" \
  ./internal/ledger/ "TestValidAmount_MatchesParseAmountExactly|TestGenericAdapter_RefusesTheSameAmounts" \
  internal/ledger/ledger.go \
  "func validAmount(s string) error {
	_, err := ParseAmount(s)
	return err
}" \
  "func validAmount(s string) error {
	if s == \"\" {
		return ErrAmountEmpty
	}
	return nil
}" || rc=1

run_mutation "C1 unqualified ceiling projected anyway" \
  ./internal/tbac/ "TestTxnScope_RefusesAnUnqualifiedCeiling" \
  internal/tbac/scope.go \
  "		if _, qualified := parent[\"currency\"]; !qualified {" \
  "		if _, qualified := parent[\"currency\"]; false && !qualified {" || rc=1

run_mutation "C2 amount projected without being parsed" \
  ./internal/tbac/ "TestTxnScope_RefusesNonPositiveAmounts|TestTxnScope_RefusesNonCanonicalAmounts" \
  internal/tbac/scope.go \
  "		if _, err := ledger.ParseAmount(tc.Amount); err != nil {" \
  "		if _, err := ledger.ParseAmount(tc.Amount); false && err != nil {" || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "OK — the amount grammar and the ceiling-qualification guard are load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
