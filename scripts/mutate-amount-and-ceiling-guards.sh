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
#   C1a an unqualified max_amount ceiling is projected     (tbac.TxnScope)
#   C1b an unqualified max_cumulative ceiling is projected (tbac.TxnScope)
#   C2a the max_amount branch projects an unparsed amount  (tbac.TxnScope)
#   C2b the cumulative branch projects an unparsed amount  (tbac.TxnScope)
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


# C1 and C2 were single mutations with want_n 2. TxnScope parses the amount and
# checks currency qualification TWICE -- once for max_amount, once for
# max_cumulative -- in byte-identical lines, so one anchor mutated both guards
# at once and reported "killed" on tests that only exercise the max_amount
# branch. want_n above 1 is a CLAIM that the occurrences are the same guard;
# here they were not. Split, one mutation per guard.

run_mutation "C1a unqualified max_amount ceiling projected" \
  ./internal/tbac/ "TestTxnScope_RefusesAnUnqualifiedCeiling" \
  internal/tbac/scope.go \
  "		if _, qualified := parent[\"currency\"]; !qualified {
			return nil, fmt.Errorf(\"capability declares %q but no %q: %w\",
				\"max_amount\", \"currency\", ErrCeilingUnqualified)" \
  "		if _, qualified := parent[\"currency\"]; false && !qualified {
			return nil, fmt.Errorf(\"capability declares %q but no %q: %w\",
				\"max_amount\", \"currency\", ErrCeilingUnqualified)" || rc=1

run_mutation "C1b unqualified max_cumulative ceiling projected" \
  ./internal/tbac/ "TestTxnScope_UnqualifiedCumulativeCeiling_Refused" \
  internal/tbac/scope.go \
  "		if _, qualified := parent[\"currency\"]; !qualified {
			return nil, fmt.Errorf(\"capability declares %q but no %q: %w\",
				cumulativeDim, \"currency\", ErrCeilingUnqualified)" \
  "		if _, qualified := parent[\"currency\"]; false && !qualified {
			return nil, fmt.Errorf(\"capability declares %q but no %q: %w\",
				cumulativeDim, \"currency\", ErrCeilingUnqualified)" || rc=1

run_mutation "C2a max_amount branch projects an unparsed amount" \
  ./internal/tbac/ "TestTxnScope_RefusesNonPositiveAmounts|TestTxnScope_RefusesNonCanonicalAmounts" \
  internal/tbac/scope.go \
  "		// re-derive one here (see its doc comment for why big.Rat alone is too
		// permissive — \"0x2710\" is 10000 to it, and \"-5000 <= 5000\" is true).
		if _, err := ledger.ParseAmount(tc.Amount); err != nil {" \
  "		// re-derive one here (see its doc comment for why big.Rat alone is too
		// permissive — \"0x2710\" is 10000 to it, and \"-5000 <= 5000\" is true).
		if _, err := ledger.ParseAmount(tc.Amount); false && err != nil {" || rc=1

run_mutation "C2b cumulative branch projects an unparsed amount" \
  ./internal/tbac/ "TestTxnScope_Cumulative" \
  internal/tbac/scope.go \
  "		if _, err := ledger.ParseAmount(tc.Amount); err != nil {
			return nil, fmt.Errorf(\"transaction amount: %w\", err)
		}
		out[cumulativeDim] = json.Number(tc.Amount)" \
  "		out[cumulativeDim] = json.Number(tc.Amount)" || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "OK — the amount grammar and the ceiling-qualification guard are load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
