#!/usr/bin/env bash
# Mutation check for the audience binding and the chain-token temporal rules.
#
# Six tests went green on the first run. That is the moment to check they are
# testing the guard and not something adjacent to it — most of what went wrong
# today was a check that passed while establishing nothing.
#
#   AUDIENCE (engine.go, step3Audience)
#     M-A  revert to the permissive original — `aud, _ := claims["aud"].(string)`
#          with no configured-audience and no presence check. An unset Audience
#          then accepts a token carrying no aud, because "" == "".
#
#   CHAIN TEMPORAL (engine.go, checkChainTokenTemporal)
#     M-B  the whole function becomes a no-op. Nothing about a CAT or CT's own
#          iat/exp is checked, which is the state this change corrects.
#     M-C  the future-iat check alone is disabled. A capability minted to become
#          valid next month is usable today.
#     M-D  the exp>iat check alone is disabled. A zero-length or inverted
#          validity window is accepted.
#
# Restores engine.go on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ENGINE=internal/verifier/engine.go
BAK=$(mktemp)
cp "$ENGINE" "$BAK"
trap 'cp "$BAK" "$ENGINE"; rm -f "$BAK"' EXIT INT TERM

run_mutation() {
  local name="$1" from="$2" to="$3"
  cp "$BAK" "$ENGINE"
  # These tests must pass CLEAN, or their failure under mutation evidences
  # nothing. This file already asserts the test COUNT is non-zero; a green
  # over tests that were already red is the other half of the same hole.
  if ! go test ./internal/verifier/ -count=1 -run 'TestSec_Unconfigured|TestSec_MissingAud|TestSec_ArrayAud|TestSec_ChainToken' >/dev/null 2>&1; then
    echo "FAIL      $name: the mapped tests do not pass on the CLEAN tree"
    return 1
  fi
  if ! grep -qF "$from" "$ENGINE"; then
    echo "FAIL      $name: anchor not found — the mutation was never applied"
    return 1
  fi
  if ! python3 - "$ENGINE" "$from" "$to" <<'PY'
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
  if ! go build -o /dev/null ./internal/verifier/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  # A green result over ZERO tests is the failure this whole file guards
  # against, so the count is asserted rather than trusted.
  local out rc ran
  out=$(go test ./internal/verifier/ -count=1 -run 'TestSec_Unconfigured|TestSec_MissingAud|TestSec_ArrayAud|TestSec_ChainToken' -v 2>&1)
  rc=$?
  ran=$(printf '%s' "$out" | grep -c "^=== RUN" || true)
  if [ "$ran" -eq 0 ]; then
    echo "BROKEN    $name: 0 tests ran — the invocation is wrong, not the guard"
    return 1
  fi
  if [ "$rc" -eq 0 ]; then
    echo "SURVIVED  $name — $ran test(s) ran and still passed. That guard is decorative."
    return 1
  fi
  echo "killed    $name  ($ran test(s) ran)"
  return 0
}

rc=0

run_mutation "M-A audience reverts to permissive" \
'	if expected == "" {
		return fmt.Errorf("verifier has no configured audience: refusing to evaluate " +
			"audience binding. Set Engine.Audience to this deployment'"'"'s identifier — an " +
			"unset audience would accept a token minted for any relying party")
	}
	raw, present := txClaims["aud"]
	if !present {
		return fmt.Errorf("SPT-Txn Token has no aud claim; this domain is %q", expected)
	}
	aud, ok := raw.(string)
	if !ok {
		return fmt.Errorf("aud claim is %T, not a string; this engine binds a single audience", raw)
	}' \
'	aud, _ := txClaims["aud"].(string)' || rc=1

run_mutation "M-B chain temporal check is a no-op" \
'func checkChainTokenTemporal(label string, claims map[string]any) error {' \
'func checkChainTokenTemporal(label string, claims map[string]any) error {
	return nil' || rc=1

run_mutation "M-C future iat tolerated" \
'	if iat > time.Now().Unix()+iatSkew {' \
'	if false && iat > time.Now().Unix()+iatSkew {' || rc=1

run_mutation "M-D inverted validity window tolerated" \
'	if exp <= iat {' \
'	if false && exp <= iat {' || rc=1

cp "$BAK" "$ENGINE"
if [ "$rc" -eq 0 ]; then
  echo "OK — audience binding and both chain temporal rules are load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green."
fi
exit "$rc"
