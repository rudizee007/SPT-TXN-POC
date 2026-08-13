#!/usr/bin/env bash
# Mutation check for the final-hop TTL invariant (adversarial review #3, F2).
#
# exp(SPT-Txn) <= exp(leaf CT) was enforced by txntoken.Issue and by nothing in
# the verifier, which is the asymmetry DELEGATION-INTENT-MCP.md §1.2 invariant 2
# exists to forbid: a child that outlives its parent MUST be rejected at
# construction AND at verification, so a malicious issuer cannot extend a
# lifetime. This proves the new check is load-bearing rather than decorative.
#
#   M-A  the check is never called          (wiring)
#   M-B  the comparison never fires         (logic)
#   M-C  an unusable exp fails open         (fail-closed behaviour)
#
# M-C is checked by a WHITE-BOX test. Its branches are unreachable through
# Verify — step2Expiry and cttoken.Verify already guarantee usable exps — so an
# end-to-end test of them passes because something else denied first. The first
# version of this script caught exactly that: M-C survived, and the test it
# named was deleted rather than kept as decoration.
#
# Not mutated: intClaim's int -> int64 widening. Its effect is unobservable on a
# 64-bit target, so any mutation here would be theatre. It is a portability fix
# and is honestly labelled as one rather than given a test that cannot fail.
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
  if ! grep -qF "$from" "$F"; then
    echo "FAIL      $name: anchor not found — the mutation was never applied"
    return 1
  fi
  python3 - "$F" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(a) == 1, f"anchor appears {s.count(a)} times"
open(p, "w").write(s.replace(a, b))
PY
  if ! go build ./internal/verifier/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test ./internal/verifier/ -run "$want_test" >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "M-A check is never called" \
  "TestSec_TxnMustNotOutliveItsLeafCapability|TestSec_TxnLifetimeAttenuationProperty" \
  "if err := checkTxnLifetime(txClaims, ctClaims); err != nil {" \
  "if err := checkTxnLifetime(txClaims, ctClaims); false && err != nil {" || rc=1

run_mutation "M-B comparison never fires" \
  "TestSec_TxnMustNotOutliveItsLeafCapability|TestSec_TxnLifetimeAttenuationProperty" \
  "	if txExp > leafExp {" \
  "	if false && txExp > leafExp {" || rc=1

run_mutation "M-C unusable exp fails open" \
  "TestCheckTxnLifetime" \
  "	txExp, ok := intClaim(txClaims, \"exp\")
	if !ok {" \
  "	txExp, ok := intClaim(txClaims, \"exp\")
	if false && !ok {" || rc=1

cp "$BAK" "$F"
if [ "$rc" -eq 0 ]; then
  echo "OK — the final-hop TTL check is load-bearing in wiring, logic and failure mode."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
