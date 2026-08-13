#!/usr/bin/env bash
# Mutation check for the gateway lifetime bound (adversarial review #3, F3).
#
# A passing suite is not evidence that a guard works. Each mutation below
# disables exactly one of the three guards that make a non-chain-walking PEP
# safe; the test that claims to cover it MUST fail. A mutation that survives
# means the corresponding assertion is decorative, which is the failure mode
# that let the original defect ship: a config field whose doc said "should be
# >= the maximum token TTL" with nothing checking it.
#
#   M-A  the token lifetime bound never fires
#   M-B  ReplayWindow may be shorter than MaxTokenTTL
#   M-C  a token with no exp is accepted
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=internal/decision/decision.go
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
  if ! go build ./internal/decision/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test ./internal/decision/ -run "$want_test" >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "M-A lifetime bound never fires" \
  "TestOverLongTokenIsRefusedBeforeItCanBurnAReplaySlot" \
  "remaining > e.cfg.MaxTokenTTL {" \
  "false && remaining > e.cfg.MaxTokenTTL {" || rc=1

run_mutation "M-B replay window may under-cover" \
  "TestNewRefusesAnUnboundedOrUnmemorableLifetime" \
  "if cfg.ReplayWindow < cfg.MaxTokenTTL {" \
  "if false && cfg.ReplayWindow < cfg.MaxTokenTTL {" || rc=1

run_mutation "M-C missing exp is accepted" \
  "TestMissingExpIsRefused" \
  "	expF, ok := claims[\"exp\"].(float64)
	if !ok {" \
  "	expF, ok := claims[\"exp\"].(float64)
	if false && !ok {" || rc=1

cp "$BAK" "$F"
if [ "$rc" -eq 0 ]; then
  echo "OK — all three guards are load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
