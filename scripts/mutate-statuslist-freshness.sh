#!/usr/bin/env bash
# Mutation check for status-list freshness at decision time (review #3, F4).
#
# VerifyToken checked the snapshot's expiry and then discarded it, so freshness
# was a property of the moment a snapshot entered the cache rather than of the
# moment a decision was made. A long-running PEP kept answering StatusValid for
# tokens revoked after population, indefinitely, with no unavailability signal —
# while the comment at the admission check claimed the opposite.
#
#   M-A  the staleness comparison never fires   (logic)
#   M-B  the snapshot expiry is never retained  (wiring)
#   M-C  a zero evaluation time is tolerated    (the footgun the parameter added)
#
# M-C is the interesting one. Making `now` a parameter removes the risk of a
# caller forgetting to consider time and replaces it with a caller passing the
# zero Time, whose Unix() is about -62135596800 — so every dated snapshot
# compares as not-yet-expired. A fix that introduces a new fail-open in place of
# the old one is not a fix, and only a mutation shows the guard is real.
#
# Restores the file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
F=internal/statuslist/token.go
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
  if ! go build ./internal/statuslist/ >/dev/null 2>&1; then
    echo "FAIL      $name: mutation does not compile — rewrite it, do not skip it"
    return 1
  fi
  if go test ./internal/statuslist/ -run "$want_test" >/dev/null 2>&1; then
    echo "SURVIVED  $name — $want_test still passes. That assertion is vacuous."
    return 1
  fi
  echo "killed    $name  (via $want_test)"
  return 0
}

rc=0

run_mutation "M-A staleness never fires" \
  "TestResolverRefusesAStaleSnapshot" \
  "if now.IsZero() || l.notAfter == 0 || now.Unix() >= l.notAfter {" \
  "if false && (now.IsZero() || l.notAfter == 0 || now.Unix() >= l.notAfter) {" || rc=1

run_mutation "M-B expiry never retained" \
  "TestResolverRefusesAStaleSnapshot" \
  "	l.notAfter = claims.Exp" \
  "	l.notAfter = 0" || rc=1

run_mutation "M-C zero evaluation time tolerated" \
  "TestZeroEvaluationTimeIsUnavailable|TestUndatedListIsNotUsableForDecisions" \
  "if now.IsZero() || l.notAfter == 0 || now.Unix() >= l.notAfter {" \
  "if l.notAfter == 0 && false || now.Unix() >= l.notAfter {" || rc=1

cp "$BAK" "$F"
if [ "$rc" -eq 0 ]; then
  echo "OK — freshness is enforced at decision time, retained from the snapshot, and safe against a zero clock."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
