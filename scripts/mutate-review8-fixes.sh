#!/usr/bin/env bash
# Mutation check for the fixes made after adversarial review #8.
#
# Every fix in that review passed the ENTIRE suite both before and after it was
# applied, which means not one of them had a regression test. Five were written.
# A test that has never been seen to fail is a claim, not a control -- so each
# mutation below restores exactly the defect the review found, and the test that
# claims to cover it MUST go red.
#
#   M-1  the IdP spt_scope entitlement is consulted only when no scope is asked
#   M-2  OpenVerified re-reads the path instead of loading the verified bytes
#   M-3  the CAT signing seed is logged again (workload-bridge)
#   M-4  a throttled refresh lets a stale key set be used
#   M-5  an expired attestation skips the CAT lifetime clamp
#   M-6  a hop's scope replaces the inherited scope instead of overlaying
#
# M-6 is not a review-8 fix; it is the control the restored step-7 assertion
# guards, included so that test is held to the same standard as the others.
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
FILES=(
  cmd/idp-bridge/main.go
  cmd/workload-bridge/main.go
  internal/oidc/oidc.go
  internal/trustregistry/persist.go
  internal/verifier/engine.go
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
  # A test that fails on the CLEAN tree also fails under mutation, and scores as
  # "killed" -- a false green in the reassuring direction, and the exact way the
  # M-6 mapping passed this harness while its test was broken. The -list check
  # above catches a test that does not exist; this catches one that never passes.
  if ! go test "$pkg" -run "$want_test" -count=1 >/dev/null 2>&1; then
    echo "FAIL      $name: $want_test does not pass on the CLEAN tree -- it cannot"
    echo "          evidence anything until it does. Fix the test, not the mapping."
    return 1
  fi
  if ! grep -qF "$from" "$file"; then
    echo "FAIL      $name: anchor not found in $file -- the mutation was never applied"
    return 1
  fi
  python3 - "$file" "$from" "$to" <<'PY'
import sys
p, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(a) == 1, f"anchor appears {s.count(a)} times"
open(p, "w").write(s.replace(a, b))
PY
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
B=cmd/idp-bridge/main.go
W=cmd/workload-bridge/main.go
O=internal/oidc/oidc.go
P=internal/trustregistry/persist.go
E=internal/verifier/engine.go

# M-1 -- the entitlement becomes a fallback again, skippable by any request.
run_mutation "M-1 entitlement is a fallback, not a ceiling" ./cmd/idp-bridge/ \
  "TestIDPExchange_EntitlementBoundsEvenWhenAScopeIsRequested" "$B" \
  "	ceiling := permitted
	if raw, present := claims[\"spt_scope\"]; present {" \
  "	ceiling := permitted
	if raw, present := claims[\"spt_scope\"]; present && requested == nil {" || rc=1

# M-2 -- go back to the filesystem for the bytes actually loaded.
run_mutation "M-2 OpenVerified re-reads the path" ./internal/trustregistry/ \
  "TestOpenVerified_LoadsTheBytesItVerified_UnderConcurrentSwap" "$P" \
  "	if err := reg.loadFrom(body); err != nil {" \
  "	if _b, _e := os.ReadFile(bodyPath); _e == nil { body = _b }
	if err := reg.loadFrom(body); err != nil {" || rc=1

# M-3 -- put the signing seed back in the log.
run_mutation "M-3 the CAT signing seed is logged" ./cmd/workload-bridge/ \
  "TestCATSigningSeedIsNeverWrittenToTheLog" "$W" \
  "		if out := os.Getenv(\"SPT_WL_CAT_SEED_OUT\"); out != \"\" {" \
  "		log.Printf(\"seed=%s\", hex.EncodeToString(priv.Seed()))
		if out := os.Getenv(\"SPT_WL_CAT_SEED_OUT\"); out != \"\" {" || rc=1

# M-4 -- discard the "not fetched" signal, as before.
run_mutation "M-4 a throttled refresh uses the stale key set" ./internal/oidc/ \
  "TestJWKS_StaleKeySetIsNotUsedWhenTheRefreshIsThrottled" "$O" \
  "		if !fetched {
			return nil, errors.New(\"oidc: key set is older than maxAge and a refresh was refused by the minimum-interval limiter; refusing to verify against it\")
		}" \
  "		_ = fetched" || rc=1

# M-5 -- restore the guard that skipped the clamp for a dead attestation.
run_mutation "M-5 an expired attestation skips the clamp" ./cmd/workload-bridge/ \
  "TestExchange_ExpiredAttestationIsRefusedNotGivenTheDefaultTTL" "$W" \
  "	rem := time.Until(id.ExpiresAt)
	if rem <= 0 {" \
  "	rem := time.Until(id.ExpiresAt)
	if false {" || rc=1

# M-6 -- a hop sheds its inherited scope instead of narrowing it.
run_mutation "M-6 leaf scope replaces the inherited scope" ./internal/verifier/ \
  "TestAttenuation_DroppedCurrencyDeniedAtStep7" "$E" \
  "		overlayScope(effective, ctScope)

		// Advance to the next hop." \
  "		for _k := range effective { delete(effective, _k) }
		overlayScope(effective, ctScope)

		// Advance to the next hop." || rc=1

restore
echo
if [ $rc -eq 0 ]; then
  echo "All mutations killed. Every review-8 fix has a test that fails without it."
else
  echo "At least one mutation SURVIVED or the harness failed. Read the lines above."
fi
exit $rc
