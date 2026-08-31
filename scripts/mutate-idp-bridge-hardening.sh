#!/usr/bin/env bash
# Mutation check for the guards added after adversarial review #6
# (ADVERSARIAL-REVIEW-6-idp-bridge-2026-08-27.md).
#
# Every mutation below restores one of the behaviours that review found, and the
# test that claims to cover it MUST fail. This matters more here than usual: the
# review found that the pre-existing audience test passed vacuously — its fixture
# emitted no azp, so the branch it was meant to exercise was never reached. A
# suite that goes green is not evidence; a suite that goes red under mutation is.
#
#   M-A  azp satisfies the audience bound again
#   M-B  the discovery issuer member is optional again
#   M-C  jwks_uri may leave the issuer's origin
#   M-D  discovery and jwks follow redirects
#   M-E  a plaintext non-loopback issuer is accepted
#   M-F  a stale key set is used without refetching
#   M-G  the minimum refresh interval is gone
#   M-H  a jwk exponent is repaired rather than refused
#   M-I  an empty requested scope suppresses the IdP entitlement claim again
#        -- SUBSUMED by review 8. The entitlement is now composed into the
#        ceiling unconditionally (cmd/idp-bridge, "ceiling := permitted"), so
#        removing the len(requested)==0 guard no longer suppresses anything and
#        this mutation is a no-op. It reports SURVIVED, correctly: the assertion
#        it names is now vacuous BECAUSE the defect became unreachable, not
#        because the test is weak. The live control is M-1 in
#        scripts/mutate-review8-fixes.sh. Retire this entry or re-point it.
#   M-J  subject_token_type is accepted and discarded again
#   M-K  an already-expired subject token skips the TTL clamp again
#   M-L  ttl_hours is multiplied before it is bounded
#   M-M  credentials are honoured from the URL query again
#   M-N  a degenerate holder key may be sealed into a CAT
#
# Restores every file on any exit path, including Ctrl-C.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
FILES=(internal/oidc/oidc.go cmd/idp-bridge/main.go internal/cattoken/cattoken.go)
BAKDIR=$(mktemp -d)
for f in "${FILES[@]}"; do cp "$f" "$BAKDIR/$(echo "$f" | tr / _)"; done
restore() { for f in "${FILES[@]}"; do cp "$BAKDIR/$(echo "$f" | tr / _)" "$f"; done; }
trap 'restore; rm -rf "$BAKDIR"' EXIT INT TERM

run_mutation() {
  local name="$1" pkg="$2" want_test="$3" file="$4" from="$5" to="$6"
  restore
  # `go test -run` that matches NOTHING exits 0, which is indistinguishable from
  # a killed mutation and fails in the reassuring direction. Confirm on the CLEAN
  # tree that the named test exists in this package. Added because M-N was first
  # written against a package that did not contain its test, and scored as killed.
  if [ -z "$(go test "$pkg" -list "$want_test" 2>/dev/null | grep -E "^Test")" ]; then
    echo "FAIL      $name: $want_test matches no test in $pkg — fix the mapping, do not skip it"
    return 1
  fi
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
  if ! python3 - "$file" "$from" "$to" <<'PY'
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
  if ! go build "$pkg" >/dev/null 2>&1; then
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
O=internal/oidc/oidc.go
B=cmd/idp-bridge/main.go
C=internal/cattoken/cattoken.go

run_mutation "M-A azp satisfies the audience bound" ./internal/oidc/ \
  "TestAudience_AzpDoesNotSatisfyTheBound" "$O" \
  "func (v *Verifier) audienceOK(c Claims) bool {
	switch a := c[\"aud\"].(type) {" \
  "func (v *Verifier) audienceOK(c Claims) bool {
	if v.audiences[c.Str(\"azp\")] {
		return true
	}
	switch a := c[\"aud\"].(type) {" || rc=1

run_mutation "M-B discovery issuer member optional" ./internal/oidc/ \
  "TestDiscovery_IssuerMemberIsRequired" "$O" \
  "	if d.Issuer == \"\" {
		return errors.New(\"oidc: discovery document declares no issuer\")
	}" \
  "	if d.Issuer == \"\" {
		v.jwksURI = d.JWKSURI
		return nil
	}" || rc=1

run_mutation "M-C jwks_uri may leave the issuer origin" ./internal/oidc/ \
  "TestDiscovery_JWKSURIMustShareTheIssuerOrigin" "$O" \
  "	if err := sameOrigin(v.issuerURL, d.JWKSURI); err != nil {" \
  "	if err := error(nil); err != nil {" || rc=1

run_mutation "M-D redirects are followed" ./internal/oidc/ \
  "TestDiscovery_RedirectsAreNotFollowed" "$O" \
  "		hc:          &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}," \
  "		hc:          &http.Client{Timeout: 10 * time.Second}," || rc=1

run_mutation "M-E plaintext non-loopback issuer accepted" ./internal/oidc/ \
  "TestIssuerScheme" "$O" \
  "		if allowPlaintext || isLoopback(u.Hostname()) {
			return u, nil
		}" \
  "		return u, nil
		if allowPlaintext || isLoopback(u.Hostname()) {
			return u, nil
		}" || rc=1

run_mutation "M-F stale key set used without refetch" ./internal/oidc/ \
  "TestJWKS_StaleKeySetIsRefetchedBeforeUse" "$O" \
  "	if v.keySetStale() {" \
  "	if false && v.keySetStale() {" || rc=1

run_mutation "M-G minimum refresh interval removed" ./internal/oidc/ \
  "TestJWKS_UnknownKidDoesNotFetchOncePerRequest" "$O" \
  "	if !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < v.minInterval {" \
  "	if false && !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < v.minInterval {" || rc=1

run_mutation "M-H jwk exponent repaired not refused" ./internal/oidc/ \
  "TestJWK_ExponentIsRefusedRatherThanGuessed" "$O" \
  "	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf(\"oidc: jwk exponent %d is not a usable RSA public exponent\", e)
	}" \
  "	if e < 3 || e%2 == 0 {
		e = 65537
	}" || rc=1

run_mutation "M-I empty scope suppresses the IdP claim" ./cmd/idp-bridge/ \
  "TestScope_EmptyObjectDoesNotSuppressTheIdPClaim" "$B" \
  "	if len(requested) == 0 {
		requested = nil
	}" \
  "	if false && len(requested) == 0 {
		requested = nil
	}" || rc=1

run_mutation "M-J subject_token_type discarded" ./cmd/idp-bridge/ \
  "TestSubjectTokenType_IsRequiredAndAllowlisted" "$B" \
  "	if !allowedSubjectTokenTypes[p[\"subject_token_type\"]] {" \
  "	if false && !allowedSubjectTokenTypes[p[\"subject_token_type\"]] {" || rc=1

run_mutation "M-K expired subject token skips the clamp" ./cmd/idp-bridge/ \
  "TestSubjectToken_ExpiredInsideTheSkewWindowIsDenied" "$B" \
  "	if rem <= 0 {" \
  "	if false && rem <= 0 {" || rc=1

run_mutation "M-L ttl_hours multiplied before bounding" ./cmd/idp-bridge/ \
  "TestTTLHours_OverflowDoesNotProduceAnAllowShapedDeadToken" "$B" \
  "		if maxHours := int(maxCATTTL / time.Hour); h > maxHours {
			h = maxHours
		}" \
  "		if maxHours := int(maxCATTTL / time.Hour); false && h > maxHours {
			h = maxHours
		}" || rc=1

run_mutation "M-M credentials honoured from the query string" ./cmd/idp-bridge/ \
  "TestParams_QueryStringIsNotACredentialChannel" "$B" \
  "	for k := range r.PostForm {
		out[k] = r.PostForm.Get(k)
	}" \
  "	for k := range r.Form {
		out[k] = r.Form.Get(k)
	}" || rc=1

run_mutation "M-N degenerate holder key may be sealed (cattoken)" ./internal/cattoken/ \
  "TestHolderKey_DegenerateEncodingsAreRefused|TestIssue_RefusesADegenerateHolderKey" "$C" \
  "	if err := checkHolderKey(req.HolderPublicKey); err != nil {
		return err
	}" \
  "	if err := checkHolderKey(req.HolderPublicKey); false && err != nil {
		return err
	}" || rc=1

run_mutation "M-O degenerate holder key reaches the bridge" ./cmd/idp-bridge/ \
  "TestHolderKey_DegenerateEncodingsAreRefused" "$C" \
  "	if err := checkHolderKey(req.HolderPublicKey); err != nil {
		return err
	}" \
  "	if err := checkHolderKey(req.HolderPublicKey); false && err != nil {
		return err
	}" || rc=1

if [ "$rc" -eq 0 ]; then
  echo
  echo "all mutations killed"
else
  echo
  echo "at least one mutation survived or failed to apply — see above"
fi
exit "$rc"
