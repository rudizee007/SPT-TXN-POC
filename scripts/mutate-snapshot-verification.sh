#!/usr/bin/env bash
# Mutation check for trust-snapshot verification — the root of trust.
#
# Every offline verification in this system rests on the snapshot being the one
# the publisher signed. A verification suite that still passes with the
# verification removed is not a suite, so each guard in the normative flow
# (docs/spec/TRUST-REGISTRY-SNAPSHOT.md §4) is deleted in turn and must turn a
# NAMED test red.
#
#   S1  the signature is never checked                (Verify)
#   S2  the body digest is never compared             (Verify)
#   S3  an empty pin set is tolerated                 (Verify)
#   S4  staleness never fires                         (Verify)
#   S5  an unregistered suite is accepted             (Verify)
#   S6  a suite this build cannot verify is trusted   (Verify)
#   S7  the signature length is not checked           (Verify)
#   S8  key material leaves the body digest           (canonicalBody)
#   S9  the version field leaves the body digest      (canonicalBody)
#   S10 records are no longer validated at load       (trustregistry.load)
#
# A mutation that does not compile, or whose anchor is not found, is a bug in
# THIS script — never a pass.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FILES=(pkg/trustsnapshot/verify.go internal/trustregistry/persist.go)
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

run_mutation "S1 signature never checked" \
  ./pkg/verify/ "TestFromSignedSnapshot_RefusesAnUnpinnedOrEmptyKeySet" \
  pkg/trustsnapshot/verify.go \
  "	if !verified {
		return nil, ErrBadSignature
	}" \
  "	if false && !verified {
		return nil, ErrBadSignature
	}" || rc=1

run_mutation "S2 body digest never compared" \
  ./pkg/verify/ "TestFromSignedSnapshot_RefusesABodyThatIsNotTheSignedBody" \
  pkg/trustsnapshot/verify.go \
  "	if digest != m.DigestHex {" \
  "	if false && digest != m.DigestHex {" || rc=1

run_mutation "S3 empty pin set tolerated" \
  ./pkg/verify/ "TestFromSignedSnapshot_RefusesAnUnpinnedOrEmptyKeySet" \
  pkg/trustsnapshot/verify.go \
  "	if len(opts.PinnedKeys) == 0 {
		return nil, ErrNoPinnedKeys
	}" \
  "	if false && len(opts.PinnedKeys) == 0 {
		return nil, ErrNoPinnedKeys
	}" || rc=1

run_mutation "S4 staleness never fires" \
  ./pkg/verify/ "TestFromSignedSnapshot_Staleness" \
  pkg/trustsnapshot/verify.go \
  "	if !opts.AllowStale && age > opts.MaxAge {" \
  "	if false && !opts.AllowStale && age > opts.MaxAge {" || rc=1

run_mutation "S5 unregistered suite accepted" \
  ./pkg/verify/ "TestFromSignedSnapshot_DistinguishesUnregisteredFromUnsupportedSuites" \
  pkg/trustsnapshot/verify.go \
  "	if !RegisteredAlgs[m.Alg] {" \
  "	if false && !RegisteredAlgs[m.Alg] {" || rc=1

run_mutation "S6 unimplemented suite trusted" \
  ./pkg/verify/ "TestFromSignedSnapshot_RefusesASuiteItCannotVerify" \
  pkg/trustsnapshot/verify.go \
  "	if m.Alg != AlgEdDSA {
		return nil, fmt.Errorf(\"%w: %q\", ErrAlgUnsupported, m.Alg)
	}" \
  "	if false && m.Alg != AlgEdDSA {
		return nil, fmt.Errorf(\"%w: %q\", ErrAlgUnsupported, m.Alg)
	}" || rc=1

run_mutation "S7 signature length unchecked" \
  ./pkg/verify/ "TestFromSignedSnapshot_AMisshapenSignatureIsMalformedNotUnverified" \
  pkg/trustsnapshot/verify.go \
  "	if len(sig) != ed25519.SignatureSize {" \
  "	if false && len(sig) != ed25519.SignatureSize {" || rc=1

run_mutation "S8 key material leaves the digest" \
  ./pkg/trustsnapshot/ "TestBodyDigest_CoversPublicKeyBytes|TestBodyDigestKAT" \
  pkg/trustsnapshot/verify.go \
  "			\"public_key\":     hex.EncodeToString(r.PublicKey)," \
  "			\"public_key\":     \"\"," || rc=1

run_mutation "S9 version leaves the digest" \
  ./pkg/trustsnapshot/ "TestBodyDigest_CoversTheVersionField|TestBodyDigestKAT" \
  pkg/trustsnapshot/verify.go \
  "		\"version\": int64(b.Version)," \
  "		\"version\": int64(0)," || rc=1

run_mutation "S10 records unvalidated at load" \
  ./pkg/verify/ "TestFromSignedSnapshot_RefusesAnInvalidRecordEvenWhenCorrectlySigned" \
  internal/trustregistry/persist.go \
  "		if err := validateRecord(rec); err != nil {
			return fmt.Errorf(\"trustregistry: %s record %d (iss %q, role %q): %w\"," \
  "		if err := validateRecord(rec); false && err != nil {
			return fmt.Errorf(\"trustregistry: %s record %d (iss %q, role %q): %w\"," || rc=1

restore
if [ "$rc" -eq 0 ]; then
  echo "OK — every guard in the snapshot verification flow is load-bearing."
else
  echo "PROBLEM — a guard can be removed with the suite still green. Fix the test, not this script."
fi
exit "$rc"
