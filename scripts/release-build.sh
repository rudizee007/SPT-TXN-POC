#!/usr/bin/env bash
# Reproducible static release build for SPT-Txn.
#
# ONE source of truth for how release binaries are produced: CI calls this
# script, and so do you locally. If the two ever diverge, an attestation
# describes a build nobody can reproduce — which defeats the point of having one.
#
#   ./scripts/release-build.sh              # version from git describe
#   VERSION=v0.3.0 ./scripts/release-build.sh
#   TARGETS="linux/amd64" ./scripts/release-build.sh   # narrow, for a quick check
#
# Output: dist/<name>_<os>_<arch>[.exe], dist/SHA256SUMS
#
# Build flags, and why:
#   CGO_ENABLED=0   fully static — no libc dependency, runs in scratch/distroless
#                   containers and on air-gapped hosts. Also keeps C out of the
#                   trust boundary, which is a hard project rule.
#   -trimpath       strips local filesystem paths from the binary. Required for
#                   reproducibility and it stops build hosts leaking paths.
#   -buildvcs=true  stamps the git revision INTO the binary (`go version -m`),
#                   so a shipped artifact can be traced to a commit without
#                   trusting the filename.
#   -ldflags "-s -w" strips debug info: smaller, and less to fingerprint.
#
# Reproducibility is *aimed at*, not yet *verified*. Bit-for-bit equality across
# machines needs a pinned toolchain (see .go-version / CI) and identical module
# cache contents. Do not claim reproducible builds publicly until two independent
# machines produce identical SHA256SUMS. See docs/RELEASE.md.
set -euo pipefail

cd "$(dirname "$0")/.."

# --- the shipped set --------------------------------------------------------
# There are 33 main packages in cmd/; most are demos, benchmarks or one-off
# calldata helpers. Ship only what an operator or an evaluating developer needs.
# Edit HERE — CI reads this list, it is not duplicated in the workflow.
BINARIES=(
  spt-demo        # end-to-end demo: issues, verifies, emits a receipt, shows tamper -> fail-closed
  receiptverify   # verify a receipt offline
  auditverify     # verify the transparency-log chain
  conformance     # check canonicalization/verifier vectors for drift
  extauthz        # Envoy ext_authz enforcement point
  opashim         # OPA-compatible decision shim
  x402gate        # x402 payment gate
  mksubject       # subject/keypair helper
)

TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="${OUT:-dist}"

# SOURCE_DATE_EPOCH: honour it if the caller set it (CI does, from the tag/commit
# date) so timestamps embedded by tooling are stable.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 0)}"

echo "SPT-Txn release build"
echo "  version : ${VERSION}"
echo "  go      : $(go version)"
echo "  epoch   : ${SOURCE_DATE_EPOCH}"
echo "  targets : ${TARGETS}"
echo "  binaries: ${BINARIES[*]}"
echo

rm -rf "${OUT}"
mkdir -p "${OUT}"

for target in ${TARGETS}; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  for name in "${BINARIES[@]}"; do
    if [ ! -d "cmd/${name}" ]; then
      echo "  !! cmd/${name} does not exist — fix BINARIES in this script" >&2
      exit 1
    fi
    ext=""
    [ "${goos}" = "windows" ] && ext=".exe"
    out="${OUT}/${name}_${goos}_${goarch}${ext}"
    echo "  building ${out}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build \
        -trimpath \
        -buildvcs=true \
        -ldflags "-s -w" \
        -o "${out}" \
        "./cmd/${name}"
  done
done

# --- checksums --------------------------------------------------------------
# Sorted, relative paths only: the file must be identical regardless of where
# the build ran.
echo
echo "writing ${OUT}/SHA256SUMS"
( cd "${OUT}" && \
  if command -v sha256sum >/dev/null 2>&1; then
    find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum
  else
    # macOS
    find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256
  fi
) > "${OUT}/SHA256SUMS"

echo
cat "${OUT}/SHA256SUMS"
echo
echo "done: $(find "${OUT}" -type f ! -name SHA256SUMS | wc -l | tr -d ' ') binaries in ${OUT}/"
