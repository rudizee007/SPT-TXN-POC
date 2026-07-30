# Releasing SPT-Txn

We sell attestation-conditioned authorization. An unattested build pipeline is
disqualifying — any acquirer's technical due diligence will look, and so will a
bank's security architecture review board. This document is how we hold that line.

## What a release produces

| Artifact | What it is |
|---|---|
| `<name>_<os>_<arch>` | Statically linked binary (`CGO_ENABLED=0`), path-trimmed, git revision stamped in |
| `SHA256SUMS` | Sorted checksums over relative paths — identical regardless of build host |
| `sbom.cyclonedx.json` | **Dependency** SBOM (CycloneDX) |
| SLSA build provenance | Keyless Sigstore attestation, per artifact |
| SBOM attestation | Binds the SBOM to the artifacts |

`docs/cbom.json` is a different artifact answering a different question — the
**cryptographic** bill of materials. Both ship; don't conflate them.

## Cutting a release

```sh
git tag v0.3.0
git push origin v0.3.0
```

The `release` workflow then, in order:

1. **Gate** — `vet`, `test`, conformance vectors, `govulncheck`, and the auth path
   under `fips140=on`. **Nothing is built until this passes.** A release that
   ships unverified binaries is worse than no release, because the attestation
   then vouches for something nobody checked.
2. **Build** — `scripts/release-build.sh` (the same script you run locally),
   then assert the linux binaries really are statically linked.
3. **SBOM + attest** — CycloneDX SBOM, SLSA provenance, SBOM attestation.
4. **Publish** — a **draft** release. A human reviews before it goes live.

Dry run without releasing: run the workflow via `workflow_dispatch` with a
version input.

## Building locally

```sh
./scripts/release-build.sh                    # all targets
TARGETS="linux/amd64" ./scripts/release-build.sh
VERSION=v0.3.0 ./scripts/release-build.sh
```

CI calls this same script deliberately. If CI and local ever diverge, the
provenance describes a build nobody can reproduce, which defeats its purpose.

## What ships

Eight of the 33 `cmd/` packages — the rest are demos, benchmarks and one-off
calldata helpers. The list lives **only** in `scripts/release-build.sh`
(`BINARIES`); the workflow reads it from there rather than keeping a second copy.

`spt-demo` · `receiptverify` · `auditverify` · `conformance` · `extauthz` ·
`opashim` · `x402gate` · `mksubject`

## How a consumer verifies us

This is the point of the exercise — the instructions are in the release notes:

```sh
gh attestation verify spt-demo_linux_amd64 --repo rudizee007/spt-txn-poc
sha256sum -c SHA256SUMS
go version -m spt-demo_linux_amd64 | grep vcs.revision
```

## Honest gaps

- **Actions are pinned to tags, not commit SHAs.** Tag refs are *mutable* — a tag
  can be repointed at different code, which is exactly the supply-chain attack
  this pipeline defends against. Go dependencies are pinned by `go.sum`; the
  Actions are not. This is the pipeline failing its own standard. Fix:
  ```sh
  go install github.com/suzuki-shunsuke/pinact/cmd/pinact@latest
  pinact run .github/workflows/*.yml
  ```
  Applies to `release.yml`, `ci.yml` and `gitleaks.yml`.
- **Reproducibility is aimed at, not verified.** `-trimpath`, `CGO_ENABLED=0` and
  a pinned toolchain get most of the way. **Do not claim reproducible builds
  publicly** until two independent machines produce identical `SHA256SUMS`.
- **No signed git tags yet.** CLAUDE.md commits to signed commits; releases should
  be cut from a signed, annotated tag (`git tag -s`).
- **FIPS scope is the auth path only.** The ZK packages use research-grade
  primitives (BN254 / Poseidon2 / Baby Jubjub) that are not FIPS-approved. Never
  let the FIPS claim broaden by implication.
- **Not externally audited. Not for production use.** Say this in every release.

## Downstream

`spt-txn-gateway` and `spt-txn-kong` are separate modules and need the same
treatment before they go public. They consume `pkg/verify` from a released
version — drop the local `replace` directive and pin a tag when releasing them.
