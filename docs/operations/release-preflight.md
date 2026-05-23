# Release Preflight

Release publication is tag-triggered, but release readiness is proven before a
tag workflow can publish. The `Release Preflight` workflow binds one exact
successful `Image Build` run to one exact source commit and emits the evidence
bundle that the tag workflow later consumes.

## Profiles

- `technical-dry-run`: validates source/run/artifact binding and creates input
  skeletons. It never claims release readiness.
- `release-candidate`: fail-closed alpha gate. It requires complete QEMU,
  hardware lab, security scan, reproducibility, approval, and governance input
  evidence bound to the same `source_sha`.
- `production-candidate`: GA gate shape. It is reserved for future production
  release evidence and remains blocked until production readiness passes.

## Run

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-image-build-run-id> \
  -f profile=technical-dry-run
```

For a release candidate, do not populate ignored evidence directories in the
source checkout. Package the operator evidence trees as a tar bundle, publish
that bundle to a controlled HTTPS location, and ingress it first:

```bash
tar -czf operator-evidence-v0.1.0-rc.1.tar.gz \
  release-lab-input/v0.1.0-rc.1 \
  release-approvals/v0.1.0-rc.1 \
  release-reproducibility/v0.1.0-rc.1 \
  release-governance/v0.1.0-rc.1/audit-log.json \
  release-governance/v0.1.0-rc.1/station-registry.json

sha256sum operator-evidence-v0.1.0-rc.1.tar.gz

gh workflow run "Release Evidence Ingress" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_image_build_run_id=<successful-image-build-run-id> \
  -f source_image_build_run_attempt=<image-build-run-attempt> \
  -f operator_bundle_url=<https-url> \
  -f operator_bundle_sha256=<operator-bundle-sha256>
```

The ingress workflow safely extracts only `release-lab-input`,
`release-approvals`, `release-reproducibility`, and `release-governance`,
requires the audit log and station registry, writes and signs
`release-ingress/<version>/evidence-ingress-manifest.json`, and uploads this
immutable artifact:

```text
release-evidence-ingress-<version>-<source_sha>-<image-build-run-id>-<image-build-run-attempt>
```

Capture the evidence ingress manifest digest:

```bash
gh run download <evidence-ingress-run-id> \
  --repo Okan-wqm/Suderra-OS \
  --name release-evidence-ingress-v0.1.0-rc.1-<source_sha>-<image-build-run-id>-<attempt> \
  --dir /tmp/evidence-ingress

sha256sum /tmp/evidence-ingress/release-ingress/v0.1.0-rc.1/evidence-ingress-manifest.json
```

Then run `profile=release-candidate`:

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-image-build-run-id> \
  -f evidence_ingress_run_id=<successful-evidence-ingress-run-id> \
  -f evidence_ingress_manifest_sha256=<evidence-ingress-manifest-sha256> \
  -f profile=release-candidate
```

`release-candidate` accepts only a successful `Image Build` run from
`.github/workflows/image-build.yml` whose `head_branch` is `main`; the workflow
also verifies that `source_sha` is exactly `origin/main` at preflight time.
Technical dry runs may be used against other branches for binding debugging,
but they cannot feed the tag release workflow.

Missing evidence ingress run ID, missing artifact, wrong artifact name, wrong
source SHA, wrong Image Build run/attempt, malformed evidence ingress manifest,
bad evidence ingress signature, missing audit log, missing station registry, or
incorrect manifest digest all fail closed before release input validation.

The workflow artifact name includes the profile so a later technical dry run
cannot shadow an approved release-candidate bundle:

```text
release-preflight-<profile>-<version>-<source_sha>
```

After a successful release-candidate preflight, capture the tag-binding metadata
from the exact run:

```bash
gh api repos/Okan-wqm/Suderra-OS/actions/runs/<preflight-run-id> > /tmp/preflight-run.json
gh api repos/Okan-wqm/Suderra-OS/actions/runs/<preflight-run-id>/artifacts > /tmp/preflight-artifacts.json
gh run download <preflight-run-id> \
  --repo Okan-wqm/Suderra-OS \
  --name release-preflight-release-candidate-v0.1.0-rc.1-<source_sha> \
  --dir /tmp/release-preflight

sha256sum /tmp/release-preflight/release-ingress/v0.1.0-rc.1/ingress-manifest.json
```

Record the preflight run ID, preflight run attempt from `/tmp/preflight-run.json`,
the artifact ID from `/tmp/preflight-artifacts.json`, and the ingress manifest
SHA-256 in the signed annotated tag.

The release tag workflow does not scan recent workflow runs. The annotated
release tag must name the approved preflight run, run attempt, artifact ID, and
ingress manifest digest explicitly:

```text
Suderra-Release-Binding: v1
Suderra-Version: <version>
Suderra-Source-SHA: <source-sha>
Suderra-Source-Build-Run-ID: <build-run-id>
Suderra-Source-Build-Run-Attempt: <build-run-attempt>
Suderra-Preflight-Run-ID: <successful-release-preflight-run-id>
Suderra-Preflight-Run-Attempt: <preflight-run-attempt>
Suderra-Preflight-Artifact-ID: <preflight-artifact-id>
Suderra-Ingress-Manifest-SHA256: <ingress-manifest-sha256>
```

The workflow downloads only the tag-derived preflight artifact name from that
run: `release-preflight-release-candidate-<version>-<source_sha>` for
pre-release tags or `release-preflight-production-candidate-<version>-<source_sha>`
for GA tags. If the annotation is missing, the tag object is unsigned, the run
is not successful, the run is not from the correct workflow path on `main`, the
artifact ID does not match, the artifact is expired, or the downloaded ingress
manifest hash differs from the tag binding, publication stops before staging or
signing release bytes. The tag workflow does not rebuild images or installer
binaries; it promotes the Image Build artifact bytes carried by the approved
preflight artifact.

Release tags must be signed by a trusted release key. The release workflow
imports `SUDERRA_RELEASE_TAG_SIGNING_PUBLIC_KEY` from secrets, runs
`git verify-tag --raw`, and requires the VALIDSIG fingerprint to appear in
`SUDERRA_RELEASE_TAG_SIGNING_FINGERPRINTS`. Unsigned tags, lightweight tags,
untrusted signers, wrong Image Build run IDs, wrong run attempts, or mismatched
tag/preflight/ingress metadata fail before any release bytes are staged.

`release-candidate` preflight also validates live GitHub governance.
`GOVERNANCE_READ_TOKEN` must be a GitHub App installation token or equivalent
read token that can read branch protection, repository rulesets, environments,
environment deployment branch policies, workflow permissions, and the audit
snapshot. If the repository cannot provide a collected audit log, governance
validation fails closed.

## Required Inputs

The candidate bundle must include and the signed ingress manifest must digest:

- `release-inputs/<version>/release-candidate.json`
- `release-ingress/<version>/ingress-manifest.json` plus `.sig` and `.cert`
- `release-ingress/<version>/evidence-ingress-manifest.json` plus `.sig` and
  `.cert`
- `build-artifacts/<defconfig>-image/*`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.log`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.warnings.json`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.source-identity.json`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.build-time.log`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.build-performance.json`
- `build-artifacts/<payload-defconfig>-build-logs/build-logs/<payload-defconfig>.payload-inputs.json`
- `build-artifacts/<payload-defconfig>-build-logs/build-logs/<payload-defconfig>.payload-package.json`
- `build-artifacts/<payload-defconfig>-build-logs/build-logs/<payload-defconfig>.usb-installer-base.json`
- `build-artifacts/installer-x86_64/suderra-installer-x86_64`
- `build-artifacts/installer-aarch64/suderra-installer-aarch64`
- `build-artifacts/image-build-contract/image-build-contract.json`
- `release-lab-input/<version>/qemu-x86_64/qemu.json`
- `release-lab-input/<version>/<hardware-target>/lab.json`
- `release-governance/<version>/audit-log.json`
- `release-governance/<version>/station-registry.json`
- `release-governance/<version>/governance-policy-validation.json`
- `release-approvals/<version>/<target>.json` using
  `suderra.release-approval.v2`
- `release-security/<version>/<scan>.json` plus the raw
  `release-security/<version>/github-check-runs.json` byte stream referenced by
  each report
- `release-reproducibility/<version>/<target>.json`

All evidence must reference the same source commit, Image Build run ID, Buildroot
submodule SHA, Buildroot upstream ref, Buildroot source mode, Buildroot patchset
digest, effective Buildroot source ID, matrix hash, Rust toolchain/Cargo.lock
digests, and artifact digests. The binding
manifest must cover the exact `ci/build-matrix.yml` release artifact set,
installer binaries, build logs, warning classifier JSON, Buildroot source
identity JSON, build timing/performance evidence, the USB installer base
manifest, payload package evidence, payload input manifest, and the Image Build
contract; extra, missing, all-zero, absolute-path, or placeholder artifact
entries fail closed.

Current alpha builds use `clean-native` Buildroot source identity:
Buildroot `2025.05.3`, native Rust `1.86.0`, no Suderra Buildroot patch files,
and no applied/worktree diff digest. If a future patched Buildroot build is
introduced, `buildroot_applied_diff_sha256` becomes mandatory and part of
`buildroot_effective_source_id`. Release builds must come from a clean isolated
Buildroot source tree; unrelated local dirty submodule state is never accepted
as release source identity.

Approval files must include at least two distinct roles for enterprise alpha:
`release-owner` and either `maintainer` or `security-compliance`. The same
approval schema is consumed by preflight and by final release evidence assembly.

## Release Byte Binding

Release-candidate preflight downloads only the expected image, installer,
build-log, performance, USB installer base, payload, and Image Build contract
artifacts from one successful `Image Build` run, verifies their GitHub Artifact
Attestations against `.github/workflows/image-build.yml` on `refs/heads/main`,
downloads the immutable `Release Evidence Ingress` artifact for operator lab,
approval, reproducibility, audit, and station-registry inputs, collects
exact-commit GitHub check-run security evidence into
`release-security/<version>/*.json`, and records the resulting input tree in
signed `suderra.release-ingress.v1`. Source checkout copies of ignored evidence
directories are not trusted. The tag workflow downloads the approved preflight
artifact, verifies the ingress cosign identity, stages release-named files from
`build-artifacts/`, signs, attests, and publishes those bytes. Before signing,
`validate-release-artifact-binding.py` maps staged release files back to their
preflight-bound source artifacts and compares SHA-256 digests:

- `<matrix artifact>.xz` -> `<release_artifact>`
- `MANIFEST.txt` -> `<release base>.manifest.txt`
- `manifest.json` -> `<release base>.payload-manifest.json`
- `manifest.sig` -> `<release base>.payload-manifest.sig`
- `suderra-installer-<arch>` -> `suderra-installer-<version>-<arch>`

Any staged image, manifest, or payload signature that does not match the bound
Image Build run stops the release. The ingress manifest also records the
version, profile, source SHA, Image Build run ID and attempt, matrix digest, Buildroot
submodule SHA, ordered Buildroot patch file digests, effective Buildroot source
ID, producer identity, expiry, schema roles, file paths, sizes, and digests.
Absolute paths, path traversal, placeholders, all-zero digests, wrong source
SHA, wrong signer identity, or tampered artifact bytes fail closed.

## Acceptance Binding

Release QEMU input is validated against both `source_sha` and the bound raw
QEMU image digest (`disk.img`). Hardware lab input is validated against
`source_sha` and the bound Image Build run ID. Security reports must include the same
version, source commit, source Image Build run, tool metadata, and a non-zero digest
for the retained scan evidence.
