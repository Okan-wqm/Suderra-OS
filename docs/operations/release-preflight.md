# Release Preflight

Release publication is tag-triggered, but release readiness is proven before a
tag workflow can publish. The `Release Preflight` workflow binds one exact
successful `Build` run to one exact source commit and emits the evidence bundle
that the tag workflow later consumes.

## Profiles

- `technical-dry-run`: validates source/run/artifact binding and creates input
  skeletons. It never claims release readiness.
- `release-candidate`: fail-closed alpha gate. It requires complete QEMU,
  hardware lab, security scan, reproducibility, approval, and governance input
  evidence bound to the same `source_sha`.

## Run

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-alpha.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-build-run-id> \
  -f profile=technical-dry-run
```

For a release candidate, rerun with `profile=release-candidate` after the input
trees are populated and validated:

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-alpha.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-build-run-id> \
  -f profile=release-candidate
```

`release-candidate` accepts only a successful `Build` run whose `head_branch` is
`main`; the workflow also verifies that `source_sha` is an ancestor of
`origin/main`. Technical dry runs may be used against other branches for binding
debugging, but they cannot feed the tag release workflow.

The workflow artifact name includes the profile so a later technical dry run
cannot shadow an approved release-candidate bundle:

```text
release-preflight-<profile>-<version>-<source_sha>
```

The release tag workflow does not scan recent workflow runs. The annotated
release tag must name the approved preflight run explicitly:

```text
Suderra-Preflight-Run-ID: <successful-release-preflight-run-id>
```

The workflow downloads only
`release-preflight-release-candidate-<version>-<source_sha>` from that run. If
the annotation is missing, the run is not successful, the run is not from
`main`, or the artifact is expired, publication stops before staging or signing
release bytes. The tag workflow does not rebuild images or installer binaries;
it promotes the Build artifact bytes carried by the approved preflight artifact.

`release-candidate` preflight also validates live GitHub governance. The token
must be able to read branch protection, repository rulesets, environments,
workflow permissions, and the audit snapshot. If the repository cannot provide a
collected audit log, governance validation fails closed.

## Required Inputs

The candidate bundle must include:

- `release-inputs/<version>/release-candidate.json`
- `release-ingress/<version>/ingress-manifest.json` plus `.sig` and `.cert`
- `build-artifacts/<defconfig>-image/*`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.log`
- `build-artifacts/<defconfig>-build-logs/build-logs/<defconfig>.warnings.json`
- `build-artifacts/installer-x86_64/suderra-installer-x86_64`
- `build-artifacts/installer-aarch64/suderra-installer-aarch64`
- `release-lab-input/<version>/qemu-x86_64/qemu.json`
- `release-lab-input/<version>/<hardware-target>/lab.json`
- `release-governance/<version>/governance-policy-validation.json`
- `release-approvals/<version>/<target>.json` using
  `suderra.release-approval.v2`
- `release-security/<version>/<scan>.json`
- `release-reproducibility/<version>/<target>.log`

All evidence must reference the same source commit, Build run ID, Buildroot
submodule SHA, Buildroot patchset digest, effective Buildroot source ID, matrix
hash, Rust toolchain/Cargo.lock digests, and artifact digests. The binding
manifest must cover the exact `ci/build-matrix.yml` release artifact set,
installer binaries, build logs, and warning classifier JSON; extra, missing,
all-zero, absolute-path, or placeholder artifact entries fail closed.

Approval files must include at least two distinct roles for enterprise alpha:
`release-owner` and either `maintainer` or `security-compliance`. The same
approval schema is consumed by preflight and by final release evidence assembly.

## Release Byte Binding

Release-candidate preflight downloads only the expected image, installer, and
build-log artifacts from one successful `Build` run and records them in signed
`suderra.release-ingress.v1`. The tag workflow downloads the approved preflight
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
Build run stops the release. The ingress manifest also records the version,
profile, source SHA, Build run ID and attempt, matrix digest, Buildroot
submodule SHA, ordered Buildroot patch file digests, effective Buildroot source
ID, producer identity, expiry, schema roles, file paths, sizes, and digests.
Absolute paths, path traversal, placeholders, all-zero digests, wrong source
SHA, wrong signer identity, or tampered artifact bytes fail closed.

## Acceptance Binding

Release QEMU input is validated against both `source_sha` and the bound raw
QEMU image digest (`disk.img`). Hardware lab input is validated against
`source_sha` and the bound Build run ID. Security reports must include the same
version, source commit, source Build run, tool metadata, and a non-zero digest
for the retained scan evidence.
