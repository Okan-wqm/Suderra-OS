# Release Preflight

Release publication is tag-triggered, but release readiness is proven before a
tag workflow can publish. The `Release Preflight` workflow binds one exact
successful `Image Build` run to one exact source commit and emits the evidence
bundle that the tag workflow later consumes.

For the first RC use `VERSION=v0.1.0-rc.1`. The workflow term `alpha` means the
pre-release evidence policy tier and applies to RC tags. Freeze `main` before
operator evidence collection begins, or the current workflow will reject ingress
and preflight when `origin/main` no longer equals `source_sha`.

## Profiles

- `technical-dry-run`: validates source/run/artifact binding and creates input
  skeletons. It never claims release readiness.
- `rc-evidence-dry-run`: prerelease-only, non-promotable evidence rehearsal. It
  emits SSOT plans, artifact digests, subject graph refs, retention plan, and
  production gap blockers under `release-dry-run/`. The dry-run
  `bundle-manifest.json` digest-binds every member plus subject graph and
  governance refs; tag publication rejects this profile.
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

For the SSOT evidence rehearsal, run the non-promotable RC dry-run profile:

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-image-build-run-id> \
  -f profile=rc-evidence-dry-run
```

The dry-run artifact is retained for operator review only. It cannot satisfy the
signed tag binding expected by the release workflow.

For a release candidate, do not populate ignored evidence directories in the
source checkout. Package the operator evidence trees as a tar bundle, publish
that bundle to a controlled HTTPS location, and ingress it first:

```bash
tar -czf operator-evidence-v0.1.0-rc.1.tar.gz \
  release-lab-input/v0.1.0-rc.1 \
  release-approvals/v0.1.0-rc.1 \
  release-reproducibility/v0.1.0-rc.1 \
  release-runtime/v0.1.0-rc.1 \
  release-signing/v0.1.0-rc.1 \
  release-governance/v0.1.0-rc.1/audit-log.json \
  release-governance/v0.1.0-rc.1/station-registry.json

# The bundle must be signed by the governed operator evidence identity
# configured in SUDERRA_OPERATOR_BUNDLE_CERTIFICATE_IDENTITY. Local ad-hoc
# identities are not accepted by Release Evidence Ingress.

OPERATOR_BUNDLE_SHA256="$(sha256sum operator-evidence-v0.1.0-rc.1.tar.gz | awk '{print $1}')"

gh workflow run "Release Evidence Ingress" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_image_build_run_id=<successful-image-build-run-id> \
  -f source_image_build_run_attempt=<image-build-run-attempt> \
  -f operator_bundle_url=<https-url> \
  -f operator_bundle_sha256="${OPERATOR_BUNDLE_SHA256}" \
  -f operator_bundle_signature_url=<https-signature-url> \
  -f operator_bundle_certificate_url=<https-certificate-url>
```

The ingress workflow safely extracts only `release-lab-input`,
`release-approvals`, `release-reproducibility`, `release-runtime`,
`release-signing`, and `release-governance`,
requires the audit log and station registry, verifies the operator bundle
signature before signing any GitHub-produced ingress evidence, writes and signs
`release-ingress/<version>/evidence-ingress-manifest.json`, and uploads this
immutable artifact:

```text
rei-<version>-<source_sha>-<image-build-run-id>-<image-build-run-attempt>
```

The operator bundle URL must be readable by the GitHub-hosted runner without
custom headers, must use HTTPS, must not redirect, and must match
`SUDERRA_OPERATOR_BUNDLE_ALLOWED_HOST`. Signer identity is fixed by
`SUDERRA_OPERATOR_BUNDLE_CERTIFICATE_IDENTITY`; the dispatcher cannot choose the
accepted host or signer. Record URL, expiry, bundle digest, signature digest,
certificate digest, signer identity, and upload owner in the audit record. Do
not commit operator evidence bundles to the repository.

Capture the evidence ingress manifest digest as a bare lowercase SHA-256:

```bash
gh run download <evidence-ingress-run-id> \
  --repo Okan-wqm/Suderra-OS \
  --name rei-v0.1.0-rc.1-<source_sha>-<image-build-run-id>-<attempt> \
  --dir /tmp/evidence-ingress

EVIDENCE_INGRESS_MANIFEST_SHA256="$(
  sha256sum /tmp/evidence-ingress/release-ingress/v0.1.0-rc.1/evidence-ingress-manifest.json |
    awk '{print $1}'
)"
```

Then run `profile=release-candidate`:

```bash
gh workflow run "Release Preflight" \
  -f version=v0.1.0-rc.1 \
  -f source_sha=<exact-main-commit> \
  -f source_run_id=<successful-image-build-run-id> \
  -f evidence_ingress_run_id=<successful-evidence-ingress-run-id> \
  -f evidence_ingress_manifest_sha256="${EVIDENCE_INGRESS_MANIFEST_SHA256}" \
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
VERSION=v0.1.0-rc.1
SOURCE_SHA=<exact-main-commit>
PREFLIGHT_RUN_ID=<successful-release-preflight-run-id>
PREFLIGHT_ARTIFACT_NAME="release-preflight-release-candidate-${VERSION}-${SOURCE_SHA}"

gh api "repos/Okan-wqm/Suderra-OS/actions/runs/${PREFLIGHT_RUN_ID}" \
  > /tmp/preflight-run.json
gh api "repos/Okan-wqm/Suderra-OS/actions/runs/${PREFLIGHT_RUN_ID}/artifacts" \
  > /tmp/preflight-artifacts.json

PREFLIGHT_RUN_ATTEMPT="$(jq -r '.run_attempt' /tmp/preflight-run.json)"
PREFLIGHT_ARTIFACT_ID="$(
  jq -er --arg name "${PREFLIGHT_ARTIFACT_NAME}" \
    '.artifacts | map(select(.name == $name and .expired == false)) |
      if length == 1 then .[0].id else error("expected one matching preflight artifact") end' \
    /tmp/preflight-artifacts.json
)"

gh run download "${PREFLIGHT_RUN_ID}" \
  --repo Okan-wqm/Suderra-OS \
  --name "${PREFLIGHT_ARTIFACT_NAME}" \
  --dir /tmp/release-preflight

INGRESS_MANIFEST_SHA256="$(
  sha256sum "/tmp/release-preflight/release-ingress/${VERSION}/ingress-manifest.json" |
    awk '{print $1}'
)"
```

Record the preflight run ID, preflight run attempt from `/tmp/preflight-run.json`,
the artifact ID from `/tmp/preflight-artifacts.json`, and the ingress manifest
SHA-256 in the signed annotated tag.

`evidence_ingress_manifest_sha256` is only the SHA-256 of
`release-ingress/<version>/evidence-ingress-manifest.json` used when dispatching
`Release Preflight`. `Suderra-Ingress-Manifest-SHA256` in the signed tag is the
SHA-256 of `release-ingress/<version>/ingress-manifest.json` downloaded from the
successful preflight artifact. Never put the evidence-ingress manifest digest in
the tag annotation.

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
Suderra-Preflight-Profile: <release-candidate-or-production-candidate>
Suderra-Ingress-Manifest-SHA256: <ingress-manifest-sha256>
```

`Suderra-Preflight-Profile` is mandatory for the live release gate. Pre-release
tags must bind to `release-candidate`; GA tags must bind to
`production-candidate`. Tags or archived notes that predate this field are
legacy archive material only: they may be inspected during offline/archive
verification, but they do not authorize a current release workflow, draft
publication, signing, or promotion.

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

- `release-inputs/<version>/<profile>.json`
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
- `release-runtime/<version>/<runtime-target>/production-runtime.json` when
  `ci/evidence-contract.yml` marks the target as runtime-required
- `release-signing/<version>/**/*.json` when the target policy requires
  production signing or OTA-capable artifacts
- `release-ota/<version>/<ota-target>/ota-artifacts.json` when the target policy
  marks the target as OTA-capable
- `release-subject-graph/<version>/release-subject-graph.json`
- `release-governance/<version>/audit-log.json`
- `release-governance/<version>/station-registry.json`
- `release-governance/<version>/governance-policy-validation.json`
- `release-approvals/<version>/<target>.json` using
  `suderra.release-approval.v2`
- `release-security/<version>/<scan>.json` plus retained raw scanner bytes. For
  production-candidate, reports must be scanner-native v2 with scanner binary,
  invocation, database archive, scanned subject, SBOM/VEX linkage, and replay
  output. GitHub check-run summaries are governance signals, not production
  scanner evidence.
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
approval, reproducibility, audit, station-registry, scanner-native,
subject-graph, signing, OTA, hardware-subject, and retention inputs. It records
the resulting input tree in signed `suderra.release-ingress.v1`. Source checkout
copies of ignored evidence directories are not trusted. The tag workflow
downloads the approved preflight artifact, verifies the ingress cosign identity,
stages release-named files from `build-artifacts/`, signs, attests, and
publishes those bytes. Before signing,
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

## Retention / Evidence Export

GitHub Actions artifacts in this path retain for 30 days, while enterprise
governance requires durable evidence retention. Before cleanup or draft
deletion, export the original operator bundle and sidecars, bundle URL/expiry
record, evidence ingress run JSON, ingress artifact, preflight run JSON,
preflight artifact, tag annotation, release workflow run JSON, final release
evidence archive, publication manifest, and post-publication proof assets to
durable release evidence storage. Aborted RC attempts must also be retained.
