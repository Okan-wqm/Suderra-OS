# Tiered CI + Immutable USB Installer Base Decision

Date: 2026-05-22

## Root Cause

The payload image job is slow because it waits for the base image matrix, then
downloads the RPi4 and RevPi4 image artifacts and still runs a full installer
Buildroot build. The expensive part is not artifact transfer; it is rebuilding
the installer rootfs/toolchain/package graph before `post-image.sh` signs and
embeds the payload images.

## Decision

The original measurement-only plan is replaced by a two-tier CI and immutable
base artifact model:

1. `Build` is the fast required PR/`main` workflow. It validates matrix,
   governance, syntax, contract tests, and Buildroot defconfig parsing only.
   Full image jobs are not required branch checks.
2. `Image Build` is the heavy image producer for nightly/manual/main-push
   evidence and release preflight. It builds QEMU/RPi4/RevPi4 images, installer
   binaries, the USB installer base, the final payload image, QEMU smoke
   evidence, artifact attestations, and `suderra.image-build-contract.v1`.
3. USB installer base reuse is immutable and digest-bound through
   `suderra.usb-installer-base.v1`. The final payload job consumes a base only
   when identity digest, manifest digest, partition digests, Buildroot source
   identity, matrix digest, builder image, trust-root public key hash, and build
   evidence digest match exactly.
4. Silent fallback is forbidden. A base identity mismatch fails the payload job;
   the heavy workflow must produce a new base artifact.
5. Release preflight binds only `Image Build` artifacts and rejects old
   `.github/workflows/build.yml` producers.
6. Performance evidence is mandatory. Payload packaging over the budget in
   `ci/build-performance-budget.yml` fails; Buildroot timing remains reporting
   until enough successful baselines exist for regression gates.

## Acceptance

- The payload job must not download Build artifacts into the repository tree.
- Build and payload jobs must require a clean external tree.
- Payload input manifests and build performance evidence must be uploaded in
  build logs and included in GitHub Artifact Attestation subjects.
- The final payload job must invoke `package-usb-installer-payload.py`, not
  `build-in-docker.sh`, for the installer defconfig.
- Contract tests must reject tampered payload input manifests and malformed
  performance evidence.
- `Build` workflow must not contain full image, payload, or QEMU jobs.
- `Image Build` must publish digest-bound USB installer base artifacts and an
  image build contract.
- Branch protection/governance policy must require only fast checks.
- Release preflight must verify `.github/workflows/image-build.yml`
  attestations and consume `package-usb-installer-payload.py` output.
