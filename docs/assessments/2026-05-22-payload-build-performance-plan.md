# Payload Build Performance Enterprise Plan

Date: 2026-05-22

## Root Cause

The payload image job is slow because it waits for the base image matrix, then
downloads the RPi4 and RevPi4 image artifacts and still runs a full installer
Buildroot build. The expensive part is not artifact transfer; it is rebuilding
the installer rootfs/toolchain/package graph before `post-image.sh` signs and
embeds the payload images.

## Architecture

1. Preserve security first. Payload images remain digest-bound, signed, and
   attested; performance work must not bypass the manifest/signature chain.
2. Stage downloaded payload inputs outside the source tree under CI storage so
   `SUDERRA_REQUIRE_CLEAN_EXTERNAL=1` can stay enabled for the payload job.
3. Emit `suderra.payload-inputs.v1` before packaging. The manifest records the
   source run, source commit, source Build artifact names, payload file names,
   byte counts, SHA-256 digests, and a canonical aggregate digest.
4. Emit `suderra.buildroot-build-performance.v1` for each Buildroot image
   build. The
   evidence preserves raw `build-time.log`, parsed package/step timing, and
   cache directory statistics so later optimization is driven by measured data.
5. Keep mutable Buildroot output cache out of the critical path until it has a
   verified invalidation model. Downloads and ccache remain the only CI caches.
6. Split the installer flow into `build-payload-base` and `build-payload`.
   The base job runs the installer Buildroot defconfig in
   `SUDERRA_USB_INSTALLER_BASE_ONLY=1` mode and publishes only `boot.vfat`,
   `rootfs.ext4`, and Buildroot evidence. The payload job consumes those base
   bytes, validates the downloaded target image contracts, signs the payload
   manifest, creates `payload.ext4`, and emits the final installer image
   without rerunning Buildroot.

## Acceptance

- The payload job must not download Build artifacts into the repository tree.
- Build and payload jobs must require a clean external tree.
- Payload input manifests and build performance evidence must be uploaded in
  build logs and included in GitHub Artifact Attestation subjects.
- The final payload job must invoke `package-usb-installer-payload.py`, not
  `build-in-docker.sh`, for the installer defconfig.
- Contract tests must reject tampered payload input manifests and malformed
  performance evidence.
