# Suderra OS Enterprise Grade Gap Closure Plan

Date: 2026-05-20
Status: Source of truth for the enterprise-grade implementation backlog

## Purpose

This document preserves the original enterprise-grade plan and the current
implementation status. Future implementation work must use this file as the
primary checklist instead of reconstructing the plan from chat history.

`production_ready=false` stays closed until every production gate below is
implemented and verified. Alpha/lab releases may continue only when evidence
clearly marks them as non-production.

## Original Plan

### Summary

- Suderra OS is not production-grade yet. The largest gaps are placeholder
  runtime services, non-real OTA/RAUC behavior, incomplete secure boot and
  dm-verity, fail-open provisioning, incomplete release evidence, and non-
  hermetic build supply chain controls.
- The first production target is **x86_64-first**.
- RPi4, CM4, and RevPi4 remain lab or release-candidate targets until signed
  FIT or equivalent Raspberry Pi secure boot, dm-verity, RAUC A/B,
  anti-rollback, and hardware-bound negative tests exist.
- factory/provisioning images are separate from locked production runtime
  images.

### P0: Fail-Closed Runtime Contract

- Production images must not boot with Dropbear, getty, debug shell, static
  root password, or local SSH provisioning enabled.
- The firstboot service must have one owner. The packaged unit must execute the
  installed `/usr/bin/suderra-firstboot` binary; overlay shell behavior is not a
  production substitute.
- Runtime state errors must fail closed. Corrupt installed-state JSON must block
  install, upgrade, remove, and rollback instead of being treated as an empty
  device.
- The installer must not report success by copying a bundle into `/opt/suderra`.
  Until RAUC is wired, any legacy copy path must be explicit lab-only behavior
  behind `SUDERRA_ALLOW_LEGACY_COPY_INSTALL=1`.
- systemd units for `/data`, firstboot, firewall, and agent startup must avoid
  ordering cycles and must pass `systemd-analyze verify --root`.

### P1: x86_64 Production Chain

- x86_64 production must use signed UKI or an equivalent locked boot chain. A
  GRUB plus mutable kernel/cmdline path is not a production claim.
- dm-verity must be generated from the exact root filesystem artifact and its
  roothash must be bound into signed boot metadata.
- RAUC must own A/B update semantics: slot configuration, signed bundles,
  bootchooser, mark-good, bootcount fallback, and rollback health evidence.
- `production_ready` cannot pass while RAUC is absent, rootfs verity artifacts
  are missing, or signed boot artifacts are only checked rather than produced.

### P2: Provisioning and Edge Transaction Security

- The root installer must not source files from an agent-writable directory.
  Runtime work must happen under root-owned state such as
  `/run/suderra-installer` or `/var/lib/suderra-installer`.
- Edge install must require a signed typed manifest with device identity,
  tenant binding, artifact digest, config payload digest, key epoch, rollback
  floor, and monotonic version rules.
- Activation must be transactional: stage, verify, write config, health check,
  promote, lockdown. Failures must roll back the current link.
- Downloads must be HTTPS-only with redirect protocol restrictions, max size,
  timeout, and audit evidence.
- The production-exposed `suderra-installer install edge` path must either use
  the same transaction engine or be disabled until RAUC-backed install exists.

### P3: Source, Buildroot, and Supply Chain

- Release builds must bind the full source consumed by Buildroot: Buildroot
  submodule identity plus the Suderra `BR2_EXTERNAL` tree, configs, board
  files, packages, userspace, and release scripts.
- CI/release builds must snapshot `BR2_EXTERNAL` from the clean Git tree instead
  of consuming a mutable live workspace. Dirty release-relevant files must fail
  the CI source contract.
- Local Rust packages must move toward Buildroot cargo source isolation and
  offline cargo4 vendor hashes. The edge-agent package remains disabled until
  its cargo4 archive hash is regenerated and reviewed.
- Builder provenance must include the signed builder image digest and pinned
  toolchain/package inputs. Mutable apt repos and local `suderra-builder:latest`
  are not sufficient enterprise evidence.
- RPi/RevPi custom kernel tarballs must be covered by forced download hash
  checks and immutable mirrors.

### P4: Release Evidence and Publication

- signed release ingress must be created only after all release-critical inputs
  are collected: build artifacts, source identity, matrix digest, scanner
  reports, reproducibility reports, governance approval, QEMU evidence, and lab
  evidence.
- Final evidence must validate cryptographic facts, not log text. Cosign,
  artifact attestations, DSSE subjects, source SHA, run ID, run attempt, signer
  identity, and issuer must be checked from downloaded release assets.
- Publication verification must cover the public byte set and its sidecars:
  `release-evidence-<version>.tar.zst`, signatures, certificates, SBOM/VEX,
  release publication manifest, and attestations.
- Release-critical GitHub Actions must be full-SHA pinned or rejected by
  contract tests.

### P5: hardware/lab evidence

- QEMU acceptance must include a semantic guest collector for `/etc/os-release`,
  `uname`, rootfs identity, failed systemd units, firstboot idempotence,
  lockdown state, listeners, and nftables rules.
- Hardware/lab evidence must be collected by a signed station CLI, not
  hand-written JSON. It must include station identity, board identity, UART
  transcript, flash transcript, full readback hash, firmware/boot evidence,
  RevPi IO checks, and negative tests.
- Lab validators must compare against expected artifact digests from release
  binding. Self-reported artifact hashes are not trusted evidence.

### P6: Rust and Userspace Quality

- Placeholder binaries must be removed from production images or gated behind
  explicit experimental flags until end-to-end tests exist.
- `suderra-installer` state writes must be atomic, and audit/state failures must
  not be silently ignored on production paths.
- The Edge Agent package must not be enabled until cargo4 vendor hashes and its
  first-class CI matrix are revalidated.
- Rust toolchain and dependency policy must be explicit across Suderra OS
  userspace and the edge-agent/aquaculture workspace.

## Implemented First Batch

The first implementation batch intentionally did not make Suderra OS
production-ready. It closed false-success and false-production surfaces:

- x86_64 production defconfig no longer enables Dropbear or getty.
- Production post-build lockdown is automatic for the production variant.
- Production post-image gates reject Dropbear, getty, placeholder firstboot, and
  missing RAUC before any production claim can pass.
- The packaged firstboot unit now points at `/usr/bin/suderra-firstboot`.
- Build source identity records the Suderra external tree digest and release
  source identity, and CI requires a clean external tree before snapshotting it.
- Installer state handling and install behavior now fail closed instead of
  treating a copy operation as a successful OTA/install.
- Edge install uses a root-owned work directory, HTTPS-only fetches, digest-
  bound config payloads, downgrade guard, health-check promotion, and rollback
  on activation or lockdown failure.
- x86_64 production defconfig now enables RAUC, the Suderra RAUC slot
  configuration package, and the common kernel hardening fragment.
- x86_64 genimage now starts rootfs B blank for RAUC ownership, reserves verity
  hash partitions, and creates a labelled `SUDERRA-DATA` filesystem.
- `scripts/production-artifacts.sh` now generates dm-verity metadata, composes
  the x86 verity kernel command line, builds a signed UKI from an explicit EFI
  stub, signs the disk image, and feeds those artifacts into post-image gates.
- A contract test exists at
  `tests/image-contracts/enterprise-gap-closure-contract-test.sh`.

## Implemented Second Batch

The second implementation batch corrected the x86 production boot-chain
architecture so the RAUC/GRUB claim and Secure Boot artifact layout agree:

- The x86 production boot path is now signed GRUB as `EFI/BOOT/BOOTX64.EFI`
  plus signed slot UKIs under `EFI/SUDERRA/`.
- The initial factory image generates a signed `suderra-A.efi` slot UKI whose
  embedded command line includes `rauc.slot=A` and the dm-verity root mapping
  for `rootfs-a`.
- The GRUB config now reads and writes the RAUC GRUB environment file and uses
  `ORDER`, `A_OK`, `A_TRY`, `B_OK`, and `B_TRY` to select slot A or B.
- The GRUB environment is initialized during production artifact generation and
  stored outside the redundant rootfs partitions at `EFI/BOOT/grubenv`.
- The target mounts the EFI partition at `/boot` and RAUC is configured with
  `grubenv=/boot/EFI/BOOT/grubenv` so userspace and GRUB operate on the same
  boot state.
- Production gates now verify both signed GRUB and the signed slot UKI with
  sidecar signatures and Secure Boot signature validation.
- `suderra-rauc-mark-good` now emits typed boot-state evidence before and after
  `rauc status mark-good`.
- The previous Rust formatting drift in `suderra-installer` state persistence
  was corrected so `cargo fmt --all --check` can pass.

## Implemented Third Batch

The third implementation batch started binding RAUC updates to the same signed
boot and dm-verity artifacts as the factory image:

- Production artifact generation now emits both signed slot UKIs,
  `suderra-A.efi` and `suderra-B.efi`.
- The production image gate requires and verifies the inactive slot UKI as well
  as the active slot UKI.
- RAUC slot configuration now models `rootfs-a-verity` and `rootfs-b-verity`
  as child slots of their matching rootfs slots, so the rootfs and verity hash
  tree are updated as one group.
- `scripts/create-rauc-bundle.sh` creates a signed x86 RAUC bundle from the
  production rootfs, verity tree, and slot UKIs.
- `scripts/rauc-x86-slot-hook.sh` installs the matching signed slot UKI into
  the shared EFI partition during the rootfs post-install hook.
- Production post-image now fails closed unless `SUDERRA_RELEASE_VERSION` and
  RAUC signing material are present and the signed RAUC bundle is generated.

## Implemented Fourth Batch

The fourth implementation batch replaced placeholder QEMU release semantics
with machine-collected guest evidence:

- QEMU images now include `suderra-qemu-semantic-collector`, which emits a
  marker-delimited JSON record on the serial console.
- The collector records `/etc/os-release`, `uname`, rootfs identity, failed
  systemd units, network state, firstboot marker state, lockdown status,
  listener inventory, and nftables ruleset evidence.
- The collector unit is enabled only for the QEMU x86_64 dev defconfig path,
  avoiding test-evidence output in hardware or production images.
- `qmp-acceptance.py` now waits for the semantic collector when running the
  `release-candidate` profile, parses the serial JSON, and binds semantic
  checks to the collected facts.
- Empty QEMU stderr is now preserved as a hashed log entry so strict release
  validators still receive the required log role.
- The QMP acceptance contract test now validates the collector script, systemd
  unit, post-build enablement, parser behavior, release-candidate semantic
  checks, and empty-stderr evidence preservation.

## Implemented Fifth Batch

The fifth implementation batch closed the unsigned/manual hardware lab input
gap:

- `scripts/evidence/suderra-lab.py collect` now creates
  `suderra.lab-evidence.v3` from a station collection spec instead of requiring
  operators to hand-write release JSON.
- The collector imports the lab validator contract as its source of truth for
  required checks, USB negative tests, and RevPi-specific checks.
- Lab artifact binding is computed from the supplied build artifact bytes; the
  collector rejects readback evidence whose SHA-256 or byte count does not
  match that bound artifact.
- The collector copies evidence files into `release-lab-input/<version>/<target>/`,
  records per-file SHA-256 values, and signs a station bundle with an Ed25519
  OpenSSL key.
- Strict lab validation now requires `station_bundle` and `station_signature`,
  verifies the signed station bundle, checks the station public-key fingerprint,
  and rejects lab JSON changed after signing.
- Final release evidence assembly now copies the station bundle, signature, and
  public key into `hardware/input/` and preserves those records under
  `hardware.station_bundle` and `hardware.station_signature`.
- Release-input contract fixtures now exercise the same signed lab evidence
  chain instead of relying on unsigned synthetic lab JSON.

## Remaining Implementation Backlog

### Next Batch: x86_64 Production Chain

- Provide production Secure Boot signing key access through HSM/KMS rather than
  file-based CI keys.
- Provide a reviewed production `SUDERRA_UKI_STUB` source and artifact
  provenance.
- Exercise the x86 RAUC bundle path in QEMU/hardware with real good update,
  bad signature, failed health, mark-good, and rollback evidence.
- Extend the current one-try GRUB fallback into a tested bootcount/rollback
  scenario covering good update, bad update, and power-loss cases.
- Add QEMU Secure Boot tests: unsigned UKI rejection, modified cmdline
  rejection, and rootfs tamper failure.

### Release Evidence Batch

- Make release-preflight produce scanner and reproducibility evidence instead
  of accepting `TO_BE_COLLECTED` skeletons.
- Move signing/attestation into the protected publish environment.
- Revalidate cosign signatures, DSSE/attestation subjects, workflow ref, source
  SHA, run ID, and run attempt from downloaded release assets.
- Include tag binding, preflight metadata, source identity, scanner reports,
  SBOM/VEX, and publication manifest in final evidence.

### Build and Supply Chain Batch

- Publish and verify a signed builder image by immutable digest.
- Pin apt snapshots or package versions used by the builder image.
- Refactor local Rust packages toward Buildroot cargo source isolation and
  offline cargo4 vendor archives.
- Revalidate edge-agent cargo4 hash before enabling the package.
- Enable forced hash checks for custom RPi/RevPi kernel downloads.

### Hardware and Lab Batch

- Sign the QEMU semantic evidence JSON or wrap it in the signed release input
  archive after collection.
- Replace the station spec ingestion path with direct station adapters for
  UART, power control, flash invocation, readback, RevPi IO, and negative-test
  execution.
- Add hardware-bound negative tests for expected artifact mismatch, readback
  mismatch, failed unmount, unsigned lab bundle, and RevPi IO failure.

## Required Verification

- `./scripts/run-tests.sh image-contracts`
- `git diff --check`
- `systemd-analyze verify --root` for each built target
- QEMU Secure Boot and dm-verity tamper tests once signed UKI/verity exists
- RAUC good update, bad signature, failed health rollback, mark-good, bootcount
  fallback, corrupt state, and power-loss scenarios
- Release evidence negative tests for tampered ingress, unlisted input, wrong
  source SHA, wrong run attempt, non-SHA action pin, signing before approval,
  and publication signature mismatch
- Hardware/lab negative tests for expected artifact mismatch, readback mismatch,
  failed unmount, unsigned lab bundle, and RevPi IO failure

## Operating Rule

When continuing enterprise-grade implementation, start from the **Remaining
Implementation Backlog** above. Do not open `production_ready=true` or remove
the fail-closed gates until the corresponding implementation and verification
sections are complete.
