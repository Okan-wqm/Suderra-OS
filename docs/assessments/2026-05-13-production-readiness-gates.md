# Suderra OS Production Readiness Gates

Date: 2026-05-13

## Verdict

Suderra OS must not be represented as production-ready yet. The current
repository can build and validate lab/provisioning images, but the production
chain is intentionally fail-closed until secure boot, dm-verity, RAUC,
rollback, hardware acceptance, and release evidence are all present.

## Enforced Gates

- `ci/build-matrix.yml` is the single source of truth for target contracts.
  GitHub build and release matrices are generated from it by
  `scripts/ci/validate-build-matrix.py`.
- Release evidence uses the `suderra.release-evidence.v1` schema at
  `release-evidence/<version>/<target>/evidence.json` and is generated or
  validated by `scripts/evidence/release-evidence.py`.
- Generated evidence skeletons are valid but blocked by default. A production
  release gate must run the validator with `--require-pass --check-files`.
- Matrix validation checks every defconfig, post-image argument, genimage
  contract, expected artifact list, and CI-build host `genimage` selection.
- GA release tags fail the production readiness gate while any
  `production_required: true` row has `production_ready: false`.
- The old placeholder SLSA artifact workflow was removed. Release provenance is
  produced only by `actions/attest-build-provenance`.
- Production post-image builds fail if signed image, dm-verity, and signed boot
  artifacts are missing.
- Release SBOMs are rejected if no CycloneDX file is generated or if a generated
  SBOM has an empty `components` list.
- Placeholder QEMU/security/OTA tests now return an explicit skip code. Set
  `SUDERRA_FAIL_ON_SKIP=1` in required gates so skipped acceptance tests fail
  closed.

## Current Production Blockers

- x86 production target lacks signed UKI/secure boot, dm-verity, RAUC, and
  hardware-lab evidence.
- Pi 4 / CM4 and RevPi target images still use mutable Pi `cmdline.txt` root
  identity and lack U-Boot signed FIT, dm-verity, RAUC, and hardware evidence.
- The USB installer has signed payload verification, but production payload key
  policy, flash readback evidence, and hardware matrix evidence are not complete.
- Generic `suderra_aarch64_defconfig` remains an unsupported template until it
  has a real board, U-Boot config, kernel config, and acceptance path.

## Evidence Required Before Production

Production release evidence must be stored under
`release-evidence/<version>/<target>/` and indexed by `evidence.json`. The
bundle must include CI run IDs, full build logs, artifact hashes, signatures,
provenance, signed SBOM/VEX status, reproducibility comparison, security scan
reports, QEMU logs where required, hardware serial logs, RAUC status, dmsetup
verity proof, lockdown status, nmap results, systemd security output,
approvals, and a final release decision.

Residual risk may be accepted only through
`release_decision.status: approved_with_residual_risk` plus an accepted,
time-bound `residual_risk` record. Residual risk does not waive missing
required evidence; it records the owner decision after required evidence has
passed.

Operational details are documented in
[`docs/operations/release-evidence.md`](../operations/release-evidence.md).
