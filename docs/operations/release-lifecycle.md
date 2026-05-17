# Release Lifecycle

Suderra OS has two release tiers. The tier is derived from the SemVer tag:
pre-release tags such as `v0.1.0-alpha.1` are candidate releases; GA tags such
as `v1.0.0` are production releases.

## Candidate / Alpha

Candidate releases prove a build from an exact tag or exact SHA and collect lab
evidence. They may carry accepted residual risk and must remain draft or
pre-release until the evidence bundle is reviewed.

Required gates:

- `candidate-readiness --tag <version>` passes.
- Build matrix comes from `ci/build-matrix.yml`; workflows must not duplicate
  target lists.
- Base image builds and payload packaging are split so the USB installer
  consumes signed target-image artifacts.
- Security scans, Rust checks, lint, Buildroot artifact contracts, warning
  policy, and QEMU smoke tests pass.
- `release-evidence/<version>/<target>/evidence.json` validates with
  `--release-tier alpha --require-pass --check-files`.
- Production blockers remain explicit residual risk; no production-ready claim
  is made.

## Production / GA

Production release is fail-closed. `production-readiness --tag <version>` must
pass before any GA release can publish.

Required additional gates:

- Production defconfigs use `BR2_PACKAGE_SUDERRA_VARIANT_PROD`.
- Production trust roots come from prod/HSM-backed key material, not dev or CI
  key profiles.
- x86 uses UEFI Secure Boot, signed UKI, immutable cmdline, and dm-verity.
- ARM uses U-Boot verified boot, signed FIT, immutable cmdline, and dm-verity.
- RAUC A/B slots, signed bundles, boot try counters, health checks, mark-good,
  rollback, and downgrade rejection are proven.
- `/data` is the only mutable partition and is LUKS2 encrypted with a TPM-sealed
  unlock policy.
- Signed SBOM and VEX are published and verified.
- Hardware evidence covers every production-required board and intended carrier.

## Tagging

Do not tag until the relevant evidence bundle is already committed.

```bash
git tag -s v0.1.0-alpha.1 -m "Suderra OS v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

Unsigned tags are a blocker for production. If GPG signing is unavailable, stop
and record the blocker instead of publishing a production-like release.

Manual workflow dispatch does not bypass tag validation; the workflow must run
from `refs/tags/<version>`.
