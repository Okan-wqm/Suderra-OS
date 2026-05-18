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

The workflow artifact name is:

```text
release-preflight-<version>-<source_sha>
```

The release tag workflow searches for a successful preflight artifact for the
tag commit. If it cannot find one, publication stops before image builds.

`release-candidate` preflight also validates live GitHub governance. The token
must be able to read branch protection, repository rulesets, environments,
workflow permissions, and the audit snapshot. If the repository cannot provide a
collected audit log, governance validation fails closed.

## Required Inputs

The candidate bundle must include:

- `release-inputs/<version>/release-candidate.json`
- `release-lab-input/<version>/qemu-x86_64/qemu.json`
- `release-lab-input/<version>/<hardware-target>/lab.json`
- `release-governance/<version>/governance-policy-validation.json`
- `release-approvals/<version>/<target>.json`
- `release-security/<version>/<scan>.json`
- `release-reproducibility/<version>/<target>.log`

All evidence must reference the same source commit, Build run ID, Buildroot
submodule SHA, matrix hash, and artifact digests.
