# Buildroot 2025.05.3 Native Rust Migration Enterprise Plan

## Objective

Suderra OS builds must stop relying on a dirty `buildroot/` submodule that has
the local Rust patch applied in-place. The upstream Buildroot source of truth is
now the pinned `2025.05.3` tag, which already contains Rust `1.86.0` and
`rust-bin` `1.86.0`.

## Architecture

- Pin `buildroot/` to Buildroot `2025.05.3`
  (`019201c6e007d80c1ab1bf65b98d9902bc767bdd`) and track the
  `2025.05.x` branch hint in `.gitmodules`.
- Keep `buildroot/` pristine in local and CI workflows. Normal builds must
  materialize an isolated source tree under `output/.buildroot-src/` with
  `scripts/buildroot-source.sh prepare`.
- Remove the old Rust `1.86.0` patch from `patches/buildroot/`; Rust is now a
  native upstream Buildroot input, not a Suderra-local submodule diff.
- Bind release evidence to Build workflow source-identity artifacts. The
  release input binding uses `suderra.release-input-binding.v2` and carries the
  Buildroot source identity as `buildroot_source_identity_schema_version` plus
  the normalized Buildroot identity fields.
- Keep `suderra-edge-agent` disabled until its Buildroot `cargo4` vendor
  archive hash is regenerated. Buildroot 2025.05 changed the cargo archive
  suffix from `cargo2` to `cargo4`; reusing the old hash would be a false
  supply-chain claim.

## Validation Gates

- `scripts/buildroot-source.sh verify-native-rust` must prove the checked-out
  submodule matches the pinned `2025.05.3` commit and contains native Rust
  `1.86.0`.
- `scripts/ci/buildroot-patch-identity.py metadata` must emit
  `suderra.buildroot-source-identity.v2` in `clean-native` mode with no patch
  files and no applied/worktree diff digests.
- Build and payload CI jobs must fail if `buildroot/` becomes dirty.
- Release input, ingress, artifact-binding, and release evidence validators
  must reject stale v1 bindings and mismatched Buildroot identity fields.
- Contract tests must reject direct CI builds from `make -C buildroot`, stale
  Buildroot patch queues, and enabling `suderra-edge-agent` before cargo4 hash
  revalidation.

## Deferred Follow-Up

Regenerate the `suderra-edge-agent` cargo4 source archive and hash only when
that package is intentionally re-enabled for a release target. That requires a
networked Buildroot source download, the produced
`suderra-edge-agent-<sha>-cargo4.tar.gz`, and a reviewed update to
`package/suderra-edge-agent/suderra-edge-agent.hash`.
