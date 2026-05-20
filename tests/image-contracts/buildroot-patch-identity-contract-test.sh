#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/scripts/ci/buildroot-patch-identity.py"

expected_sha="019201c6e007d80c1ab1bf65b98d9902bc767bdd"
actual_index_sha="$(git -C "${ROOT}" ls-tree HEAD buildroot | awk '{print $3}')"
actual_head_sha="$(git -C "${ROOT}/buildroot" rev-parse HEAD)"
[ "${actual_index_sha}" = "${expected_sha}" ] || {
    echo "ERROR: buildroot gitlink must point at Buildroot 2025.05.3" >&2
    exit 1
}
[ "${actual_head_sha}" = "${expected_sha}" ] || {
    echo "ERROR: checked-out buildroot submodule must be Buildroot 2025.05.3" >&2
    exit 1
}
grep -q 'branch = 2025\.05\.x' "${ROOT}/.gitmodules" || {
    echo "ERROR: .gitmodules must track the 2025.05.x Buildroot branch hint" >&2
    exit 1
}
if git -C "${ROOT}/buildroot" status --porcelain --untracked-files=all | grep -q .; then
    echo "ERROR: buildroot submodule must be clean for native Rust mode" >&2
    git -C "${ROOT}/buildroot" status --porcelain --untracked-files=all >&2
    exit 1
fi
if compgen -G "${ROOT}/patches/buildroot/*.patch" >/dev/null; then
    echo "ERROR: Buildroot patch queue must be empty for native Rust 2025.05.3 mode" >&2
    exit 1
fi

python3 "${TOOL}" metadata --source-sha "$(git -C "${ROOT}" rev-parse HEAD)" >/tmp/suderra-buildroot-source.json

python3 - /tmp/suderra-buildroot-source.json <<'PY'
import json
import re
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for field, pattern in {
    "suderra_source_sha": r"^[0-9a-f]{40}$",
    "suderra_external_tree_sha256": r"^[0-9a-f]{64}$",
    "suderra_release_source_id": r"^[0-9a-f]{64}$",
    "buildroot_index_sha": r"^[0-9a-f]{40}$",
    "buildroot_patchset_sha256": r"^[0-9a-f]{64}$",
    "buildroot_effective_source_id": r"^[0-9a-f]{64}$",
}.items():
    value = payload.get(field)
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise SystemExit(f"ERROR: invalid {field}: {value!r}")
if payload.get("schema_version") != "suderra.buildroot-source-identity.v2":
    raise SystemExit("ERROR: Buildroot source identity must use v2 schema")
if not isinstance(payload.get("suderra_external_dirty_paths"), list):
    raise SystemExit("ERROR: source identity must record external dirty path list")
if payload.get("buildroot_upstream_ref") != "2025.05.3":
    raise SystemExit("ERROR: Buildroot source identity must bind upstream ref 2025.05.3")
if payload.get("buildroot_source_mode") != "clean-native":
    raise SystemExit("ERROR: Buildroot source identity must use clean-native mode")
patches = payload.get("buildroot_patch_files")
if patches != []:
    raise SystemExit("ERROR: native Buildroot Rust mode must not record patch files")
if payload.get("buildroot_expected_patched") is not False:
    raise SystemExit("ERROR: native Buildroot Rust mode must not be marked patched")
for field in (
    "buildroot_applied_diff_sha256",
    "buildroot_worktree_diff_sha256",
    "buildroot_expected_diff_sha256",
    "buildroot_staged_diff_sha256",
):
    if field in payload:
        raise SystemExit(f"ERROR: native Buildroot Rust identity must not include {field}")
if payload.get("buildroot_rust_version") != "1.86.0":
    raise SystemExit("ERROR: native Buildroot rust package must be 1.86.0")
if payload.get("buildroot_rust_bin_version") != "1.86.0":
    raise SystemExit("ERROR: native Buildroot rust-bin package must be 1.86.0")
PY

grep -q 'buildroot-source.sh" prepare' "${ROOT}/scripts/build.sh" || {
    echo "ERROR: build.sh must prepare an isolated Buildroot source tree" >&2
    exit 1
}
grep -q 'buildroot-source.sh" prepare-external' "${ROOT}/scripts/build.sh" || {
    echo "ERROR: build.sh must prepare an isolated BR2_EXTERNAL source tree" >&2
    exit 1
}
grep -q 'BR2_EXTERNAL="${BR2_EXTERNAL_SOURCE_DIR}"' "${ROOT}/scripts/build.sh" || {
    echo "ERROR: build.sh must build against the isolated BR2_EXTERNAL source tree" >&2
    exit 1
}
grep -q 'SUDERRA_BUILDROOT_SOURCE_IDENTITY_OUT' "${ROOT}/scripts/build-in-docker.sh" || {
    echo "ERROR: Docker build wrapper must pass Buildroot source identity output path" >&2
    exit 1
}
grep -q 'SUDERRA_REQUIRE_CLEAN_EXTERNAL' "${ROOT}/.github/workflows/build.yml" || {
    echo "ERROR: CI builds must require a clean BR2_EXTERNAL tree before snapshotting" >&2
    exit 1
}
if grep -q 'apply-buildroot-patches.sh buildroot' "${ROOT}/.github/workflows/build.yml"; then
    echo "ERROR: build workflow must not apply patches to the tracked buildroot submodule" >&2
    exit 1
fi
if grep -q 'make -C buildroot' "${ROOT}/.github/workflows/build.yml"; then
    echo "ERROR: build workflow must not build from the tracked buildroot submodule" >&2
    exit 1
fi
grep -q 'Verify Buildroot submodule stayed clean' "${ROOT}/.github/workflows/build.yml" || {
    echo "ERROR: build workflow must verify buildroot stayed clean" >&2
    exit 1
}
