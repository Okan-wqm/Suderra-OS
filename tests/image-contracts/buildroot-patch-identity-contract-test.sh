#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/scripts/ci/buildroot-patch-identity.py"

python3 "${TOOL}" metadata --source-sha "$(git -C "${ROOT}" rev-parse HEAD)" >/tmp/suderra-buildroot-source.json

python3 - /tmp/suderra-buildroot-source.json <<'PY'
import json
import re
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for field, pattern in {
    "buildroot_index_sha": r"^[0-9a-f]{40}$",
    "buildroot_patchset_sha256": r"^[0-9a-f]{64}$",
    "buildroot_effective_source_id": r"^[0-9a-f]{64}$",
}.items():
    value = payload.get(field)
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise SystemExit(f"ERROR: invalid {field}: {value!r}")
patches = payload.get("buildroot_patch_files")
if not isinstance(patches, list) or not patches:
    raise SystemExit("ERROR: Buildroot patch files must be recorded")
for patch in patches:
    if not str(patch.get("path", "")).startswith("patches/buildroot/"):
        raise SystemExit(f"ERROR: unexpected Buildroot patch path: {patch!r}")
PY

grep -q 'buildroot-patch-identity.py" validate-applied' "${ROOT}/scripts/apply-buildroot-patches.sh" || {
    echo "ERROR: apply-buildroot-patches.sh must validate the applied patch identity" >&2
    exit 1
}
grep -q 'apply --check "${patch}"' "${ROOT}/scripts/apply-buildroot-patches.sh" || {
    echo "ERROR: Buildroot patch application must try normal git apply before any fallback" >&2
    exit 1
}
grep -q 'Falling back to --unidiff-zero' "${ROOT}/scripts/apply-buildroot-patches.sh" || {
    echo "ERROR: zero-context Buildroot patch fallback must be explicit and auditable" >&2
    exit 1
}
grep -q 'apply-buildroot-patches.sh buildroot' "${ROOT}/.github/workflows/build.yml" || {
    echo "ERROR: build workflow defconfig parse must apply Buildroot patches first" >&2
    exit 1
}
