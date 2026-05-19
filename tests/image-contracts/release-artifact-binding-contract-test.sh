#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
BUILDROOT_INDEX_SHA="$(git -C "${PROJECT_ROOT}" ls-tree HEAD buildroot | awk '{print $3}')"

python3 - "${TMPDIR}" "${VERSION}" "${SOURCE_SHA}" "${BUILDROOT_INDEX_SHA}" "${PROJECT_ROOT}" <<'PY'
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = sys.argv[2]
source_sha = sys.argv[3]
buildroot_index_sha = sys.argv[4]
project_root = Path(sys.argv[5])
release_dir = root / "release"
binding_path = root / "release-inputs" / version / "release-candidate.json"
release_dir.mkdir(parents=True, exist_ok=True)
binding_path.parent.mkdir(parents=True, exist_ok=True)

spec = importlib.util.spec_from_file_location(
    "validate_build_matrix",
    project_root / "scripts" / "ci" / "validate-build-matrix.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
matrix = module.load_matrix(project_root / "ci" / "build-matrix.yml")

def write_release(name: str, text: str) -> str:
    payload = text.encode("utf-8")
    (release_dir / name).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()

def staged_name(row: dict, artifact: str) -> str | None:
    release_artifact = row["release_artifact"]
    source_artifact = row["artifact"]
    if artifact == f"{source_artifact}.xz":
        return release_artifact
    if artifact == "MANIFEST.txt":
        return f"{module.release_rename_base(release_artifact)}.manifest.txt"
    if artifact == "manifest.json":
        return f"{module.payload_manifest_base(release_artifact)}.payload-manifest.json"
    if artifact == "manifest.sig":
        return f"{module.payload_manifest_base(release_artifact)}.payload-manifest.sig"
    return None

binding_artifacts = []
for row in matrix["defconfigs"]:
    if not row.get("release"):
        continue
    for artifact in module.expected_artifacts(row):
        target_name = staged_name(row, artifact)
        if target_name is None:
            digest = hashlib.sha256(f"raw:{row['name']}:{artifact}".encode("utf-8")).hexdigest()
        else:
            digest = write_release(target_name, f"bound:{row['name']}:{artifact}\n")
        binding_artifacts.append(
            {
                "defconfig": row["name"],
                "target": row["target"],
                "artifact": artifact,
                "path": f"{row['name']}-image/{artifact}",
                "bytes": 32,
                "sha256": digest,
            }
        )

installers = []
for arch in ("x86_64", "aarch64"):
    release_name = f"suderra-installer-{version}-{arch}"
    digest = write_release(release_name, f"installer:{arch}\n")
    write_release(f"{release_name}.sha256", f"{digest}  {release_name}\n")
    installers.extend(
        [
            {
                "role": "installer",
                "arch": arch,
                "artifact": f"suderra-installer-{arch}",
                "path": f"installer-{arch}/suderra-installer-{arch}",
                "bytes": len(f"installer:{arch}\n".encode("utf-8")),
                "sha256": digest,
            },
            {
                "role": "checksum",
                "arch": arch,
                "artifact": f"suderra-installer-{arch}.sha256",
                "path": f"installer-{arch}/suderra-installer-{arch}.sha256",
                "bytes": len(f"{digest}  {release_name}\n".encode("utf-8")),
                "sha256": hashlib.sha256(f"{digest}  {release_name}\n".encode("utf-8")).hexdigest(),
            },
        ]
    )

metadata = json.loads(
    subprocess.check_output(
        [
            sys.executable,
            str(project_root / "scripts" / "ci" / "buildroot-patch-identity.py"),
            "metadata",
            "--source-sha",
            source_sha,
        ],
        text=True,
    )
)
binding = {
    "schema_version": "suderra.release-input-binding.v1",
    "profile": "release-candidate",
    "version": version,
    "source_sha": source_sha,
    "source_run_id": "123456789",
    "source_run_attempt": "1",
    "build_workflow_name": "Build",
    "matrix_path": "ci/build-matrix.yml",
    "matrix_sha256": hashlib.sha256((project_root / "ci/build-matrix.yml").read_bytes()).hexdigest(),
    "artifacts": sorted(binding_artifacts, key=lambda item: (item["defconfig"], item["artifact"])),
    "installers": sorted(installers, key=lambda item: (item["arch"], item["artifact"])),
    "release_targets": [],
    "generated_at": "2026-05-13T00:00:00Z",
}
binding.update(metadata)
binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${PROJECT_ROOT}/scripts/evidence/validate-release-artifact-binding.py" \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --release-dir "${TMPDIR}/release" \
    --matrix "${PROJECT_ROOT}/ci/build-matrix.yml" \
    >/dev/null

printf 'tampered\n' >"${TMPDIR}/release/suderra-qemu-x86_64.img.xz"
if python3 "${PROJECT_ROOT}/scripts/evidence/validate-release-artifact-binding.py" \
    --binding-manifest "${TMPDIR}/release-inputs/${VERSION}/release-candidate.json" \
    --release-dir "${TMPDIR}/release" \
    --matrix "${PROJECT_ROOT}/ci/build-matrix.yml" \
    2>"${TMPDIR}/artifact-binding.err"; then
    echo "ERROR: release artifact binding accepted a tampered staged image" >&2
    exit 1
fi
grep -q "sha mismatch" "${TMPDIR}/artifact-binding.err" || {
    echo "ERROR: release artifact binding mismatch did not mention sha mismatch" >&2
    cat "${TMPDIR}/artifact-binding.err" >&2
    exit 1
}
