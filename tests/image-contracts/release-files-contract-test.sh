#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

RELEASE_DIR="${TMPDIR}/release"
mkdir -p "${RELEASE_DIR}"

python3 - "${PROJECT_ROOT}" "${RELEASE_DIR}" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
release_dir = Path(sys.argv[2])
module_path = root / "scripts" / "ci" / "validate-build-matrix.py"
spec = importlib.util.spec_from_file_location("validate_build_matrix", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

matrix = module.load_matrix(root / "ci" / "build-matrix.yml")
for target in matrix["defconfigs"]:
    if not target.get("release"):
        continue
    release_artifact = str(target["release_artifact"])
    rename_base = module.release_rename_base(release_artifact)
    sbom_base = module.sbom_base(release_artifact)
    for name in (
        release_artifact,
        f"{release_artifact}.sha256",
        f"{rename_base}.manifest.txt",
        f"{sbom_base}.cyclonedx.json",
    ):
        (release_dir / name).write_text(f"{name}\n", encoding="utf-8")
    expected = set(module.expected_artifacts(target))
    if "manifest.json" in expected:
        (release_dir / f"{module.payload_manifest_base(release_artifact)}.payload-manifest.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    if "manifest.sig" in expected:
        (release_dir / f"{module.payload_manifest_base(release_artifact)}.payload-manifest.sig").write_text(
            "signature\n",
            encoding="utf-8",
        )

version = "v9.9.9"
for arch in ("x86_64", "aarch64"):
    for suffix in ("", ".sha256"):
        (release_dir / f"suderra-installer-{version}-{arch}{suffix}").write_text(
            f"installer {arch}{suffix}\n",
            encoding="utf-8",
        )
PY

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" release-files \
    --version v9.9.9 \
    --release-dir "${RELEASE_DIR}" \
    >/dev/null

python3 - "${RELEASE_DIR}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

release_dir = Path(sys.argv[1])
manifest = {
    "schema_version": "suderra.release-assets.v1",
    "version": "v9.9.9",
    "generated_at": "2026-05-18T00:00:00Z",
    "source": {"git_commit": "0" * 40},
    "matrix_sha256": "0" * 64,
    "buildroot_index_sha": "160000 commit buildroot " + "1" * 40,
    "files": [],
}
for path in sorted(release_dir.iterdir()):
    if path.is_file():
        payload = path.read_bytes()
        manifest["files"].append(
            {
                "name": path.name,
                "role": "contract-fixture",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
(release_dir / "release-assets.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(release_dir / "manifest.json").write_text("{}\n", encoding="utf-8")
(release_dir / "SHA256SUMS").write_text("0  fixture\n", encoding="utf-8")
for path in list(release_dir.iterdir()):
    if not path.is_file() or path.name.endswith((".sig", ".cert")):
        continue
    (release_dir / f"{path.name}.sig").write_text("signature\n", encoding="utf-8")
    (release_dir / f"{path.name}.cert").write_text("certificate\n", encoding="utf-8")
PY

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" release-files \
    --version v9.9.9 \
    --release-dir "${RELEASE_DIR}" \
    --signed \
    >/dev/null

rm -f "${RELEASE_DIR}/suderra-pi-cm4-revpi-usb-installer.payload-manifest.sig"
if python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" release-files \
    --version v9.9.9 \
    --release-dir "${RELEASE_DIR}" \
    2>"${TMPDIR}/missing.err"; then
    echo "ERROR: release file validation accepted a missing USB payload manifest signature" >&2
    exit 1
fi
if ! grep -q "payload-manifest.sig" "${TMPDIR}/missing.err"; then
    echo "ERROR: missing payload manifest failure did not identify the release asset" >&2
    cat "${TMPDIR}/missing.err" >&2
    exit 1
fi

RELEASE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release.yml"
grep -q 'release/suderra-\*.payload-manifest.json' "${RELEASE_WORKFLOW}" ||
    {
        echo "ERROR: release workflow does not publish payload manifest JSON assets" >&2
        exit 1
    }
grep -q 'release/suderra-\*.payload-manifest.sig' "${RELEASE_WORKFLOW}" ||
    {
        echo "ERROR: release workflow does not publish payload manifest signature assets" >&2
        exit 1
    }
grep -q 'release/release-assets.json' "${RELEASE_WORKFLOW}" ||
    {
        echo "ERROR: release workflow does not publish immutable release asset manifest" >&2
        exit 1
    }
