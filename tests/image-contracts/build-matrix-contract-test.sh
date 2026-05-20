#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" validate

python3 - "${PROJECT_ROOT}" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
validator = root / "scripts" / "ci" / "validate-build-matrix.py"


def matrix_defconfigs(selector: str) -> set[str]:
    payload = subprocess.check_output(
        ["python3", str(validator), "github-matrix", "--selector", selector],
        text=True,
    )
    return {entry["defconfig"] for entry in json.loads(payload)["include"]}


base = matrix_defconfigs("ci_build_base")
payload = matrix_defconfigs("ci_build_payload")
release_base = matrix_defconfigs("release_base")
release_payload = matrix_defconfigs("release_payload")

expected_base = {
    "suderra_qemu_x86_64_defconfig",
    "suderra_aarch64_rpi4_defconfig",
    "suderra_aarch64_revpi4_defconfig",
}
expected_payload = {"suderra_aarch64_rpi4_usb_installer_defconfig"}

if base != expected_base:
    raise SystemExit(f"ci_build_base mismatch: {sorted(base)}")
if payload != expected_payload:
    raise SystemExit(f"ci_build_payload mismatch: {sorted(payload)}")
expected_release_base = {
    "suderra_qemu_x86_64_defconfig",
    "suderra_aarch64_rpi4_defconfig",
    "suderra_aarch64_revpi4_defconfig",
}
if release_base != expected_release_base:
    raise SystemExit(f"release_base mismatch: {sorted(release_base)}")
if release_payload != expected_payload:
    raise SystemExit(f"release_payload mismatch: {sorted(release_payload)}")
if base & payload:
    raise SystemExit(f"base/payload matrix overlap: {sorted(base & payload)}")
if release_base & release_payload:
    raise SystemExit(f"release base/payload matrix overlap: {sorted(release_base & release_payload)}")

legacy_text = subprocess.check_output(
    ["git", "-C", str(root / "buildroot"), "show", "HEAD:Config.in.legacy"],
    text=True,
)
legacy_symbols = set(re.findall(r"^config (BR2_[A-Za-z0-9_]+)$", legacy_text, flags=re.MULTILINE))
selected_legacy: list[str] = []
selected_re = re.compile(r"^(BR2_[A-Za-z0-9_]+)=(y|m|\".+\"|[1-9].*)$")
for config in sorted((root / "configs").glob("*_defconfig")):
    for line_no, line in enumerate(config.read_text(encoding="utf-8").splitlines(), start=1):
        match = selected_re.match(line.strip())
        if match and match.group(1) in legacy_symbols:
            selected_legacy.append(f"{config.relative_to(root)}:{line_no}:{line.strip()}")
if selected_legacy:
    raise SystemExit("legacy Buildroot Kconfig symbols selected:\n" + "\n".join(selected_legacy))
PY

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    candidate-readiness --tag v0.1.0-alpha.1 >/dev/null

if python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    production-readiness --tag v0.1.0 >/dev/null 2>&1; then
    echo "ERROR: production readiness unexpectedly passed while production blockers remain" >&2
    exit 1
fi
