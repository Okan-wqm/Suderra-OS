#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" validate

python3 - "${PROJECT_ROOT}" <<'PY'
import json
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
if base & payload:
    raise SystemExit(f"base/payload matrix overlap: {sorted(base & payload)}")
PY
