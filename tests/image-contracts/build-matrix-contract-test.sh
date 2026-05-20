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
hash_dir = root / "board" / "suderra" / "buildroot-hashes"
linux_hash = hash_dir / "linux" / "linux.hash"
kernel_hash_dir_config = (
    'BR2_GLOBAL_PATCH_DIR="$(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra/buildroot-hashes"'
)
kernel_tarball_re = re.compile(r'^BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=".*?([^/"]+\.tar\.gz)"$')
custom_kernel_errors: list[str] = []
for config in sorted((root / "configs").glob("*_defconfig")):
    config_lines = config.read_text(encoding="utf-8").splitlines()
    stripped_lines = [line.strip() for line in config_lines]
    for line_no, line in enumerate(config_lines, start=1):
        match = selected_re.match(line.strip())
        if match and match.group(1) in legacy_symbols:
            selected_legacy.append(f"{config.relative_to(root)}:{line_no}:{line.strip()}")

    if "BR2_LINUX_KERNEL_CUSTOM_TARBALL=y" not in stripped_lines:
        continue
    location_lines = [
        line for line in stripped_lines if line.startswith("BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=")
    ]
    if len(location_lines) != 1:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must define exactly one custom kernel tarball location"
        )
        continue
    if "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y" not in stripped_lines:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must enable BR2_DOWNLOAD_FORCE_CHECK_HASHES"
        )
    if kernel_hash_dir_config not in stripped_lines:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} must set BR2_GLOBAL_PATCH_DIR to board/suderra/buildroot-hashes"
        )
    tarball_match = kernel_tarball_re.match(location_lines[0])
    if not tarball_match:
        custom_kernel_errors.append(
            f"{config.relative_to(root)} custom kernel tarball location must end in a .tar.gz basename"
        )
        continue
    tarball = tarball_match.group(1)
    if not linux_hash.is_file():
        custom_kernel_errors.append(f"{linux_hash.relative_to(root)} is required")
        continue
    hash_pattern = re.compile(rf"^sha256\s+([0-9a-f]{{64}})\s+{re.escape(tarball)}$", re.MULTILINE)
    hash_match = hash_pattern.search(linux_hash.read_text(encoding="utf-8"))
    if not hash_match:
        custom_kernel_errors.append(
            f"{linux_hash.relative_to(root)} must contain a sha256 entry for {tarball}"
        )
    elif hash_match.group(1) == "0" * 64:
        custom_kernel_errors.append(
            f"{linux_hash.relative_to(root)} contains a placeholder digest for {tarball}"
        )
if selected_legacy:
    raise SystemExit("legacy Buildroot Kconfig symbols selected:\n" + "\n".join(selected_legacy))
if custom_kernel_errors:
    raise SystemExit("custom kernel tarballs must be hash-checked:\n" + "\n".join(custom_kernel_errors))
PY

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    candidate-readiness --tag v0.1.0-alpha.1 >/dev/null

if python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" \
    production-readiness --tag v0.1.0 >/dev/null 2>&1; then
    echo "ERROR: production readiness unexpectedly passed while production blockers remain" >&2
    exit 1
fi
