#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"

python3 "${PROJECT_ROOT}/scripts/ci/validate-build-matrix.py" validate

python3 - "${PROJECT_ROOT}" <<'PY'
import json
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
validator = root / "scripts" / "ci" / "validate-build-matrix.py"
evidence_contract_spec = importlib.util.spec_from_file_location(
    "evidence_contract",
    root / "scripts" / "evidence" / "evidence_contract.py",
)
matrix_spec = importlib.util.spec_from_file_location("validate_build_matrix", validator)
assert evidence_contract_spec is not None and evidence_contract_spec.loader is not None
assert matrix_spec is not None and matrix_spec.loader is not None
evidence_contract = importlib.util.module_from_spec(evidence_contract_spec)
validate_build_matrix = importlib.util.module_from_spec(matrix_spec)
evidence_contract_spec.loader.exec_module(evidence_contract)
matrix_spec.loader.exec_module(validate_build_matrix)

contract = evidence_contract.load_contract(root / "ci" / "evidence-contract.yml")
matrix = validate_build_matrix.load_matrix(root / "ci" / "build-matrix.yml")
join_errors = evidence_contract.validate_matrix_join(matrix, contract)
if join_errors:
    raise SystemExit("evidence contract/build matrix join errors:\n" + "\n".join(join_errors))
bad_matrix = json.loads(json.dumps(matrix))
for row in bad_matrix["defconfigs"]:
    if row.get("target") == "x86_64":
        row["signing"] = "unsigned-lab"
bad_errors = evidence_contract.validate_matrix_join(bad_matrix, contract)
if not any("signing_required" in item for item in bad_errors):
    raise SystemExit("evidence contract/build matrix join failed to reject unsigned production signing")


def matrix_defconfigs(selector: str) -> set[str]:
    payload = subprocess.check_output(
        ["python3", str(validator), "github-matrix", "--selector", selector],
        text=True,
    )
    return {entry["defconfig"] for entry in json.loads(payload)["include"]}


base = matrix_defconfigs("ci_build_base")
payload = matrix_defconfigs("ci_build_payload")
fast = matrix_defconfigs("fast_required")
image_base = matrix_defconfigs("image_build_base")
image_payload = matrix_defconfigs("image_build_payload")
image_qemu = matrix_defconfigs("image_build_qemu")
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
if fast != expected_base | expected_payload:
    raise SystemExit(f"fast_required mismatch: {sorted(fast)}")
if image_base != expected_base:
    raise SystemExit(f"image_build_base mismatch: {sorted(image_base)}")
if image_payload != expected_payload:
    raise SystemExit(f"image_build_payload mismatch: {sorted(image_payload)}")
if image_qemu != {"suderra_qemu_x86_64_defconfig"}:
    raise SystemExit(f"image_build_qemu mismatch: {sorted(image_qemu)}")
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
if image_base & image_payload:
    raise SystemExit(f"image base/payload matrix overlap: {sorted(image_base & image_payload)}")
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
