#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
HARNESS="${PROJECT_ROOT}/tests/qemu/qmp-acceptance.py"
BOOT_TEST="${PROJECT_ROOT}/tests/qemu/boot-test.sh"
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"
QEMU_GRUB="${PROJECT_ROOT}/board/suderra/x86_64/grub-qemu.cfg"

python3 -m py_compile "${HARNESS}"
"${HARNESS}" --help >/dev/null
python3 - "${HARNESS}" <<'PY'
import importlib.util
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

harness_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("qmp_acceptance", harness_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)
    code = tmp / "OVMF_CODE_4M.fd"
    vars_template = tmp / "OVMF_VARS_4M.fd"
    code.write_bytes(b"code")
    vars_template.write_bytes(b"vars")

    pflash = module.resolve_ovmf_firmware(
        SimpleNamespace(ovmf=code, ovmf_vars=None, ovmf_mode="auto"),
        tmp / "boot-test",
    )
    assert pflash.mode == "pflash"
    assert pflash.code == code
    assert pflash.vars_template == vars_template
    assert pflash.vars_runtime is not None
    assert pflash.vars_runtime.read_bytes() == b"vars"
    pflash_args = module.firmware_qemu_args(pflash)
    assert "-bios" not in pflash_args
    assert any("if=pflash" in arg for arg in pflash_args)

    monolithic = tmp / "OVMF.fd"
    monolithic.write_bytes(b"bios")
    bios = module.resolve_ovmf_firmware(
        SimpleNamespace(ovmf=monolithic, ovmf_vars=None, ovmf_mode="auto"),
        tmp / "boot-test-bios",
    )
    assert bios.mode == "bios"
    assert module.firmware_qemu_args(bios) == ["-bios", str(monolithic)]
PY

if ! grep -q 'qmp-acceptance.py' "${BOOT_TEST}"; then
    echo "ERROR: boot-test.sh must use the QMP acceptance harness" >&2
    exit 1
fi
if grep -q 'timeout "${TIMEOUT}" qemu-system-x86_64' "${BOOT_TEST}"; then
    echo "ERROR: boot-test.sh still uses direct timeout/grep smoke execution" >&2
    exit 1
fi
if ! grep -q 'linux /bzImage' "${QEMU_GRUB}"; then
    echo "ERROR: QEMU GRUB config must boot the kernel path exported into the EFI partition" >&2
    exit 1
fi
if grep -q '/boot/bzImage' "${QEMU_GRUB}"; then
    echo "ERROR: QEMU GRUB config must not use the rootfs /boot path for the EFI kernel" >&2
    exit 1
fi
if grep -q '^#' "${QEMU_GRUB}"; then
    echo "ERROR: QEMU GRUB runtime config must avoid comment commands in serial boot evidence" >&2
    exit 1
fi
if ! grep -q 'efi-part/EFI/BOOT/grub.cfg' "${POST_IMAGE}"; then
    echo "ERROR: post-image.sh must install the authoritative GRUB config into the EFI image tree" >&2
    exit 1
fi
