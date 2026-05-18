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
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

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

    assert module.SCHEMA_VERSION == "suderra.qemu-acceptance.v3"
    checks = module.release_checks(
        {"banner": True, "systemd": True, "provisioning-ready": True},
        {"kernel-panic": False, "oom-or-systemd-failure": False},
    )
    required = {
        "boot",
        "systemd",
        "zero-failed-units",
        "no-kernel-panic",
        "no-emergency-mode",
        "os-release",
        "kernel",
        "rootfs",
        "network",
        "firstboot-idempotence",
        "lockdown-transition",
        "listeners",
        "firewall",
    }
    assert required <= set(checks)
    assert checks["boot"]["status"] == "passed"
    assert checks["no-kernel-panic"]["status"] == "passed"
PY

if grep -q 'suderra.qemu-acceptance.v2' "${HARNESS}"; then
    echo "ERROR: QMP acceptance harness must emit qemu acceptance schema v3" >&2
    exit 1
fi

QEMU_INPUT="${TMPDIR}/release-lab-input/v9.9.9-alpha.1/qemu-x86_64/qemu.json"
mkdir -p "$(dirname "${QEMU_INPUT}")"
python3 - "${QEMU_INPUT}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

qemu_input = Path(sys.argv[1])
root = qemu_input.parent
log_entries = []
for role, name in (("serial", "serial.log"), ("qmp-events", "qmp.json"), ("qemu-stderr", "qemu-stderr.log")):
    payload = f"synthetic {name}\n".encode("utf-8")
    (root / name).write_bytes(payload)
    log_entries.append({"role": role, "path": name, "sha256": hashlib.sha256(payload).hexdigest()})
checks = {
    name: {
        "status": "passed",
        "evidence": f"{name} collected by contract fixture",
        "source": "contract-fixture",
    }
    for name in (
        "boot",
        "systemd",
        "zero-failed-units",
        "no-kernel-panic",
        "no-emergency-mode",
        "os-release",
        "kernel",
        "rootfs",
        "network",
        "firstboot-idempotence",
        "lockdown-transition",
        "listeners",
        "firewall",
    )
}
payload = {
    "schema_version": "suderra.qemu-acceptance.v3",
    "version": "v9.9.9-alpha.1",
    "target": "qemu-x86_64",
    "source_sha": "0123456789abcdef0123456789abcdef01234567",
    "generated_at": "2026-05-13T00:00:00Z",
    "image": "suderra-qemu-x86_64.img",
    "qemu_version": "QEMU emulator version contract-test",
    "firmware": "OVMF_CODE.fd",
    "image_sha256": "a" * 64,
    "firmware_sha256": "b" * 64,
    "status": "passed",
    "logs": log_entries,
    "checks": checks,
    "guest_facts": {
        "os_release": {"ID": "suderra"},
        "kernel": "contract-test",
        "rootfs": {"partlabel": "rootfs"},
        "network": {"state": "up"},
        "listeners": [],
        "firewall": {"nft": "loaded"},
        "firstboot": {"idempotent": True},
        "lockdown": {"status": "locked"},
    },
}
qemu_input.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "${PROJECT_ROOT}/scripts/evidence/validate-qemu-input.py" \
    --require-pass \
    --check-files \
    "${QEMU_INPUT}" \
    >/dev/null
python3 - "${QEMU_INPUT}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["checks"].pop("lockdown-transition")
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${PROJECT_ROOT}/scripts/evidence/validate-qemu-input.py" \
    --require-pass \
    --check-files \
    "${QEMU_INPUT}" \
    2>"${TMPDIR}/qemu-input.err"; then
    echo "ERROR: QEMU input validator accepted missing lockdown-transition check" >&2
    exit 1
fi
grep -q "lockdown-transition" "${TMPDIR}/qemu-input.err" || {
    echo "ERROR: QEMU input validator did not report missing lockdown-transition" >&2
    cat "${TMPDIR}/qemu-input.err" >&2
    exit 1
}

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
