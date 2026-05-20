#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
HARNESS="${PROJECT_ROOT}/tests/qemu/qmp-acceptance.py"
BOOT_TEST="${PROJECT_ROOT}/tests/qemu/boot-test.sh"
POST_BUILD="${PROJECT_ROOT}/board/suderra/common/post-build.sh"
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"
QEMU_GRUB="${PROJECT_ROOT}/board/suderra/x86_64/grub-qemu.cfg"
COLLECTOR="${PROJECT_ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-qemu-semantic-collector"
COLLECTOR_UNIT_DIR="${PROJECT_ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system"
COLLECTOR_UNIT="${COLLECTOR_UNIT_DIR}/suderra-qemu-semantic-collector.service"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

python3 -m py_compile "${HARNESS}"
bash -n "${COLLECTOR}"
"${HARNESS}" --help >/dev/null
python3 - "${HARNESS}" <<'PY'
import importlib.util
import json
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

    semantic_payload = {
        "schema_version": "suderra.qemu-semantic.v1",
        "os_release": {"ID": "suderra-os", "VERSION_ID": "v9.9.9-alpha.1", "VARIANT": "dev"},
        "kernel": {"release": "6.12.0-suderra", "machine": "x86_64"},
        "rootfs": {"cmdline_root": "PARTLABEL=rootfs", "mount_source": "/dev/vda2", "fstype": "ext4"},
        "failed_units": {"count": 0, "lines": []},
        "network": {"state": "offline", "details": []},
        "firstboot": {"done_marker": True, "service_state": "active"},
        "lockdown": {"status": "unlocked", "exit_code": 1, "output": ["expected dev image state"]},
        "listeners": [],
        "firewall": {"loaded": True, "ruleset_sha256": "c" * 64, "ruleset": []},
    }
    serial = (
        "boot log\n"
        f"{module.SEMANTIC_MARKER_BEGIN}\n"
        f"{json.dumps(semantic_payload, sort_keys=True)}\n"
        f"{module.SEMANTIC_MARKER_END}\n"
    )
    facts = module.parse_semantic_guest_facts(serial)
    assert facts["os_release"]["ID"] == "suderra-os"
    assert facts["listeners"] == []
    candidate_checks = module.release_checks(
        {"banner": True, "systemd": True, "provisioning-ready": True},
        {"kernel-panic": False, "oom-or-systemd-failure": False},
        profile="release-candidate",
        guest_facts=facts,
    )
    for name in (
        "zero-failed-units",
        "os-release",
        "kernel",
        "rootfs",
        "network",
        "firstboot-idempotence",
        "lockdown-transition",
        "listeners",
        "firewall",
    ):
        assert candidate_checks[name]["status"] == "passed", (name, candidate_checks[name])

    missing_semantic_checks = module.release_checks(
        {"banner": True, "systemd": True, "provisioning-ready": True},
        {"kernel-panic": False, "oom-or-systemd-failure": False},
        profile="release-candidate",
    )
    assert missing_semantic_checks["os-release"]["status"] == "failed"

    empty_stderr = tmp / "qemu-stderr.log"
    empty_stderr.write_text("", encoding="utf-8")
    stderr_entry = module.relative_log_entry(tmp, "qemu-stderr", empty_stderr, allow_empty=True)
    assert stderr_entry is not None
    assert stderr_entry["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
PY

if grep -q 'suderra.qemu-acceptance.v2' "${HARNESS}"; then
    echo "ERROR: QMP acceptance harness must emit qemu acceptance schema v3" >&2
    exit 1
fi

for token in \
    'SUDERRA_QEMU_SEMANTIC_JSON_BEGIN' \
    'SUDERRA_QEMU_SEMANTIC_JSON_END' \
    '/etc/os-release' \
    'uname -a' \
    'systemctl --failed --no-legend --plain' \
    'suderra-lockdown-status' \
    'ss -H -lntup' \
    'nft list ruleset'
do
    if ! grep -q -- "${token}" "${COLLECTOR}"; then
        echo "ERROR: QEMU semantic collector missing token: ${token}" >&2
        exit 1
    fi
done
if ! grep -q '/usr/sbin/suderra-qemu-semantic-collector' "${COLLECTOR_UNIT}"; then
    echo "ERROR: QEMU semantic collector unit must invoke the collector" >&2
    exit 1
fi
if ! grep -q 'suderra_qemu_x86_64' "${POST_BUILD}" ||
   ! grep -q 'suderra-qemu-semantic-collector.service' "${POST_BUILD}"; then
    echo "ERROR: post-build must enable QEMU semantic collector only through the QEMU defconfig path" >&2
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
semantic = {
    "schema_version": "suderra.qemu-semantic.v1",
    "os_release": {"ID": "suderra"},
    "kernel": {"release": "contract-test"},
    "rootfs": {"partlabel": "rootfs"},
    "failed_units": {"count": 0, "lines": []},
    "network": {"state": "up"},
    "listeners": [],
    "firewall": {"loaded": True},
    "firstboot": {"done_marker": True},
    "lockdown": {"status": "locked"},
}
for role, name, payload in (
    ("serial", "serial.log", "synthetic serial.log\n"),
    ("qmp-events", "qmp.json", "synthetic qmp.json\n"),
    ("qemu-stderr", "qemu-stderr.log", "synthetic qemu-stderr.log\n"),
    ("qemu-semantic", "qemu-semantic.json", json.dumps(semantic, sort_keys=True) + "\n"),
):
    payload_bytes = payload.encode("utf-8")
    (root / name).write_bytes(payload_bytes)
    log_entries.append({"role": role, "path": name, "sha256": hashlib.sha256(payload_bytes).hexdigest()})
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
    "guest_facts": semantic,
}
qemu_input.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "${PROJECT_ROOT}/scripts/evidence/validate-qemu-input.py" \
    --require-pass \
    --check-files \
    --expected-artifact-sha256 "$(printf '%064d' 0 | tr '0' 'a')" \
    "${QEMU_INPUT}" \
    >/dev/null
if python3 "${PROJECT_ROOT}/scripts/evidence/validate-qemu-input.py" \
    --require-pass \
    --check-files \
    --expected-artifact-sha256 "$(printf '%064d' 0 | tr '0' 'c')" \
    "${QEMU_INPUT}" \
    2>"${TMPDIR}/qemu-hash.err"; then
    echo "ERROR: QEMU input validator accepted the wrong bound image sha" >&2
    exit 1
fi
grep -q "bound artifact sha256" "${TMPDIR}/qemu-hash.err" || {
    echo "ERROR: QEMU image hash mismatch did not mention bound artifact sha256" >&2
    cat "${TMPDIR}/qemu-hash.err" >&2
    exit 1
}
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
