#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-contract}"
COLLECTOR="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-qemu-semantic-collector"
VALIDATOR="${ROOT}/scripts/evidence/validate-qemu-input.py"
NFTABLES="${ROOT}/board/suderra/common/rootfs-overlay/etc/nftables.conf"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

bash -n "${COLLECTOR}"
grep -q 'ss -H -lntup' "${COLLECTOR}" || {
    echo "ERROR: semantic collector must capture TCP/UDP listeners for nmap parity (${TARGET})" >&2
    exit 1
}
grep -q 'nft list ruleset' "${COLLECTOR}" || {
    echo "ERROR: semantic collector must capture nftables ruleset for external scan parity" >&2
    exit 1
}
grep -q 'policy drop' "${NFTABLES}" || {
    echo "ERROR: production firewall baseline must default-drop inbound traffic" >&2
    exit 1
}

python3 -m py_compile "${VALIDATOR}"
python3 - "${TMPDIR}/qemu.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
root = out.parent
semantic = {
    "schema_version": "suderra.qemu-semantic.v1",
    "os_release": {"ID": "suderra-os", "VARIANT": "prod"},
    "kernel": {"release": "6.12.0"},
    "rootfs": {"mount_source": "/dev/mapper/suderra-root", "cmdline_root": "/dev/mapper/suderra-root"},
    "failed_units": {"count": 0, "lines": []},
    "network": {"state": "up"},
    "firstboot": {"done_marker": True},
    "lockdown": {"status": "confidentiality"},
    "listeners": [{"proto": "tcp", "local": "0.0.0.0:22"}],
    "firewall": {"loaded": True},
    "secure_boot": {"enabled": True},
    "dm_verity": {"active": True},
    "rauc": {"available": True},
    "data_encryption": {"encrypted": True},
    "anti_rollback": {"rollback_floor": "v9.9.9"},
}
checks = {
    name: {"status": "passed", "evidence": "contract", "source": "contract"}
    for name in (
        "boot", "systemd", "zero-failed-units", "no-kernel-panic", "no-emergency-mode",
        "os-release", "kernel", "rootfs", "network", "firstboot-idempotence",
        "lockdown-transition", "listeners", "firewall", "secure_boot", "dm_verity",
        "dm-verity-tamper-rejection", "rauc", "rauc-good-update",
        "rauc-bad-signature-rejection", "rauc-health-rollback",
        "anti-rollback-downgrade-rejection", "data-luks-swtpm"
    )
}
logs = []
for role, name, payload in (
    ("serial", "serial.log", "serial\n"),
    ("qmp-events", "qmp.json", "[]\n"),
    ("qemu-semantic", "qemu-semantic.json", json.dumps(semantic, sort_keys=True) + "\n"),
):
    path = root / name
    path.write_text(payload, encoding="utf-8")
    logs.append({"role": role, "path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
payload = {
    "schema_version": "suderra.qemu-acceptance.v4",
    "version": "v9.9.9",
    "target": "qemu-x86_64-prod-ab",
    "source_sha": "0123456789abcdef0123456789abcdef01234567",
    "generated_at": "2026-05-25T00:00:00Z",
    "image": "disk.img",
    "image_sha256": "a" * 64,
    "qemu_version": "QEMU contract",
    "firmware": "OVMF_CODE.secboot.fd",
    "firmware_sha256": "b" * 64,
    "status": "passed",
    "profile": "production-runtime",
    "failure_class": "none",
    "qemu_exit_status": 0,
    "termination": {"mode": "exited", "exit_status": 0, "killed": False, "timeout": False, "acceptable": True},
    "logs": logs,
    "checks": checks,
    "guest_facts": semantic,
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${VALIDATOR}" "${TMPDIR}/qemu.json" --require-pass --profile production-runtime --check-files \
    2>"${TMPDIR}/listeners.err"; then
    echo "ERROR: production-runtime QEMU validator accepted open listener evidence" >&2
    exit 1
fi
grep -q 'listeners' "${TMPDIR}/listeners.err"
