#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATOR="${ROOT}/scripts/evidence/validate-production-runtime-suite.py"
PRODUCTION_ARTIFACTS="${ROOT}/scripts/production-artifacts.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

python3 -m py_compile "${VALIDATOR}"

if grep -q 'dm-mod.create=' "${PRODUCTION_ARTIFACTS}"; then
    echo "ERROR: production UKI cmdline must not depend on early dm-mod.create" >&2
    exit 1
fi
grep -q 'build_x86_verity_initramfs' "${PRODUCTION_ARTIFACTS}" || {
    echo "ERROR: production artifacts must embed a verity initramfs in slot UKIs" >&2
    exit 1
}
grep -q 'suderra.verity.root_hash' "${PRODUCTION_ARTIFACTS}" || {
    echo "ERROR: signed UKI cmdline must bind the dm-verity roothash" >&2
    exit 1
}

python3 - "${TMPDIR}/production-runtime.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
root = out.parent
scenarios = [
    ("signed-boot", "booted", "none"),
    ("unsigned-boot-rejection", "firmware-rejected", "uki-signature"),
    ("cmdline-tamper-rejection", "kernel-rejected", "cmdline"),
    ("dm-verity-rootfs-tamper-rejection", "kernel-rejected", "rootfs-partition"),
    ("rauc-good-update", "booted", "rauc-install"),
    ("rauc-bad-signature-rejection", "userspace-rejected", "rauc-bundle-signature"),
    ("rauc-health-rollback", "rollback-completed", "rauc-health"),
    ("anti-rollback-downgrade-rejection", "userspace-rejected", "rauc-version"),
    ("data-luks-swtpm", "booted", "swtpm-state"),
]
items = []
for name, outcome, mutation in scenarios:
    log = root / f"{name}.serial.log"
    log.write_text(f"{name} {outcome}\n", encoding="utf-8")
    before = hashlib.sha256(f"{name}:before".encode()).hexdigest()
    after = hashlib.sha256(f"{name}:after".encode()).hexdigest()
    if name == "dm-verity-rootfs-tamper-rejection":
        after = before
    items.append({
        "name": name,
        "status": "passed",
        "expected_outcome": outcome,
        "observed_outcome": outcome,
        "command": f"tests/qemu/production-runtime-scenario.sh {name}",
        "started_at": "2026-05-25T00:00:00Z",
        "completed_at": "2026-05-25T00:00:01Z",
        "termination_class": "expected",
        "failure_class": "none",
        "mutation": {
            "type": mutation,
            "target": "base-image" if mutation != "none" else "none",
            "before_sha256": before,
            "after_sha256": after,
        },
        "logs": [{
            "role": "serial",
            "path": log.name,
            "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            "bytes": log.stat().st_size,
        }],
    })
payload = {
    "schema_version": "suderra.qemu-production-runtime-suite.v1",
    "version": "v9.9.9",
    "target": "qemu-x86_64-prod-ab",
    "source_sha": "0123456789abcdef0123456789abcdef01234567",
    "generated_at": "2026-05-25T00:00:00Z",
    "image": "disk.img",
    "image_sha256": "a" * 64,
    "ovmf_code": "OVMF_CODE.secboot.fd",
    "ovmf_code_sha256": "b" * 64,
    "ovmf_vars": "OVMF_VARS.fd",
    "ovmf_vars_sha256": "c" * 64,
    "swtpm_state": "swtpm-state",
    "swtpm_state_sha256": "d" * 64,
    "scenarios": items,
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${VALIDATOR}" "${TMPDIR}/production-runtime.json" --require-pass --check-files \
    2>"${TMPDIR}/verity.err"; then
    echo "ERROR: production-runtime validator accepted no-op dm-verity tamper evidence" >&2
    exit 1
fi
grep -q 'must differ from before_sha256' "${TMPDIR}/verity.err"
