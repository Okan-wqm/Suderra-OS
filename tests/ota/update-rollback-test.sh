#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OTA="${ROOT}/userspace/suderra-ota/src/main.rs"
VALIDATOR="${ROOT}/scripts/evidence/validate-production-runtime-suite.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

for token in \
    'suderra.os-update-manifest.v1' \
    'verify_manifest_signature' \
    'verify_manifest_policy' \
    'refusing downgrade' \
    'rollback_floor' \
    'run_rauc(&["install"' \
    'run_rauc(&["status", "mark-bad"])' \
    'run_rauc(&["status", "mark-good"])' \
    'persist_rollback_floor' \
    'pending_boot_slot' \
    'alpha.2", "v1.0.0-alpha.10'
do
    grep -Fq "${token}" "${OTA}" || {
        echo "ERROR: suderra-ota missing fail-closed OTA/rollback behavior: ${token}" >&2
        exit 1
    }
done

python3 -m py_compile "${VALIDATOR}"
python3 - "${TMPDIR}/runtime.json" <<'PY'
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
    ("anti-rollback-downgrade-rejection", "userspace-rejected", "rauc-version"),
    ("data-luks-swtpm", "booted", "swtpm-state"),
]
items = []
for name, outcome, mutation in scenarios:
    log = root / f"{name}.serial.log"
    log.write_text(f"{name} {outcome}\n", encoding="utf-8")
    before = hashlib.sha256(f"{name}:before".encode()).hexdigest()
    after = hashlib.sha256(f"{name}:after".encode()).hexdigest()
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

if python3 "${VALIDATOR}" "${TMPDIR}/runtime.json" --require-pass --check-files \
    2>"${TMPDIR}/runtime.err"; then
    echo "ERROR: production-runtime suite accepted missing RAUC health rollback evidence" >&2
    exit 1
fi
grep -q 'rauc-health-rollback' "${TMPDIR}/runtime.err"
