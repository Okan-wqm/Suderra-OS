#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/validate-lab-input.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

ROOT="${TMPDIR}/release-lab-input/v9.9.9-alpha.1/pi-cm4-revpi-usb-installer"
mkdir -p "${ROOT}"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"

python3 - "${ROOT}" "${SOURCE_SHA}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
source_sha = sys.argv[2]


def write(rel: str, payload: str = "synthetic lab evidence\n") -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return rel


def write_sha(rel: str, payload: str = "synthetic lab evidence\n") -> tuple[str, str]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = payload.encode("utf-8")
    path.write_bytes(payload_bytes)
    return rel, hashlib.sha256(payload_bytes).hexdigest()


required_checks = [
    "board-identity",
    "artifact-hash",
    "flash-transcript",
    "full-readback-hash",
    "serial-boot-log",
    "post-install-boot",
    "partitions",
    "root-data-mounts",
    "network",
    "listeners",
    "failed-units",
    "thermal",
    "watchdog",
]
boards = [
    "raspberry-pi-4-model-b",
    "cm4-lite-sd",
    "cm4-emmc-io-board",
    "revpi-connect-4",
]
devices = []
for board in boards:
    checks = {
        name: {
            "status": "passed",
            "evidence": evidence[0],
            "evidence_sha256": evidence[1],
            "command": f"collect {name}",
            "expected": "passed",
            "observed": "passed",
            "parsed_result": "passed",
        }
        for name in required_checks
        for evidence in [write_sha(f"hardware/{board}/{name}.txt")]
    }
    if board == "revpi-connect-4":
        evidence = write_sha(f"hardware/{board}/revpi-io.txt")
        checks["revpi-io"] = {
            "status": "passed",
            "evidence": evidence[0],
            "evidence_sha256": evidence[1],
            "command": "collect revpi-io",
            "expected": "passed",
            "observed": "passed",
            "parsed_result": "passed",
        }
    log = write_sha(f"hardware/{board}/serial.log")
    devices.append(
        {
            "board": board,
            "serial": f"serial-{board}",
            "sku": f"sku-{board}",
            "storage_serial": f"storage-{board}",
            "uart_adapter": f"uart-{board}",
            "power_supply": "lab-psu-01",
            "boot_firmware": "contract-fixture",
            "operator": "Contract Test",
            "tested_at": "2026-05-18T00:00:00Z",
            "status": "passed",
            "logs": [{"path": log[0], "sha256": log[1]}],
            "device_identity": {
                "model": board,
                "compatible": f"suderra,{board}",
                "storage_by_id": f"/dev/disk/by-id/{board}",
                "storage_serial": f"storage-{board}",
                "root_partuuid": f"partuuid-{board}",
            },
            "readback": {
                "scope": "full",
                "bytes_read": 1048576,
                "expected_sha256": "e" * 64,
                "actual_sha256": "e" * 64,
                "command": "sha256sum full readback",
            },
            "checks": checks,
        }
    )

negative_tests = []
for name in [
    "no-target-disk",
    "ambiguous-targets",
    "usb-target-without-override",
    "tampered-payload",
    "bad-signature",
    "expired-manifest",
    "wrong-board",
    "small-target",
    "rollback-floor-violation",
]:
    evidence = write_sha(f"negative/{name}.txt")
    negative_tests.append(
        {
            "name": name,
            "failure_code": f"expected-{name}",
            "status": "passed",
            "evidence": evidence[0],
            "evidence_sha256": evidence[1],
            "write_prevention": {"target_hash_unchanged": True},
        }
    )

lab = {
    "schema_version": "suderra.lab-evidence.v3",
    "version": "v9.9.9-alpha.1",
    "target": "pi-cm4-revpi-usb-installer",
    "generated_at": "2026-05-18T00:00:00Z",
    "lab_id": "contract-lab",
    "operator": "Contract Test",
    "station": {
        "station_id": "contract-station",
        "fixture_id": "contract-fixture",
        "operator_id": "contract",
        "trusted_key_fingerprint": "contract-key",
        "clock": "ntp-synchronized",
        "tool_versions": {"suderra-lab": "contract"},
    },
    "artifact_binding": {
        "version": "v9.9.9-alpha.1",
        "source_sha": source_sha,
        "source_run_id": "123456789",
        "release_assets_sha256": "f" * 64,
    },
    "devices": devices,
    "negative_tests": negative_tests,
}
(root / "lab.json").write_text(json.dumps(lab, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${ROOT}/lab.json" \
    --require-pass \
    --check-files \
    --expected-source-sha "${SOURCE_SHA}" \
    >/dev/null

MISMATCH_ROOT="${TMPDIR}/release-lab-input/v9.9.9-alpha.1/rpi4"
mkdir -p "${MISMATCH_ROOT}"
cp -a "${ROOT}/." "${MISMATCH_ROOT}/"
python3 - "${MISMATCH_ROOT}/lab.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["target"] = "pi-cm4-revpi-usb-installer"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${TOOL}" validate "${MISMATCH_ROOT}/lab.json" --require-pass --check-files 2>"${TMPDIR}/target.err"; then
    echo "ERROR: lab input accepted a target that does not match its evidence path" >&2
    exit 1
fi
if ! grep -q "path target" "${TMPDIR}/target.err"; then
    echo "ERROR: target path mismatch failure did not identify the path contract" >&2
    cat "${TMPDIR}/target.err" >&2
    exit 1
fi

python3 - "${ROOT}/lab.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["devices"] = [
    device for device in payload["devices"] if device["board"] != "revpi-connect-4"
]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${TOOL}" validate "${ROOT}/lab.json" --require-pass --check-files 2>"${TMPDIR}/missing.err"; then
    echo "ERROR: lab input accepted missing RevPi evidence" >&2
    exit 1
fi
if ! grep -q "revpi-connect-4" "${TMPDIR}/missing.err"; then
    echo "ERROR: missing board failure did not identify RevPi" >&2
    cat "${TMPDIR}/missing.err" >&2
    exit 1
fi
