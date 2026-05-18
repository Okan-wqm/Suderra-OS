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

python3 - "${ROOT}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])


def write(rel: str, payload: str = "synthetic lab evidence\n") -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return rel


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
            "evidence": write(f"hardware/{board}/{name}.txt"),
        }
        for name in required_checks
    }
    if board == "revpi-connect-4":
        checks["revpi-io"] = {
            "status": "passed",
            "evidence": write(f"hardware/{board}/revpi-io.txt"),
        }
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
            "logs": [write(f"hardware/{board}/serial.log")],
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
    negative_tests.append(
        {
            "name": name,
            "status": "passed",
            "evidence": write(f"negative/{name}.txt"),
        }
    )

lab = {
    "schema_version": "suderra.lab-evidence.v1",
    "version": "v9.9.9-alpha.1",
    "target": "pi-cm4-revpi-usb-installer",
    "generated_at": "2026-05-18T00:00:00Z",
    "lab_id": "contract-lab",
    "operator": "Contract Test",
    "devices": devices,
    "negative_tests": negative_tests,
}
(root / "lab.json").write_text(json.dumps(lab, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${ROOT}/lab.json" --require-pass --check-files >/dev/null

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
