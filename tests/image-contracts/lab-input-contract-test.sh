#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
VALIDATOR="${PROJECT_ROOT}/scripts/evidence/validate-lab-input.py"
COLLECTOR="${PROJECT_ROOT}/scripts/evidence/suderra-lab.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
TARGET="pi-cm4-revpi-usb-installer"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
SOURCE_RUN_ID="123456789"
ROOT="${TMPDIR}/release-lab-input/${VERSION}/${TARGET}"
SPEC="${TMPDIR}/lab-spec.json"
ARTIFACT="${TMPDIR}/artifact.img"
KEY="${TMPDIR}/station.key"

python3 -m py_compile "${VALIDATOR}" "${COLLECTOR}"
"${COLLECTOR}" --help >/dev/null
openssl genpkey -algorithm Ed25519 -out "${KEY}" >/dev/null 2>&1
printf 'contract artifact bytes\n' >"${ARTIFACT}"

python3 - "${PROJECT_ROOT}" "${TMPDIR}" "${SPEC}" "${ARTIFACT}" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

project_root = Path(sys.argv[1])
tmp = Path(sys.argv[2])
spec_path = Path(sys.argv[3])
artifact = Path(sys.argv[4])
validator_path = project_root / "scripts" / "evidence" / "validate-lab-input.py"
spec = importlib.util.spec_from_file_location("validate_lab_input", validator_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

captures = tmp / "captures"
captures.mkdir()


def write(rel: str, payload: str) -> str:
    path = captures / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return path.relative_to(tmp).as_posix()


boards = [
    "raspberry-pi-4-model-b",
    "cm4-lite-sd",
    "cm4-emmc-io-board",
    "revpi-connect-4",
]
devices = []
for board in boards:
    check_names = list(module.REQUIRED_LAB_CHECKS)
    if board == "revpi-connect-4":
        check_names.append("revpi-io")
    checks = {
        name: {
            "source": write(f"hardware/{board}/{name}.txt", f"{board} {name} evidence\n"),
            "command": f"collect {name}",
            "expected": "passed",
            "observed": "passed",
            "parsed_result": "passed",
        }
        for name in check_names
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
            "logs": [
                {
                    "source": write(f"hardware/{board}/serial.log", f"{board} serial\n"),
                    "path": f"hardware/{board}/serial.log",
                }
            ],
            "device_identity": {
                "model": board,
                "compatible": f"suderra,{board}",
                "storage_by_id": f"/dev/disk/by-id/{board}",
                "storage_serial": f"storage-{board}",
                "root_partuuid": f"partuuid-{board}",
            },
            "readback": {
                "source": artifact.as_posix(),
                "command": "sha256sum full readback",
            },
            "checks": checks,
        }
    )

negative_tests = []
for name in module.REQUIRED_USB_NEGATIVE_TESTS:
    negative_tests.append(
        {
            "name": name,
            "failure_code": f"expected-{name}",
            "status": "passed",
            "command": f"flash negative {name}",
            "expected": "closed-fail",
            "observed": "closed-fail",
            "exit_code": 1,
            "source": write(f"negative/{name}.txt", f"{name} closed-fail evidence\n"),
            "write_prevention": {
                "target_hash_unchanged": True,
                "before_sha256": "d" * 64,
                "after_sha256": "d" * 64,
                "bytes_checked": artifact.stat().st_size,
            },
        }
    )

payload = {
    "lab_id": "contract-lab",
    "operator": "Contract Test",
    "station": {
        "station_id": "contract-station",
        "fixture_id": "contract-fixture",
        "operator_id": "contract",
        "trusted_key_fingerprint": "will-be-derived",
        "clock": "ntp-synchronized",
        "tool_versions": {"contract-fixture": "1"},
    },
    "devices": devices,
    "negative_tests": negative_tests,
}
spec_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${COLLECTOR}" collect \
    --version "${VERSION}" \
    --target "${TARGET}" \
    --source-sha "${SOURCE_SHA}" \
    --source-run-id "${SOURCE_RUN_ID}" \
    --artifact "${ARTIFACT}" \
    --spec "${SPEC}" \
    --signing-key "${KEY}" \
    --output-root "${TMPDIR}/release-lab-input" \
    >/dev/null

python3 "${VALIDATOR}" validate "${ROOT}/lab.json" \
    --require-pass \
    --check-files \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-source-run-id "${SOURCE_RUN_ID}" \
    >/dev/null

python3 - "${ROOT}/lab.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["station_bundle"]["schema_version"] == "suderra.lab-station-bundle.v1"
assert payload["station_signature"]["algorithm"] == "openssl-pkeyutl-ed25519-raw"
assert payload["station"]["trusted_key_fingerprint"] == payload["station_signature"]["public_key_sha256"]
assert payload["artifact_binding"]["build_artifact_bytes"] > 0
for device in payload["devices"]:
    assert device["readback"]["expected_sha256"] == payload["artifact_binding"]["build_artifact_sha256"]
    assert device["readback"]["bytes_read"] == payload["artifact_binding"]["build_artifact_bytes"]
PY

UNSIGNED_ROOT="${TMPDIR}/unsigned/${VERSION}/${TARGET}"
mkdir -p "${UNSIGNED_ROOT}"
cp -a "${ROOT}/." "${UNSIGNED_ROOT}/"
python3 - "${UNSIGNED_ROOT}/lab.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload.pop("station_signature")
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${VALIDATOR}" validate "${UNSIGNED_ROOT}/lab.json" --require-pass --check-files \
    2>"${TMPDIR}/unsigned.err"; then
    echo "ERROR: lab input accepted unsigned station evidence" >&2
    exit 1
fi
grep -q "station_signature" "${TMPDIR}/unsigned.err" || {
    echo "ERROR: unsigned station evidence failure did not mention station_signature" >&2
    cat "${TMPDIR}/unsigned.err" >&2
    exit 1
}

TAMPER_ROOT="${TMPDIR}/tamper/${VERSION}/${TARGET}"
mkdir -p "${TAMPER_ROOT}"
cp -a "${ROOT}/." "${TAMPER_ROOT}/"
python3 - "${TAMPER_ROOT}/lab.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["devices"][0]["serial"] = "tampered-after-signing"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${VALIDATOR}" validate "${TAMPER_ROOT}/lab.json" --require-pass --check-files \
    2>"${TMPDIR}/tamper.err"; then
    echo "ERROR: lab input accepted tampered signed payload" >&2
    exit 1
fi
grep -q "lab_payload_sha256" "${TMPDIR}/tamper.err" || {
    echo "ERROR: tampered lab payload failure did not mention lab_payload_sha256" >&2
    cat "${TMPDIR}/tamper.err" >&2
    exit 1
}

MISMATCH_ROOT="${TMPDIR}/release-lab-input/${VERSION}/rpi4"
mkdir -p "${MISMATCH_ROOT}"
cp -a "${ROOT}/." "${MISMATCH_ROOT}/"
if python3 "${VALIDATOR}" validate "${MISMATCH_ROOT}/lab.json" --require-pass --check-files \
    2>"${TMPDIR}/target.err"; then
    echo "ERROR: lab input accepted a target that does not match its evidence path" >&2
    exit 1
fi
grep -q "path target" "${TMPDIR}/target.err" || {
    echo "ERROR: target path mismatch failure did not identify the path contract" >&2
    cat "${TMPDIR}/target.err" >&2
    exit 1
}

MISSING_ROOT="${TMPDIR}/missing/${VERSION}/${TARGET}"
mkdir -p "${MISSING_ROOT}"
cp -a "${ROOT}/." "${MISSING_ROOT}/"
python3 - "${MISSING_ROOT}/lab.json" <<'PY'
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
if python3 "${VALIDATOR}" validate "${MISSING_ROOT}/lab.json" --require-pass --check-files \
    2>"${TMPDIR}/missing.err"; then
    echo "ERROR: lab input accepted missing RevPi evidence" >&2
    exit 1
fi
grep -q "revpi-connect-4" "${TMPDIR}/missing.err" || {
    echo "ERROR: missing board failure did not identify RevPi" >&2
    cat "${TMPDIR}/missing.err" >&2
    exit 1
}
