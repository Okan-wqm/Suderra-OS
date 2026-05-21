#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

RUNTIME_VALIDATOR="${PROJECT_ROOT}/scripts/evidence/validate-production-runtime-suite.py"
RUNTIME_RUNNER="${PROJECT_ROOT}/tests/qemu/production-runtime.py"
SCANNER_REPLAY="${PROJECT_ROOT}/scripts/evidence/security-raw-replay.py"
STATION_ACQUISITION="${PROJECT_ROOT}/scripts/evidence/station-acquisition.py"
HSM_VALIDATOR="${PROJECT_ROOT}/scripts/evidence/validate-hsm-signing-evidence.py"

python3 -m py_compile \
    "${RUNTIME_VALIDATOR}" \
    "${RUNTIME_RUNNER}" \
    "${SCANNER_REPLAY}" \
    "${STATION_ACQUISITION}" \
    "${HSM_VALIDATOR}"
"${RUNTIME_VALIDATOR}" --help >/dev/null
"${RUNTIME_RUNNER}" --help >/dev/null
"${SCANNER_REPLAY}" --help >/dev/null
"${STATION_ACQUISITION}" --help >/dev/null

VERSION="v9.9.9"
TARGET="qemu-x86_64-prod-ab"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
EXPECTED_IMAGE_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REGISTRY_SHA="6666666666666666666666666666666666666666666666666666666666666666"
ARTIFACT_SHA="7777777777777777777777777777777777777777777777777777777777777777"
RUNTIME_ROOT="${TMPDIR}/runtime"
mkdir -p "${RUNTIME_ROOT}/logs"

python3 - "${RUNTIME_ROOT}/production-runtime.json" "${SOURCE_SHA}" "${EXPECTED_IMAGE_SHA}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
source_sha = sys.argv[2]
image_sha = sys.argv[3]
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
    log = root / "logs" / f"{name}.serial.log"
    log.write_text(f"{name} {outcome}\n", encoding="utf-8")
    before = hashlib.sha256(f"{name}:before".encode()).hexdigest()
    after = hashlib.sha256(f"{name}:after".encode()).hexdigest()
    items.append(
        {
            "name": name,
            "status": "passed",
            "expected_outcome": outcome,
            "observed_outcome": outcome,
            "command": f"run {name}",
            "started_at": "2026-05-21T00:00:00Z",
            "completed_at": "2026-05-21T00:00:01Z",
            "termination_class": "expected",
            "failure_class": "none",
            "mutation": {
                "type": mutation,
                "target": "base-image" if mutation != "none" else "none",
                "before_sha256": before,
                "after_sha256": after,
            },
            "logs": [
                {
                    "role": "serial",
                    "path": log.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                    "bytes": log.stat().st_size,
                }
            ],
        }
    )
payload = {
    "schema_version": "suderra.qemu-production-runtime-suite.v1",
    "version": "v9.9.9",
    "target": "qemu-x86_64-prod-ab",
    "source_sha": source_sha,
    "generated_at": "2026-05-21T00:00:00Z",
    "image": "disk.img",
    "image_sha256": image_sha,
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

python3 "${RUNTIME_VALIDATOR}" "${RUNTIME_ROOT}/production-runtime.json" \
    --check-files \
    --require-pass \
    --expected-version "${VERSION}" \
    --expected-target "${TARGET}" \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-artifact-sha256 "${EXPECTED_IMAGE_SHA}" \
    >/dev/null

python3 - "${RUNTIME_ROOT}/production-runtime.json" "${TMPDIR}/missing-runtime.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
payload["scenarios"] = [item for item in payload["scenarios"] if item["name"] != "data-luks-swtpm"]
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${RUNTIME_VALIDATOR}" "${TMPDIR}/missing-runtime.json" --require-pass 2>"${TMPDIR}/runtime.err"; then
    echo "ERROR: production-runtime suite accepted missing required scenario" >&2
    exit 1
fi
grep -q "data-luks-swtpm" "${TMPDIR}/runtime.err"

SECURITY_ROOT="${TMPDIR}/release-security/${VERSION}"
mkdir -p "${SECURITY_ROOT}"
cat >"${SECURITY_ROOT}/trivy-raw.json" <<'JSON'
{"Results":[{"Target":"rootfs","Vulnerabilities":[]}]}
JSON
RAW_SHA="$(sha256sum "${SECURITY_ROOT}/trivy-raw.json" | awk '{print $1}')"
RAW_BYTES="$(wc -c < "${SECURITY_ROOT}/trivy-raw.json" | awk '{print $1}')"
cat >"${SECURITY_ROOT}/trivy.json" <<JSON
{
  "schema_version": "suderra.release-security-report.v2",
  "version": "${VERSION}",
  "source_sha": "${SOURCE_SHA}",
  "source_run_id": "123456789",
  "scan": "trivy",
  "status": "passed",
  "generated_at": "2026-05-21T00:00:00Z",
  "tool": "trivy",
  "tool_version": "0.70.0",
  "scanner_db": {
    "type": "trivy-db",
    "version": "2026-05-21",
    "created_at": "2026-05-21T00:00:00Z",
    "digest": "sha256:${RAW_SHA}",
    "auto_update_disabled": true
  },
  "subjects": [
    {
      "name": "suderra-qemu.img.xz",
      "role": "release-image",
      "path": "suderra-qemu.img.xz",
      "sha256": "e${RAW_SHA#?}",
      "bytes": 42,
      "scan_mode": "rootfs"
    }
  ],
  "raw": {
    "path": "${VERSION}/trivy-raw.json",
    "sha256": "${RAW_SHA}",
    "bytes": ${RAW_BYTES}
  },
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0
  }
}
JSON
python3 "${SCANNER_REPLAY}" "${SECURITY_ROOT}/trivy.json" --check-files --raw-root "${TMPDIR}/release-security" >/dev/null

python3 - "${SECURITY_ROOT}/trivy-raw.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["Results"][0]["Vulnerabilities"] = [{"Severity": "HIGH", "VulnerabilityID": "CVE-TEST"}]
path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${SCANNER_REPLAY}" "${SECURITY_ROOT}/trivy.json" --check-files --raw-root "${TMPDIR}/release-security" \
    2>"${TMPDIR}/scanner.err"; then
    echo "ERROR: scanner replay accepted tampered high finding" >&2
    exit 1
fi
grep -q "sha256 mismatch\\|high/critical\\|severity_counts" "${TMPDIR}/scanner.err"

ACQ_PLAN="${TMPDIR}/station-plan.json"
cat >"${ACQ_PLAN}" <<JSON
{
  "version": "${VERSION}",
  "target": "revpi4",
  "source_sha": "${SOURCE_SHA}",
  "source_run_id": "123456789",
  "station_id": "station-1",
  "registry_sha256": "${REGISTRY_SHA}",
  "artifact_sha256": "${ARTIFACT_SHA}",
  "artifact_bytes": 8,
  "events": [
    {"role": "flash", "adapter_id": "flash-1", "adapter_version": "1", "adapter_binary_sha256": "1$(printf %063d 0)", "command": ["true"], "measured": {"target": "/dev/disk/by-id/test"}},
    {"role": "readback", "adapter_id": "readback-1", "adapter_version": "1", "adapter_binary_sha256": "2$(printf %063d 0)", "command": ["true"], "measured": {"bytes_read": 8}},
    {"role": "uart", "adapter_id": "uart-1", "adapter_version": "1", "adapter_binary_sha256": "3$(printf %063d 0)", "command": ["true"], "measured": {"boot_seen": true}},
    {"role": "power", "adapter_id": "power-1", "adapter_version": "1", "adapter_binary_sha256": "4$(printf %063d 0)", "command": ["true"], "measured": {"cycled": true}},
    {"role": "storage", "adapter_id": "storage-1", "adapter_version": "1", "adapter_binary_sha256": "5$(printf %063d 0)", "command": ["true"], "measured": {"by_id": "/dev/disk/by-id/test"}}
  ]
}
JSON
python3 "${STATION_ACQUISITION}" create \
    --plan "${ACQ_PLAN}" \
    --output "${TMPDIR}/station-acquisition.json" \
    >/dev/null
python3 "${STATION_ACQUISITION}" validate "${TMPDIR}/station-acquisition.json" --check-files >/dev/null
