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
EVIDENCE_CONTRACT="${PROJECT_ROOT}/scripts/evidence/evidence_contract.py"

python3 -m py_compile \
    "${EVIDENCE_CONTRACT}" \
    "${RUNTIME_VALIDATOR}" \
    "${RUNTIME_RUNNER}" \
    "${SCANNER_REPLAY}" \
    "${STATION_ACQUISITION}" \
    "${HSM_VALIDATOR}"
python3 "${EVIDENCE_CONTRACT}" validate >/dev/null
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
python3 - "${PROJECT_ROOT}" <<'PY'
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "evidence_contract",
    root / "scripts/evidence/evidence_contract.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
contract = module.load_contract(root / "ci/evidence-contract.yml")
runtime_checks = module.runtime_required_checks(contract)
scenario_to_checks = module.runtime_scenario_to_checks(contract)
covered = {check for checks in scenario_to_checks.values() for check in checks}
missing = set(runtime_checks) - covered
if missing:
    raise SystemExit(f"runtime checks are not mapped from scenarios: {sorted(missing)}")
if module.runtime_suite_targets_for("x86_64", contract) != ["qemu-x86_64-prod-ab"]:
    raise SystemExit("x86_64 runtime suite mapping must come from evidence contract")
policy = module.target_policy("x86_64", contract)
if policy.get("production_gate") is not True or policy.get("release_public") is not False:
    raise SystemExit("x86_64 must be a gated non-public production target in evidence contract")
if set(module.adapter_roles(contract)) != {
    "flash",
    "readback",
    "uart",
    "power",
    "storage",
    "tpm",
    "secure-boot",
    "rauc",
    "tamper",
}:
    raise SystemExit("hardware adapter roles must come from evidence contract")
PY
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

if python3 "${RUNTIME_VALIDATOR}" "${RUNTIME_ROOT}/production-runtime.json" \
    --require-pass \
    --profile production-candidate \
    2>"${TMPDIR}/runtime-v1.err"; then
    echo "ERROR: production-candidate accepted legacy production-runtime suite v1" >&2
    exit 1
fi
grep -q 'suderra.qemu-production-runtime-suite.v2' "${TMPDIR}/runtime-v1.err"

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

V2_RUNTIME_ROOT="${TMPDIR}/runtime-v2"
mkdir -p "${V2_RUNTIME_ROOT}"
python3 - "${V2_RUNTIME_ROOT}/production-runtime.json" "${SOURCE_SHA}" "${EXPECTED_IMAGE_SHA}" <<'PY'
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
guest_facts = {
    "secure_boot": {"enabled": True, "source": "ovmf"},
    "dm_verity": {"active": True, "table": "0 1 verity 1"},
    "rauc": {"available": True, "status": "active slot A"},
    "data_encryption": {
        "encrypted": True,
        "luks_mapper_state": {"mapper": "suderra-data", "open": True},
    },
    "anti_rollback": {"rollback_floor": "v9.9.9"},
}
items = []
for name, outcome, mutation in scenarios:
    scenario_dir = root / "logs" / name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    serial = scenario_dir / f"{name}.serial.log"
    serial.write_text(
        f"SUDERRA_PRODUCTION_RUNTIME_OUTCOME={outcome}\n"
        "SUDERRA_QEMU_SEMANTIC_JSON_BEGIN\n"
        f"{json.dumps(guest_facts, sort_keys=True)}\n"
        "SUDERRA_QEMU_SEMANTIC_JSON_END\n",
        encoding="utf-8",
    )
    qmp = scenario_dir / f"{name}.qmp.json"
    qmp.write_text(
        json.dumps(
            [{"QMP": {"version": "contract"}}, {"id": "suderra-production-runtime-quit", "return": {}}],
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    before = hashlib.sha256(f"{name}:before".encode()).hexdigest()
    after = hashlib.sha256(f"{name}:after".encode()).hexdigest()
    mutation_payload = {"type": "none"}
    if mutation != "none":
        artifact = scenario_dir / "mutation.bin"
        artifact.write_text(f"{name}:mutated\n", encoding="utf-8")
        artifact_after = hashlib.sha256(artifact.read_bytes()).hexdigest()
        mutation_payload = {
            "type": mutation,
            "target": "base-image",
            "before_sha256": before,
            "after_sha256": after,
            "artifact": {
                "role": mutation,
                "path": artifact.relative_to(root).as_posix(),
                "before_sha256": before,
                "after_sha256": artifact_after,
            },
        }
    items.append(
        {
            "name": name,
            "status": "passed",
            "expected_outcome": outcome,
            "observed_outcome": outcome,
            "command": f"tests/qemu/production-runtime-scenario.sh {name}",
            "started_at": "2026-05-21T00:00:00Z",
            "completed_at": "2026-05-21T00:00:01Z",
            "termination_class": "expected",
            "failure_class": "none",
            "qemu_argv": ["qemu-system-x86_64", "-qmp", "unix:qmp.sock,server=on,wait=off"],
            "termination": {
                "class": "qmp-quit",
                "reason": "contract fixture exited cleanly",
                "qmp_quit_sent": True,
                "qmp_quit_ack": True,
                "timeout": False,
            },
            "swtpm_state": {
                "path": "swtpm-state",
                "before_sha256": "d" * 64,
                "after_sha256": ("e" * 64 if name == "data-luks-swtpm" else "d" * 64),
            },
            "raw_evidence": {
                "serial_sha256": hashlib.sha256(serial.read_bytes()).hexdigest(),
                "qmp_events_sha256": hashlib.sha256(qmp.read_bytes()).hexdigest(),
            },
            "guest_facts": guest_facts,
            "mutation": mutation_payload,
            "logs": [
                {
                    "role": "serial",
                    "path": serial.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(serial.read_bytes()).hexdigest(),
                    "bytes": serial.stat().st_size,
                },
                {
                    "role": "qmp-events",
                    "path": qmp.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(qmp.read_bytes()).hexdigest(),
                    "bytes": qmp.stat().st_size,
                },
            ],
        }
    )
payload = {
    "schema_version": "suderra.qemu-production-runtime-suite.v2",
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
    "ovmf_enrollment": {
        "mode": "secure-boot-enrolled",
        "enrolled_vars_sha256": "c" * 64,
        "secure_boot_db_sha256": "f" * 64,
    },
    "qemu_version": "QEMU emulator version contract",
    "qemu_argv": ["qemu-system-x86_64", "-qmp", "unix:qmp.sock,server=on,wait=off"],
    "swtpm_state": "swtpm-state",
    "swtpm_state_sha256": "d" * 64,
    "swtpm_state_before_sha256": "d" * 64,
    "swtpm_state_after_sha256": "e" * 64,
    "scenarios": items,
}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "${RUNTIME_VALIDATOR}" "${V2_RUNTIME_ROOT}/production-runtime.json" \
    --check-files \
    --require-pass \
    --profile production-runtime \
    --expected-version "${VERSION}" \
    --expected-target "${TARGET}" \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-artifact-sha256 "${EXPECTED_IMAGE_SHA}" \
    >/dev/null

python3 - "${V2_RUNTIME_ROOT}/production-runtime.json" "${V2_RUNTIME_ROOT}/runtime-v2-replay.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
out = Path(sys.argv[2])
payload = json.loads(path.read_text(encoding="utf-8"))
scenario = payload["scenarios"][0]
serial_log = path.parent / scenario["logs"][0]["path"]
serial_log.write_text("SUDERRA_PRODUCTION_RUNTIME_OUTCOME=userspace-rejected\n", encoding="utf-8")
digest = hashlib.sha256(serial_log.read_bytes()).hexdigest()
scenario["logs"][0]["sha256"] = digest
scenario["logs"][0]["bytes"] = serial_log.stat().st_size
scenario["raw_evidence"]["serial_sha256"] = digest
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${RUNTIME_VALIDATOR}" "${V2_RUNTIME_ROOT}/runtime-v2-replay.json" \
    --check-files \
    --require-pass \
    --profile production-runtime \
    2>"${TMPDIR}/runtime-v2-replay.err"; then
    echo "ERROR: production-runtime v2 accepted an observed_outcome unsupported by raw logs" >&2
    exit 1
fi
grep -q "replayed serial evidence" "${TMPDIR}/runtime-v2-replay.err"

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
python3 - "${ACQ_PLAN}" "${VERSION}" "${SOURCE_SHA}" "${REGISTRY_SHA}" "${ARTIFACT_SHA}" <<'PY'
import json
import sys
from pathlib import Path

out, version, source_sha, registry_sha, artifact_sha = sys.argv[1:]
events = [
    ("flash", "flash-1", "1", {"target": "/dev/disk/by-id/test"}),
    ("readback", "readback-1", "2", {"bytes_read": 8, "sha256": artifact_sha}),
    ("uart", "uart-1", "3", {"boot_seen": True}),
    ("power", "power-1", "4", {"cycled": True, "transcript_sha256": "5" + "0" * 63}),
    ("storage", "storage-1", "6", {"by_id": "/dev/disk/by-id/test"}),
    ("tpm", "tpm-1", "7", {"present": True, "manufacturer": "contract"}),
    ("secure-boot", "secure-boot-1", "8", {"enabled": True, "enforced": True}),
    ("rauc", "rauc-1", "9", {"rollback_verified": True, "mark_good_verified": True}),
    ("tamper", "tamper-1", "a", {"dm_verity_rejected": True, "boot_tamper_rejected": True}),
]
payload = {
    "version": version,
    "target": "revpi4",
    "source_sha": source_sha,
    "source_run_id": "123456789",
    "station_id": "station-1",
    "registry_sha256": registry_sha,
    "artifact_sha256": artifact_sha,
    "artifact_bytes": 8,
    "events": [
        {
            "role": role,
            "adapter_id": adapter,
            "adapter_version": "1",
            "adapter_binary_sha256": prefix + "0" * 63,
            "command": ["true"],
            "measured": measured,
        }
        for role, adapter, prefix, measured in events
    ],
}
Path(out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "${STATION_ACQUISITION}" create \
    --plan "${ACQ_PLAN}" \
    --output "${TMPDIR}/station-acquisition.json" \
    >/dev/null
python3 "${STATION_ACQUISITION}" validate "${TMPDIR}/station-acquisition.json" --check-files >/dev/null
python3 "${STATION_ACQUISITION}" validate "${TMPDIR}/station-acquisition.json" \
    --check-files \
    --expected-version "${VERSION}" \
    --expected-target revpi4 \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-source-run-id 123456789 \
    --expected-artifact-sha256 "${ARTIFACT_SHA}" \
    --expected-artifact-bytes 8 \
    --expected-registry-sha256 "${REGISTRY_SHA}" \
    >/dev/null
if python3 "${STATION_ACQUISITION}" validate "${TMPDIR}/station-acquisition.json" \
    --expected-target x86_64 \
    2>"${TMPDIR}/station-target.err"; then
    echo "ERROR: station acquisition accepted the wrong expected target" >&2
    exit 1
fi
grep -q "expected target" "${TMPDIR}/station-target.err"
