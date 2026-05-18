#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/release-evidence.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

EVIDENCE="${TMPDIR}/release-evidence/v9.9.9/qemu-x86_64/evidence.json"

python3 "${TOOL}" schema > "${TMPDIR}/schema.json"
python3 - "${TMPDIR}/schema.json" <<'PY'
import json
import sys

schema = json.loads(open(sys.argv[1], encoding="utf-8").read())
boards = schema["required_hardware_boards_by_target"]
expected = {
    "raspberry-pi-4-model-b",
    "cm4-lite-sd",
    "cm4-emmc-io-board",
    "revpi-connect-4",
}
actual = set(boards["pi-cm4-revpi-usb-installer"])
if actual != expected:
    raise SystemExit(f"USB installer hardware coverage mismatch: {sorted(actual)}")
PY
python3 "${TOOL}" generate \
    --version v9.9.9 \
    --target qemu-x86_64 \
    --output "${EVIDENCE}" \
    >/dev/null

python3 "${TOOL}" validate "${EVIDENCE}" >/dev/null

if python3 "${TOOL}" validate "${EVIDENCE}" --require-pass 2>"${TMPDIR}/blocked.err"; then
    echo "ERROR: generated blocked evidence unexpectedly passed release-ready validation" >&2
    exit 1
fi

if ! grep -q "release-ready evidence" "${TMPDIR}/blocked.err"; then
    echo "ERROR: release-ready failure did not explain missing evidence" >&2
    cat "${TMPDIR}/blocked.err" >&2
    exit 1
fi

python3 - "${EVIDENCE}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
root = evidence_path.parent
data = json.loads(evidence_path.read_text(encoding="utf-8"))


def write_bytes(rel: str, payload: bytes) -> tuple[str, int]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def write_text(rel: str, payload: str) -> tuple[str, int]:
    return write_bytes(rel, payload.encode("utf-8"))

data["source"]["git_commit"] = "0123456789abcdef0123456789abcdef01234567"
data["source"]["dirty"] = False
data["source"]["ci"]["run_id"] = "123456789"
data["source"]["ci"]["run_attempt"] = "1"

for artifact in data["artifacts"]:
    digest, size = write_bytes(artifact["path"], b"synthetic release artifact\n")
    artifact["sha256"] = digest
    artifact["bytes"] = size
    artifact["signature"]["verified"] = True
    artifact["provenance"]["verified"] = True
    write_text(artifact["signature"]["path"], "synthetic cosign signature\n")
    write_text(artifact["signature"]["certificate"], "synthetic cosign certificate\n")
    write_text(artifact["provenance"]["path"], "synthetic provenance\n")

asset_manifest = {
    "schema_version": "suderra.release-assets.v1",
    "version": data["version"],
    "generated_at": data["generated_at"],
    "source": data["source"],
    "matrix_sha256": "0" * 64,
    "buildroot_index_sha": "160000 commit buildroot " + "1" * 40,
    "files": [
        {
            "name": artifact["name"],
            "role": artifact["role"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
        }
        for artifact in data["artifacts"]
    ],
}
data["asset_manifest"]["sha256"], _ = write_text(
    data["asset_manifest"]["path"],
    json.dumps(asset_manifest, sort_keys=True) + "\n",
)
data["asset_manifest"]["verified"] = True

sbom_payload = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"name": "busybox", "version": "contract"}],
}
sbom_digest, _ = write_text(
    data["sbom"]["path"],
    json.dumps(sbom_payload, sort_keys=True) + "\n",
)
data["sbom"]["sha256"] = sbom_digest
data["sbom"]["component_count"] = 1
data["sbom"]["signature_verified"] = True
data["vex"] = {
    "status": "present",
    "path": "vex/suderra.vex.json",
    "sha256": None,
    "signature_verified": True,
}
data["vex"]["sha256"], _ = write_text(
    data["vex"]["path"],
    json.dumps({"vex": "contract-fixture", "statements": []}, sort_keys=True) + "\n",
)
data["reproducibility"]["status"] = "passed"
data["reproducibility"]["comparison"] = "independent rebuild matched release artifact"
data["reproducibility"]["logs"] = ["logs/reproducibility.log"]

for scan in data["security_scans"]:
    scan["status"] = "passed"
    scan["report"] = f"security/{scan['name']}.json"

for name, check in data["machine_verification"].items():
    check["status"] = "passed"
    check["logs"] = [f"machine/{name}.log"]

data["governance"]["retention_years"] = 7
data["governance"]["approval_model"] = "single-alpha-owner"
for name, check in data["governance"]["checks"].items():
    check["status"] = "passed"
    check["evidence"] = f"governance/{name}.json"

data["qemu"]["status"] = "passed"
data["qemu"]["logs"] = ["qemu/boot.log"]
data["qemu"]["checks"] = [
    "boot",
    "systemd",
    "zero-failed-units",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
]

data["approvals"] = [
    {
        "role": "release-owner",
        "name": "Contract Test",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-1",
    }
]
data["release_decision"] = {
    "status": "approved",
    "decided_by": "Contract Test",
    "decided_at": "2026-05-13T00:00:00Z",
    "rationale": "Synthetic contract fixture.",
}

for rel in data["reproducibility"]["logs"]:
    write_text(rel, "synthetic reproducibility transcript\n")
for scan in data["security_scans"]:
    write_text(scan["report"], json.dumps({"scan": scan["name"], "status": "passed"}) + "\n")
for check in data["machine_verification"].values():
    for rel in check["logs"]:
        write_text(rel, "synthetic machine verification transcript\n")
for name, check in data["governance"]["checks"].items():
    payload = {"status": "passed"}
    if name == "policy_validation":
        payload["schema_version"] = "suderra.github-governance-validation.v1"
    write_text(check["evidence"], json.dumps(payload, sort_keys=True) + "\n")
for rel in data["qemu"]["logs"]:
    write_text(rel, "synthetic QEMU serial and journal evidence\n")

evidence_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${EVIDENCE}" --require-pass --check-files >/dev/null

if python3 "${TOOL}" validate "${EVIDENCE}" --release-tier alpha --require-pass --check-files 2>"${TMPDIR}/tier.err"; then
    echo "ERROR: GA evidence unexpectedly validated with alpha release tier" >&2
    exit 1
fi
if ! grep -q "release tier must be production" "${TMPDIR}/tier.err"; then
    echo "ERROR: release tier mismatch did not fail closed" >&2
    cat "${TMPDIR}/tier.err" >&2
    exit 1
fi

REQUIRED_BYPASS="${TMPDIR}/release-evidence/v9.9.9/qemu-x86_64-required-bypass/evidence.json"
mkdir -p "$(dirname "${REQUIRED_BYPASS}")"
cp "${EVIDENCE}" "${REQUIRED_BYPASS}"
python3 - "${REQUIRED_BYPASS}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["qemu"]["required"] = False
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate "${REQUIRED_BYPASS}" --require-pass --check-files 2>"${TMPDIR}/required.err"; then
    echo "ERROR: release evidence accepted a matrix-required QEMU bypass" >&2
    exit 1
fi
if ! grep -q "matrix-derived requirement" "${TMPDIR}/required.err"; then
    echo "ERROR: required-gate bypass failure did not cite matrix-derived requirement" >&2
    cat "${TMPDIR}/required.err" >&2
    exit 1
fi

ALPHA="${TMPDIR}/release-evidence/v9.9.9-alpha.1/qemu-x86_64/evidence.json"
python3 "${TOOL}" generate \
    --version v9.9.9-alpha.1 \
    --target qemu-x86_64 \
    --output "${ALPHA}" \
    >/dev/null

python3 - "${ALPHA}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
root = evidence_path.parent
data = json.loads(evidence_path.read_text(encoding="utf-8"))


def write_text(rel: str, payload: str) -> tuple[str, int]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = payload.encode("utf-8")
    path.write_bytes(payload_bytes)
    return hashlib.sha256(payload_bytes).hexdigest(), len(payload_bytes)


data["source"]["git_commit"] = "0123456789abcdef0123456789abcdef01234567"
data["source"]["dirty"] = False
data["source"]["ci"]["run_id"] = "123456789"
data["source"]["ci"]["run_attempt"] = "1"

for artifact in data["artifacts"]:
    digest, size = write_text(artifact["path"], "alpha image artifact\n")
    artifact["sha256"] = digest
    artifact["bytes"] = size
    artifact["signature"]["verified"] = True
    artifact["provenance"]["verified"] = True
    write_text(artifact["signature"]["path"], "synthetic alpha cosign signature\n")
    write_text(artifact["signature"]["certificate"], "synthetic alpha cosign certificate\n")
    write_text(artifact["provenance"]["path"], "synthetic alpha provenance\n")

asset_manifest = {
    "schema_version": "suderra.release-assets.v1",
    "version": data["version"],
    "generated_at": data["generated_at"],
    "source": data["source"],
    "matrix_sha256": "0" * 64,
    "buildroot_index_sha": "160000 commit buildroot " + "1" * 40,
    "files": [
        {
            "name": artifact["name"],
            "role": artifact["role"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
        }
        for artifact in data["artifacts"]
    ],
}
data["asset_manifest"]["sha256"], _ = write_text(
    data["asset_manifest"]["path"],
    json.dumps(asset_manifest, sort_keys=True) + "\n",
)
data["asset_manifest"]["verified"] = True

sbom_payload = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"name": "busybox", "version": "alpha"}],
}
data["sbom"]["sha256"], _ = write_text(
    data["sbom"]["path"],
    json.dumps(sbom_payload, sort_keys=True) + "\n",
)
data["sbom"]["component_count"] = 1
data["sbom"]["signature_verified"] = True
data["vex"]["status"] = "not_collected"
data["reproducibility"]["status"] = "passed"
data["reproducibility"]["comparison"] = "single alpha candidate build accepted with residual risk"
data["reproducibility"]["logs"] = ["logs/reproducibility.log"]

for scan in data["security_scans"]:
    scan["status"] = "passed"
    scan["report"] = f"security/{scan['name']}.json"

for name, check in data["machine_verification"].items():
    check["status"] = "passed"
    check["logs"] = [f"machine/{name}.log"]

data["governance"]["retention_years"] = 7
data["governance"]["approval_model"] = "single-alpha-owner"
for name, check in data["governance"]["checks"].items():
    check["status"] = "passed"
    check["evidence"] = f"governance/{name}.json"

data["qemu"]["status"] = "passed"
data["qemu"]["logs"] = ["qemu/boot.log"]
data["qemu"]["checks"] = [
    "boot",
    "systemd",
    "zero-failed-units",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
]
data["approvals"] = [
    {
        "role": "release-owner",
        "name": "Contract Test",
        "approved_at": "2026-05-13T00:00:00Z",
        "ticket": "TEST-ALPHA",
    }
]
data["residual_risk"] = {
    "status": "accepted",
    "items": [
        {
            "id": "RR-ALPHA-001",
            "severity": "high",
            "description": "Alpha evidence intentionally lacks production signing controls.",
            "mitigation": "Keep release draft/prerelease and block GA promotion.",
            "owner": "release-owner@example.com",
            "ticket": "TEST-ALPHA",
        }
    ],
    "accepted_by": "release-owner@example.com",
    "accepted_at": "2026-05-13T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z",
}
data["release_decision"] = {
    "status": "approved_with_residual_risk",
    "decided_by": "Contract Test",
    "decided_at": "2026-05-13T00:00:00Z",
    "rationale": "Synthetic alpha contract fixture.",
}

for rel in data["reproducibility"]["logs"]:
    write_text(rel, "synthetic alpha reproducibility transcript\n")
for scan in data["security_scans"]:
    write_text(scan["report"], json.dumps({"scan": scan["name"], "status": "passed"}) + "\n")
for check in data["machine_verification"].values():
    for rel in check["logs"]:
        write_text(rel, "synthetic alpha machine verification transcript\n")
for name, check in data["governance"]["checks"].items():
    payload = {"status": "passed"}
    if name == "policy_validation":
        payload["schema_version"] = "suderra.github-governance-validation.v1"
    write_text(check["evidence"], json.dumps(payload, sort_keys=True) + "\n")
for rel in data["qemu"]["logs"]:
    write_text(rel, "synthetic QEMU alpha evidence\n")

evidence_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${ALPHA}" --release-tier alpha --require-pass --check-files >/dev/null

BROKEN="${TMPDIR}/release-evidence/v9.9.9/wrong-target/evidence.json"
mkdir -p "$(dirname "${BROKEN}")"
cp "${EVIDENCE}" "${BROKEN}"
if python3 "${TOOL}" validate "${BROKEN}" 2>"${TMPDIR}/path.err"; then
    echo "ERROR: evidence in the wrong target directory unexpectedly validated" >&2
    exit 1
fi

if ! grep -q "target directory" "${TMPDIR}/path.err"; then
    echo "ERROR: path contract failure did not mention target directory mismatch" >&2
    cat "${TMPDIR}/path.err" >&2
    exit 1
fi
