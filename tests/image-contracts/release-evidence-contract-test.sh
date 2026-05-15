#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/release-evidence.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

EVIDENCE="${TMPDIR}/release-evidence/v9.9.9/qemu-x86_64/evidence.json"

python3 "${TOOL}" schema >/dev/null
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
for rel in data["qemu"]["logs"]:
    write_text(rel, "synthetic QEMU serial and journal evidence\n")

evidence_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${TOOL}" validate "${EVIDENCE}" --require-pass --check-files >/dev/null

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
