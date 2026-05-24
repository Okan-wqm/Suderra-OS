#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TOOL="${PROJECT_ROOT}/scripts/evidence/operator-evidence-ingress.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-rc.1"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
RUN_ID="123456789"
RUN_ATTEMPT="1"
BUNDLE_ROOT="${TMPDIR}/bundle"
STAGED_ROOT="${TMPDIR}/staged"

python3 - "${BUNDLE_ROOT}" "${VERSION}" "${SOURCE_SHA}" "${RUN_ID}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
version = sys.argv[2]
source_sha = sys.argv[3]
run_id = sys.argv[4]
targets = ("qemu-x86_64", "rpi4", "pi-cm4-revpi-usb-installer", "revpi4")

def write(rel: str, payload: dict) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

write(
    f"release-governance/{version}/audit-log.json",
    {
        "schema_version": "suderra.audit-log-snapshot.v1",
        "status": "collected",
        "events_sha256": "a" * 64,
        "unapproved_governance_changes": False,
    },
)
write(
    f"release-governance/{version}/station-registry.json",
    {"schema_version": "suderra.lab-station-registry.v1", "stations": []},
)
write(f"release-lab-input/{version}/qemu-x86_64/qemu.json", {"schema_version": "suderra.qemu-acceptance.v4"})
for target in ("rpi4", "pi-cm4-revpi-usb-installer", "revpi4"):
    write(f"release-lab-input/{version}/{target}/lab.json", {"schema_version": "suderra.lab-evidence.v3"})
for target in targets:
    write(
        f"release-approvals/{version}/{target}.json",
        {
            "schema_version": "suderra.release-approval.v2",
            "version": version,
            "target": target,
            "source_sha": source_sha,
        },
    )
    write(
        f"release-reproducibility/{version}/{target}.json",
        {
            "schema_version": "suderra.reproducibility.v1",
            "version": version,
            "target": target,
            "source_sha": source_sha,
            "source_run_id": run_id,
        },
    )
PY

mkdir -p "${STAGED_ROOT}"
( cd "${BUNDLE_ROOT}" && tar -czf "${TMPDIR}/operator-evidence.tar.gz" . )
python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence.tar.gz" \
    --output-root "${STAGED_ROOT}" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "${RUN_ID}" \
    --source-image-build-run-attempt "${RUN_ATTEMPT}" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    >/dev/null

python3 "${TOOL}" validate \
    "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --input-root "${STAGED_ROOT}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-source-image-build-run-id "${RUN_ID}" \
    --expected-source-image-build-run-attempt "${RUN_ATTEMPT}" \
    >/dev/null

cp "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    "${TMPDIR}/missing-required-record.json"
python3 - "${TMPDIR}/missing-required-record.json" "${VERSION}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
missing = f"release-governance/{version}/station-registry.json"
payload["files"] = [item for item in payload["files"] if item.get("path") != missing]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/missing-required-record.json" \
    2>"${TMPDIR}/missing-record.err"; then
    echo "ERROR: operator evidence ingress accepted a missing required file record" >&2
    exit 1
fi
grep -q "missing required file records" "${TMPDIR}/missing-record.err"

SCHEMA_ROOT="${TMPDIR}/bad-schema-root"
cp -a "${STAGED_ROOT}" "${SCHEMA_ROOT}"
python3 - "${SCHEMA_ROOT}/release-lab-input/${VERSION}/qemu-x86_64/qemu.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["schema_version"] = "suderra.qemu-acceptance.v3"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${SCHEMA_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --input-root "${SCHEMA_ROOT}" \
    2>"${TMPDIR}/schema.err"; then
    echo "ERROR: operator evidence ingress accepted malformed required schema versions" >&2
    exit 1
fi
grep -q "schema_version" "${TMPDIR}/schema.err"

if python3 "${TOOL}" validate \
    "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --input-root "${STAGED_ROOT}" \
    --expected-source-image-build-run-id "222222222" \
    2>"${TMPDIR}/wrong-run.err"; then
    echo "ERROR: operator evidence ingress accepted the wrong Image Build run" >&2
    exit 1
fi
grep -q "source_image_build_run_id" "${TMPDIR}/wrong-run.err"

rm "${STAGED_ROOT}/release-governance/${VERSION}/station-registry.json"
if python3 "${TOOL}" validate \
    "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --input-root "${STAGED_ROOT}" \
    2>"${TMPDIR}/missing-registry.err"; then
    echo "ERROR: operator evidence ingress accepted a missing station registry" >&2
    exit 1
fi
grep -q "station-registry" "${TMPDIR}/missing-registry.err"

python3 - "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["files"][0]["path"] = "../escape.json"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    2>"${TMPDIR}/path.err"; then
    echo "ERROR: operator evidence ingress accepted path traversal" >&2
    exit 1
fi
grep -q "must be relative" "${TMPDIR}/path.err"
