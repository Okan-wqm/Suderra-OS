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
        "source_kind": "manual-org-export",
        "organization": "Okan-wqm",
        "repository": "Okan-wqm/Suderra-OS",
        "collector": {"identity": "contract", "run_id": run_id},
        "lookback_window": {
            "start": "2026-04-24T00:00:00Z",
            "end": "2026-05-24T00:00:00Z",
            "days": 30
        },
        "query": "repo:Okan-wqm/Suderra-OS",
        "event_count": 0,
        "events_sha256": "a" * 64,
        "raw_export": {
            "path": "audit-log.raw.json",
            "bytes": 2,
            "sha256": "e" * 64
        },
        "replay": {"status": "passed", "unapproved_events": []},
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
printf 'contract signature\n' >"${TMPDIR}/operator-evidence.tar.gz.sig"
printf 'contract certificate\n' >"${TMPDIR}/operator-evidence.tar.gz.cert"
BUNDLE_SHA256="$(sha256sum "${TMPDIR}/operator-evidence.tar.gz" | awk '{print $1}')"
BUNDLE_SIGNATURE_SHA256="$(sha256sum "${TMPDIR}/operator-evidence.tar.gz.sig" | awk '{print $1}')"
BUNDLE_CERTIFICATE_SHA256="$(sha256sum "${TMPDIR}/operator-evidence.tar.gz.cert" | awk '{print $1}')"
python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence.tar.gz" \
    --bundle-signature "${TMPDIR}/operator-evidence.tar.gz.sig" \
    --bundle-certificate "${TMPDIR}/operator-evidence.tar.gz.cert" \
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
    --bundle-url "https://operator-evidence.example.test/operator-evidence.tar.gz" \
    --bundle-sha256 "${BUNDLE_SHA256}" \
    --bundle-signature-sha256 "${BUNDLE_SIGNATURE_SHA256}" \
    --bundle-certificate-sha256 "${BUNDLE_CERTIFICATE_SHA256}" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null

if python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence.tar.gz" \
    --bundle-signature "${TMPDIR}/operator-evidence.tar.gz.sig" \
    --bundle-certificate "${TMPDIR}/operator-evidence.tar.gz.cert" \
    --output-root "${TMPDIR}/bad-digest-root" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "${RUN_ID}" \
    --source-image-build-run-attempt "${RUN_ATTEMPT}" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    --bundle-url "https://operator-evidence.example.test/operator-evidence.tar.gz" \
    --bundle-sha256 "$(printf '0%.0s' {1..64})" \
    --bundle-signature-sha256 "${BUNDLE_SIGNATURE_SHA256}" \
    --bundle-certificate-sha256 "${BUNDLE_CERTIFICATE_SHA256}" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null 2>"${TMPDIR}/bad-bundle-digest.err"; then
    echo "ERROR: operator evidence ingress accepted a mismatched bundle digest" >&2
    exit 1
fi
grep -q "bundle-sha256" "${TMPDIR}/bad-bundle-digest.err"

if python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence.tar.gz" \
    --bundle-signature "${TMPDIR}/operator-evidence.tar.gz.sig" \
    --bundle-certificate "${TMPDIR}/operator-evidence.tar.gz.cert" \
    --output-root "${TMPDIR}/bad-signature-digest-root" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "${RUN_ID}" \
    --source-image-build-run-attempt "${RUN_ATTEMPT}" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    --bundle-url "https://operator-evidence.example.test/operator-evidence.tar.gz" \
    --bundle-sha256 "${BUNDLE_SHA256}" \
    --bundle-signature-sha256 "$(printf '1%.0s' {1..64})" \
    --bundle-certificate-sha256 "${BUNDLE_CERTIFICATE_SHA256}" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null 2>"${TMPDIR}/bad-signature-digest.err"; then
    echo "ERROR: operator evidence ingress accepted a mismatched bundle signature digest" >&2
    exit 1
fi
grep -q "bundle-signature-sha256" "${TMPDIR}/bad-signature-digest.err"

if python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence.tar.gz" \
    --bundle-signature "${TMPDIR}/operator-evidence.tar.gz.sig" \
    --bundle-certificate "${TMPDIR}/operator-evidence.tar.gz.cert" \
    --output-root "${TMPDIR}/bad-certificate-digest-root" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "${RUN_ID}" \
    --source-image-build-run-attempt "${RUN_ATTEMPT}" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    --bundle-url "https://operator-evidence.example.test/operator-evidence.tar.gz" \
    --bundle-sha256 "${BUNDLE_SHA256}" \
    --bundle-signature-sha256 "${BUNDLE_SIGNATURE_SHA256}" \
    --bundle-certificate-sha256 "$(printf '2%.0s' {1..64})" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null 2>"${TMPDIR}/bad-certificate-digest.err"; then
    echo "ERROR: operator evidence ingress accepted a mismatched bundle certificate digest" >&2
    exit 1
fi
grep -q "bundle-certificate-sha256" "${TMPDIR}/bad-certificate-digest.err"

BAD_DRY_RUN_ROOT="${TMPDIR}/bad-dry-run-bundle"
cp -a "${BUNDLE_ROOT}" "${BAD_DRY_RUN_ROOT}"
mkdir -p "${BAD_DRY_RUN_ROOT}/release-dry-run/${VERSION}"
printf '{"schema_version":"suderra.rc-evidence-dry-run.v1"}\n' \
    >"${BAD_DRY_RUN_ROOT}/release-dry-run/${VERSION}/dry-run-report.json"
( cd "${BAD_DRY_RUN_ROOT}" && tar -czf "${TMPDIR}/operator-evidence-with-dry-run.tar.gz" . )
BAD_DRY_RUN_SHA256="$(sha256sum "${TMPDIR}/operator-evidence-with-dry-run.tar.gz" | awk '{print $1}')"
if python3 "${TOOL}" stage \
    --bundle "${TMPDIR}/operator-evidence-with-dry-run.tar.gz" \
    --bundle-signature "${TMPDIR}/operator-evidence.tar.gz.sig" \
    --bundle-certificate "${TMPDIR}/operator-evidence.tar.gz.cert" \
    --output-root "${TMPDIR}/bad-dry-run-root" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-image-build-run-id "${RUN_ID}" \
    --source-image-build-run-attempt "${RUN_ATTEMPT}" \
    --repository "Okan-wqm/Suderra-OS" \
    --workflow "Release Evidence Ingress" \
    --run-id "987654321" \
    --run-attempt "1" \
    --actor "contract" \
    --bundle-url "https://operator-evidence.example.test/operator-evidence-with-dry-run.tar.gz" \
    --bundle-sha256 "${BAD_DRY_RUN_SHA256}" \
    --bundle-signature-sha256 "${BUNDLE_SIGNATURE_SHA256}" \
    --bundle-certificate-sha256 "${BUNDLE_CERTIFICATE_SHA256}" \
    --bundle-certificate-identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/operator-evidence.yml@refs/heads/main" \
    --bundle-certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --bundle-allowed-host "operator-evidence.example.test" \
    >/dev/null 2>"${TMPDIR}/bad-dry-run.err"; then
    echo "ERROR: operator evidence ingress accepted non-promotable release-dry-run output" >&2
    exit 1
fi
grep -q "release-dry-run" "${TMPDIR}/bad-dry-run.err"

python3 "${TOOL}" validate \
    "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    --input-root "${STAGED_ROOT}" \
    --expected-version "${VERSION}" \
    --expected-source-sha "${SOURCE_SHA}" \
    --expected-source-image-build-run-id "${RUN_ID}" \
    --expected-source-image-build-run-attempt "${RUN_ATTEMPT}" \
    >/dev/null

python3 - "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
assert payload["schema_version"] == "suderra.operator-evidence-ingress.v2"
PY

cp "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    "${TMPDIR}/expired-ingress.json"
python3 - "${TMPDIR}/expired-ingress.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["generated_at"] = "2000-01-01T00:00:00Z"
payload["expires_at"] = "2000-01-02T00:00:00Z"
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/expired-ingress.json" \
    2>"${TMPDIR}/expired-ingress.err"; then
    echo "ERROR: operator evidence ingress accepted an expired manifest" >&2
    exit 1
fi
grep -q "expired" "${TMPDIR}/expired-ingress.err"

cp "${STAGED_ROOT}/release-ingress/${VERSION}/evidence-ingress-manifest.json" \
    "${TMPDIR}/missing-bundle-provenance.json"
python3 - "${TMPDIR}/missing-bundle-provenance.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload.pop("operator_bundle", None)
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if python3 "${TOOL}" validate \
    "${TMPDIR}/missing-bundle-provenance.json" \
    2>"${TMPDIR}/missing-bundle-provenance.err"; then
    echo "ERROR: operator evidence ingress accepted missing bundle provenance" >&2
    exit 1
fi
grep -q "operator_bundle" "${TMPDIR}/missing-bundle-provenance.err"

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
