#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
SOURCE_SHA="$(git -C "${PROJECT_ROOT}" rev-parse HEAD)"
RUN_ID="123456789"
CHECKS_JSON="${TMPDIR}/release-security/${VERSION}/github-check-runs.json"

python3 - "${CHECKS_JSON}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
names = (
    "GitHub Actions Lint",
    "ShellCheck",
    "YAML Lint",
    "Markdown Lint",
    "Hadolint",
    "Secret Scan (gitleaks)",
    "Gitleaks (secret scan)",
    "Format + Clippy + Test",
    "Security (audit + deny)",
    "Trivy (filesystem)",
    "Trivy (config / Dockerfile)",
    "Grype (filesystem)",
)
payload = {
    "total_count": len(names),
    "check_runs": [
        {
            "id": idx,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-05-20T00:00:00Z",
            "completed_at": "2026-05-20T00:01:00Z",
            "html_url": f"https://example.invalid/checks/{idx}",
            "details_url": f"https://example.invalid/checks/{idx}/details",
            "app": {"slug": "github-actions"},
        }
        for idx, name in enumerate(names, start=1)
    ],
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${PROJECT_ROOT}/scripts/evidence/collect-ci-check-evidence.py" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-run-id "${RUN_ID}" \
    --checks-json "${CHECKS_JSON}" \
    --output-root "${TMPDIR}/release-security" \
    >/dev/null

python3 - "${PROJECT_ROOT}" "${TMPDIR}" "${VERSION}" "${SOURCE_SHA}" "${RUN_ID}" "${CHECKS_JSON}" <<'PY'
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

project_root = Path(sys.argv[1])
root = Path(sys.argv[2])
version = sys.argv[3]
source_sha = sys.argv[4]
run_id = sys.argv[5]
checks_json = Path(sys.argv[6])

spec = importlib.util.spec_from_file_location(
    "validate_build_matrix",
    project_root / "scripts" / "ci" / "validate-build-matrix.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
matrix = module.load_matrix(project_root / "ci" / "build-matrix.yml")
evidence_sha = hashlib.sha256(checks_json.read_bytes()).hexdigest()
for scan in matrix["security_scans"]:
    report = root / "release-security" / version / f"{scan}.json"
    if not report.is_file():
        raise SystemExit(f"missing report for {scan}")
    payload = json.loads(report.read_text(encoding="utf-8"))
    if payload["schema_version"] != "suderra.release-security-report.v1":
        raise SystemExit(f"{scan}: schema mismatch")
    if payload["source_sha"] != source_sha or str(payload["source_run_id"]) != run_id:
        raise SystemExit(f"{scan}: source binding mismatch")
    if payload["status"] != "passed":
        raise SystemExit(f"{scan}: status must be passed")
    if payload["evidence_sha256"] != evidence_sha:
        raise SystemExit(f"{scan}: evidence digest mismatch")
    if payload.get("evidence_bytes") != checks_json.stat().st_size:
        raise SystemExit(f"{scan}: evidence size mismatch")
    if payload.get("evidence_path") != f"{version}/github-check-runs.json":
        raise SystemExit(f"{scan}: evidence path mismatch")
    if not payload.get("check_runs"):
        raise SystemExit(f"{scan}: check_runs must not be empty")
    if any(item.get("conclusion") != "success" for item in payload["check_runs"]):
        raise SystemExit(f"{scan}: report preserved a non-success check")
PY

python3 - "${CHECKS_JSON}" "${TMPDIR}/failed-check-runs.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in payload["check_runs"]:
    if item["name"] == "Hadolint":
        item["conclusion"] = "failure"
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${PROJECT_ROOT}/scripts/evidence/collect-ci-check-evidence.py" \
    --version "${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    --source-run-id "${RUN_ID}" \
    --checks-json "${TMPDIR}/failed-check-runs.json" \
    --output-root "${TMPDIR}/failed-release-security" \
    2>"${TMPDIR}/failed.err"; then
    echo "ERROR: release security collector accepted a failed check run" >&2
    exit 1
fi
grep -q "hadolint" "${TMPDIR}/failed.err" && grep -q "Hadolint" "${TMPDIR}/failed.err" || {
    echo "ERROR: failed check diagnostic did not identify Hadolint" >&2
    cat "${TMPDIR}/failed.err" >&2
    exit 1
}
