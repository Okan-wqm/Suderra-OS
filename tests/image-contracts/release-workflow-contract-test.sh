#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
RELEASE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release.yml"
PREFLIGHT_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release-preflight.yml"
BUILD_WORKFLOW="${PROJECT_ROOT}/.github/workflows/build.yml"

grep -q '^concurrency:' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must have a release-tag concurrency guard" >&2
    exit 1
}

if grep -q 'workflow_dispatch:' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not support branch-ref workflow_dispatch releases" >&2
    exit 1
fi

grep -q '^name: Release Preflight$' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight workflow must exist" >&2
    exit 1
}
grep -q 'workflow_dispatch:' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight workflow must be manually dispatchable" >&2
    exit 1
}
grep -q 'source_sha:' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must bind an exact source_sha input" >&2
    exit 1
}
grep -q 'source_run_id:' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must bind an exact source_run_id input" >&2
    exit 1
}
if grep -q 'contents: write' "${PREFLIGHT_WORKFLOW}" || grep -q 'id-token: write' "${PREFLIGHT_WORKFLOW}"; then
    echo "ERROR: release preflight must not have publish/signing permissions" >&2
    exit 1
fi
grep -q 'release-preflight-' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact name must include version and source_sha" >&2
    exit 1
}
grep -Fq 'release-preflight-${{ inputs.profile }}-${{ inputs.version }}-${{ inputs.source_sha }}' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact name must include profile, version, and source_sha" >&2
    exit 1
}
grep -Fq 'release-preflight-release-candidate-${VERSION}-${SOURCE_SHA}' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must bind only release-candidate preflight artifacts" >&2
    exit 1
}
grep -q 'validate-release-artifact-binding.py' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must compare staged release bytes to the preflight binding" >&2
    exit 1
}
grep -q 'preflight-binding:' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must require a successful release preflight binding" >&2
    exit 1
}

if grep -q "tags: \\['v\\*'\\]" "${BUILD_WORKFLOW}" || grep -q "tags:" "${BUILD_WORKFLOW}"; then
    echo "ERROR: build workflow must not independently build v* release tags" >&2
    exit 1
fi

python3 - "${RELEASE_WORKFLOW}" <<'PY'
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
job = None
contents_write_jobs = []
release_publish_jobs = []
for raw in workflow:
    if raw.startswith("  ") and not raw.startswith("    ") and raw.rstrip().endswith(":"):
        name = raw.strip()[:-1]
        if name not in {"push", "tags"}:
            job = name
    if "contents: write" in raw and job:
        contents_write_jobs.append(job)
    if "release-publish" in raw and job:
        release_publish_jobs.append(job)

if contents_write_jobs != ["publish"]:
    raise SystemExit(f"contents: write must be limited to publish job, got {contents_write_jobs}")
if release_publish_jobs != ["publish"]:
    raise SystemExit(f"release-publish environment must be limited to publish job, got {release_publish_jobs}")
PY
