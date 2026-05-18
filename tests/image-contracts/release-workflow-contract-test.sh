#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
RELEASE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release.yml"
BUILD_WORKFLOW="${PROJECT_ROOT}/.github/workflows/build.yml"

grep -q '^concurrency:' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must have a release-tag concurrency guard" >&2
    exit 1
}

if grep -q 'workflow_dispatch:' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not support branch-ref workflow_dispatch releases" >&2
    exit 1
fi

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
