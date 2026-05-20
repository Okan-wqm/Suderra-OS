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
if grep -q 'contents: write' "${PREFLIGHT_WORKFLOW}"; then
    echo "ERROR: release preflight must not have publish permissions" >&2
    exit 1
fi
grep -q 'id-token: write' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must have OIDC permission to sign ingress" >&2
    exit 1
}
grep -q 'release-preflight-' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact name must include version and source_sha" >&2
    exit 1
}
grep -Fq 'release-preflight-${{ inputs.profile }}-${{ inputs.version }}-${{ inputs.source_sha }}' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact name must include profile, version, and source_sha" >&2
    exit 1
}
grep -q 'validate-release-tag-binding.py validate-run' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must validate the tag-bound preflight run and artifact" >&2
    exit 1
}
grep -q 'validate-release-tag-binding.py validate-cross-binding' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must cross-bind tag, preflight input, and ingress metadata" >&2
    exit 1
}
grep -q 'SUDERRA_RELEASE_TAG_SIGNING_FINGERPRINTS' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must require trusted tag signer fingerprints" >&2
    exit 1
}
grep -q 'preflight_run_id=.*GITHUB_OUTPUT' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must expose the tag-bound preflight run id as a step output" >&2
    exit 1
}
grep -q 'production-candidate' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must distinguish alpha and production preflight profiles" >&2
    exit 1
}
grep -q 'release-tag-binding.json' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must use explicit annotated-tag preflight binding metadata" >&2
    exit 1
}
if grep -q -- '--limit 50' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not discover preflight runs by scanning recent runs" >&2
    exit 1
fi
grep -q 'validate-release-artifact-binding.py' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must compare staged release bytes to the preflight binding" >&2
    exit 1
}
grep -q 'release-evidence.py asset-manifest' "${RELEASE_WORKFLOW}" &&
    grep -q -- '--binding-manifest "release-inputs/' "${RELEASE_WORKFLOW}" ||
    {
        echo "ERROR: release asset manifest must bind preflight Buildroot source identity" >&2
        exit 1
    }
grep -q 'release-ingress.py create' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must create a release ingress manifest" >&2
    exit 1
}
grep -q 'cosign sign-blob' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must sign the ingress manifest" >&2
    exit 1
}
grep -q 'release-ingress.py validate' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must validate the signed release ingress manifest" >&2
    exit 1
}
grep -q -- '--require-ingress-signature' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must require ingress signature verification" >&2
    exit 1
}
grep -q 'build-artifacts/' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact must carry preflight-bound Build bytes" >&2
    exit 1
}
if grep -q -- 'gh run download.*--dir build-artifacts$' "${PREFLIGHT_WORKFLOW}"; then
    echo "ERROR: release preflight must download explicit Build artifact names, not the whole run" >&2
    exit 1
fi
grep -q 'build-artifacts/' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must stage from preflight-bound Build bytes" >&2
    exit 1
}
if grep -q 'build-in-docker.sh' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must promote preflight-bound image bytes, not rebuild images" >&2
    exit 1
fi
if grep -q 'Download all artifacts' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not download unbound workflow artifacts" >&2
    exit 1
fi
if grep -q 'cargo install cross' "${RELEASE_WORKFLOW}" || grep -q 'cross build -p suderra-installer' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not rebuild installer binaries after preflight" >&2
    exit 1
fi
grep -Fq 'name: installer-${{ matrix.arch }}' "${BUILD_WORKFLOW}" || {
    echo "ERROR: Build workflow must produce preflight-bound installer artifacts" >&2
    exit 1
}
grep -q 'release-evidence-.*\.tar\.zst' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must publish a compressed release evidence archive" >&2
    exit 1
}
grep -q 'release-publication-manifest.json' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must publish a final publication manifest" >&2
    exit 1
}
grep -q 'release-publication-manifest.json.sig' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must sign the final publication manifest" >&2
    exit 1
}
grep -q 'release-publication-manifest.py validate' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must machine-validate the final publication manifest" >&2
    exit 1
}
grep -q 'Verify published draft asset byte set' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must validate the draft GitHub Release asset set after publish" >&2
    exit 1
}
if grep -q 'signed-release/release-evidence-generated' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: GitHub Release assets must not publish generated evidence internals outside the archive" >&2
    exit 1
fi
grep -q 'Final publication provenance attestation' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must attest final publication bytes" >&2
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
