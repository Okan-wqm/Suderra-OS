#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
RELEASE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release.yml"
PREFLIGHT_WORKFLOW="${PROJECT_ROOT}/.github/workflows/release-preflight.yml"
BUILD_WORKFLOW="${PROJECT_ROOT}/.github/workflows/build.yml"
IMAGE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/image-build.yml"

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
grep -q 'collect-ci-check-evidence.py' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must convert exact source_sha CI checks into release security evidence" >&2
    exit 1
}
grep -q -- '--station-registry release-governance/${{ needs.validate.outputs.version }}/station-registry.json' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must validate lab evidence against a governance-owned station registry" >&2
    exit 1
}
if grep -q -- '--station-registry release-lab-input/station-registry.json' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not trust station registry from release-lab-input" >&2
    exit 1
fi
grep -q 'check-runs?per_page=100' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must fetch source_sha GitHub check-runs for scanner evidence" >&2
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
grep -q 'Image Build' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must bind Image Build, not fast Build" >&2
    exit 1
}
grep -q '.github/workflows/image-build.yml' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must pin image-build.yml as artifact producer" >&2
    exit 1
}
grep -q 'image-build-contract.py validate' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight must validate the image build contract" >&2
    exit 1
}
grep -q 'build-artifacts/' "${PREFLIGHT_WORKFLOW}" || {
    echo "ERROR: release preflight artifact must carry preflight-bound Image Build bytes" >&2
    exit 1
}
if grep -q -- 'gh run download.*--dir build-artifacts$' "${PREFLIGHT_WORKFLOW}"; then
    echo "ERROR: release preflight must download explicit Image Build artifact names, not the whole run" >&2
    exit 1
fi
grep -q 'build-artifacts/' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must stage from preflight-bound Image Build bytes" >&2
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
grep -Fq 'name: installer-${{ matrix.arch }}' "${IMAGE_WORKFLOW}" || {
    echo "ERROR: Image Build workflow must produce preflight-bound installer artifacts" >&2
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
grep -q 'release-stage:' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must separate unprivileged release staging from signing" >&2
    exit 1
}
grep -q 'release-sign:' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must have a protected signing job" >&2
    exit 1
}
grep -q 'name: release-sign' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release signing job must run under the release-sign protected environment" >&2
    exit 1
}
grep -q 'staged-release-' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must pass staged bytes to the protected signing job" >&2
    exit 1
}
grep -q 'machine-verification-record.py create' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must create structured machine-verification records" >&2
    exit 1
}
grep -q -- '--format json' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must preserve structured GitHub attestation JSON, not only logs" >&2
    exit 1
}
grep -q -- '--attestation-json-dir machine-verification/attestations' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must compare DSSE subjects from attestation JSON" >&2
    exit 1
}
grep -q 'SOURCE_COMMIT="$(git rev-list -n 1 "${{ needs.validate.outputs.version }}")"' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must bind machine verification to the tag target source commit" >&2
    exit 1
}
if grep -q -- '--source-sha "${GITHUB_SHA}"' "${RELEASE_WORKFLOW}"; then
    echo "ERROR: release workflow must not use event GITHUB_SHA as the source commit for tag-bound evidence" >&2
    exit 1
fi
python3 - "${RELEASE_WORKFLOW}" <<'PY'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
positions = {
    "download_governance": None,
    "validate_lab": None,
}
for idx, line in enumerate(lines):
    if "name: Download governance evidence" in line and positions["download_governance"] is None:
        positions["download_governance"] = idx
    if "name: Validate full-matrix lab evidence input" in line:
        positions["validate_lab"] = idx
if positions["download_governance"] is None or positions["validate_lab"] is None:
    raise SystemExit("release workflow must download governance evidence and validate lab input")
if positions["download_governance"] > positions["validate_lab"]:
    raise SystemExit("release workflow must download governance evidence before lab validation")
PY
python3 - "${RELEASE_WORKFLOW}" <<'PY'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
inside = False
body = []
for line in lines:
    if line == "  release-sign:":
        inside = True
        continue
    if inside and line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
        break
    if inside:
        body.append(line)
if any("apt-get" in line for line in body):
    raise SystemExit("protected release-sign job must not install live apt packages")
PY
grep -q 'Verify published release asset byte set and cryptography' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must validate the published GitHub Release asset set and cryptography after publish" >&2
    exit 1
}
grep -q 'gh attestation verify "${f}"' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: published release verification must revalidate GitHub artifact attestations" >&2
    exit 1
}
grep -q 'draft: true' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: protected publish job must create a draft release before post-publication closure" >&2
    exit 1
}
grep -q -- '--draft=false' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: release workflow must promote the draft only after post-publication closure evidence" >&2
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
grep -q 'post-publication-verification.py create' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: publish job must create replayable post-publication verification evidence" >&2
    exit 1
}
grep -q 'post-publication-verification.py validate' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: publish job must replay-validate post-publication verification evidence" >&2
    exit 1
}
grep -q 'release-publication-proof-manifest.py create' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: publish job must create a second-stage publication proof manifest" >&2
    exit 1
}
grep -q 'gh release upload "${{ needs.validate.outputs.version }}"' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: publish job must upload post-publication proof bytes as release assets" >&2
    exit 1
}
grep -q 'post-publication-verification-' "${RELEASE_WORKFLOW}" || {
    echo "ERROR: publish job must upload post-publication verification as a retained artifact" >&2
    exit 1
}

if grep -q "tags: \\['v\\*'\\]" "${BUILD_WORKFLOW}" || grep -q "tags:" "${BUILD_WORKFLOW}" ||
    grep -q "tags: \\['v\\*'\\]" "${IMAGE_WORKFLOW}" || grep -q "tags:" "${IMAGE_WORKFLOW}"; then
    echo "ERROR: build workflows must not independently build v* release tags" >&2
    exit 1
fi

python3 - "${RELEASE_WORKFLOW}" <<'PY'
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
job = None
contents_write_jobs = []
release_publish_jobs = []
release_sign_jobs = []
id_token_write_jobs = []
attestations_write_jobs = []
for raw in workflow:
    if raw.startswith("  ") and not raw.startswith("    ") and raw.rstrip().endswith(":"):
        name = raw.strip()[:-1]
        if name not in {"push", "tags"}:
            job = name
    if "contents: write" in raw and job:
        contents_write_jobs.append(job)
    if raw.strip() == "name: release-publish" and job:
        release_publish_jobs.append(job)
    if raw.strip() == "name: release-sign" and job:
        release_sign_jobs.append(job)
    if "id-token: write" in raw and job:
        id_token_write_jobs.append(job)
    if "attestations: write" in raw and job:
        attestations_write_jobs.append(job)

if contents_write_jobs != ["publish"]:
    raise SystemExit(f"contents: write must be limited to publish job, got {contents_write_jobs}")
if release_publish_jobs != ["publish"]:
    raise SystemExit(f"release-publish environment must be limited to publish job, got {release_publish_jobs}")
if release_sign_jobs != ["release-sign"]:
    raise SystemExit(f"release-sign environment must be limited to release-sign job, got {release_sign_jobs}")
if id_token_write_jobs != ["release-sign", "publish"]:
    raise SystemExit(f"id-token: write must be limited to release-sign and publish jobs, got {id_token_write_jobs}")
if attestations_write_jobs != ["release-sign"]:
    raise SystemExit(f"attestations: write must be limited to release-sign job, got {attestations_write_jobs}")
PY
