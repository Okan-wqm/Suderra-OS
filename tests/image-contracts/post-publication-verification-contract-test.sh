#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_TOOL="${ROOT}/scripts/evidence/release-publication-manifest.py"
POST_PUBLICATION_TOOL="${ROOT}/scripts/evidence/post-publication-verification.py"
PROOF_MANIFEST_TOOL="${ROOT}/scripts/evidence/release-publication-proof-manifest.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

VERSION="v9.9.9-alpha.1"
SOURCE_SHA="0123456789abcdef0123456789abcdef01234567"
RELEASE_DIR="${TMPDIR}/release"
ATTESTATION_DIR="${TMPDIR}/attestations"
mkdir -p "${RELEASE_DIR}" "${ATTESTATION_DIR}"

printf 'final evidence archive\n' > "${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst"
printf 'signature\n' > "${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst.sig"
printf 'certificate\n' > "${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst.cert"

python3 "${MANIFEST_TOOL}" create \
    --version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --output "${RELEASE_DIR}/release-publication-manifest.json" \
    --repository Okan-wqm/Suderra-OS \
    --workflow Release \
    --run-id 123456789 \
    --run-attempt 1 \
    >/dev/null
printf 'manifest signature\n' > "${RELEASE_DIR}/release-publication-manifest.json.sig"
printf 'manifest certificate\n' > "${RELEASE_DIR}/release-publication-manifest.json.cert"

asset_sha="$(sha256sum "${RELEASE_DIR}/release-evidence-${VERSION}.tar.zst" | awk '{print $1}')"
python3 - "${ATTESTATION_DIR}/release-evidence-${VERSION}.tar.zst.json" "release-evidence-${VERSION}.tar.zst" "${asset_sha}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
name = sys.argv[2]
sha = sys.argv[3]
payload = {
    "_type": "https://in-toto.io/Statement/v1",
    "predicateType": "https://slsa.dev/provenance/v1",
    "subject": [{"name": name, "digest": {"sha256": sha}}],
    "predicate": {
        "buildDefinition": {
            "externalParameters": {
                "repository": "Okan-wqm/Suderra-OS",
                "ref": "refs/tags/v9.9.9-alpha.1",
                "run_id": "123456789",
                "run_attempt": "1",
                "source_sha": "0123456789abcdef0123456789abcdef01234567",
            },
            "resolvedDependencies": [
                {
                    "uri": "git+https://github.com/Okan-wqm/Suderra-OS",
                    "digest": {"gitCommit": "0123456789abcdef0123456789abcdef01234567"},
                }
            ],
        },
        "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
    },
}
path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${POST_PUBLICATION_TOOL}" create \
    --version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --attestation-json-dir "${ATTESTATION_DIR}" \
    --output "${TMPDIR}/post-publication.json" \
    --identity "https://github.com/Okan-wqm/Suderra-OS/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --issuer "https://token.actions.githubusercontent.com" \
    --repository Okan-wqm/Suderra-OS \
    --workflow Release \
    --run-id 123456789 \
    --run-attempt 1 \
    --ref "refs/tags/${VERSION}" \
    --source-sha "${SOURCE_SHA}" \
    >/dev/null
mkdir -p "${TMPDIR}/proof"
cp "${TMPDIR}/post-publication.json" "${TMPDIR}/proof/release-post-publication-verification.json"
printf 'post-publication signature\n' > "${TMPDIR}/proof/release-post-publication-verification.json.sig"
printf 'post-publication certificate\n' > "${TMPDIR}/proof/release-post-publication-verification.json.cert"
cp "${ATTESTATION_DIR}"/*.json "${TMPDIR}/proof/"

python3 "${PROOF_MANIFEST_TOOL}" create \
    --version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --proof-dir "${TMPDIR}/proof" \
    --output "${TMPDIR}/proof/release-publication-proof-manifest.json" \
    >/dev/null
printf 'proof manifest signature\n' > "${TMPDIR}/proof/release-publication-proof-manifest.json.sig"
printf 'proof manifest certificate\n' > "${TMPDIR}/proof/release-publication-proof-manifest.json.cert"

python3 "${PROOF_MANIFEST_TOOL}" validate \
    "${TMPDIR}/proof/release-publication-proof-manifest.json" \
    --release-dir "${RELEASE_DIR}" \
    --proof-dir "${TMPDIR}/proof" \
    --expected-version "${VERSION}" \
    >/dev/null

python3 "${POST_PUBLICATION_TOOL}" validate \
    "${TMPDIR}/post-publication.json" \
    --expected-version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --attestation-json-dir "${ATTESTATION_DIR}" \
    >/dev/null

python3 - "${ATTESTATION_DIR}/release-evidence-${VERSION}.tar.zst.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["subject"][0]["digest"]["sha256"] = "0" * 64
path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${POST_PUBLICATION_TOOL}" validate \
    "${TMPDIR}/post-publication.json" \
    --expected-version "${VERSION}" \
    --release-dir "${RELEASE_DIR}" \
    --attestation-json-dir "${ATTESTATION_DIR}" \
    2>"${TMPDIR}/tampered.err"; then
    echo "ERROR: tampered post-publication attestation unexpectedly passed" >&2
    exit 1
fi

grep -q 'cannot replay post-publication verification' "${TMPDIR}/tampered.err" || {
    echo "ERROR: tampered post-publication failure did not explain replay mismatch" >&2
    cat "${TMPDIR}/tampered.err" >&2
    exit 1
}
