#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SECURITY_WORKFLOW="${ROOT}/.github/workflows/security-scan.yml"

for token in GITLEAKS_SHA256 TRIVY_SHA256 GRYPE_SHA256; do
    grep -q "${token}" "${SECURITY_WORKFLOW}" || {
        echo "ERROR: security workflow must pin ${token}" >&2
        exit 1
    }
done

if grep -q 'raw.githubusercontent.com/anchore/grype/main/install.sh' "${SECURITY_WORKFLOW}"; then
    echo "ERROR: security workflow must not install Grype from mutable main install.sh" >&2
    exit 1
fi
if grep -q 'apt-get install -y trivy' "${SECURITY_WORKFLOW}"; then
    echo "ERROR: security workflow must not install mutable Trivy apt packages" >&2
    exit 1
fi
if grep -q 'gitleaks/gitleaks-action' "${ROOT}/.github/workflows/lint.yml" "${SECURITY_WORKFLOW}"; then
    echo "ERROR: workflows must use the pinned gitleaks CLI, not the action" >&2
    exit 1
fi
for workflow in "${ROOT}/.github/workflows/lint.yml" "${SECURITY_WORKFLOW}"; do
    grep -q -- '--repo gitleaks/gitleaks' "${workflow}" || {
        echo "ERROR: ${workflow} must download gitleaks by release asset name through gh" >&2
        exit 1
    }
    grep -q -- '--pattern "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"' "${workflow}" || {
        echo "ERROR: ${workflow} must bind gitleaks download to the expected linux_x64 asset name" >&2
        exit 1
    }
done
