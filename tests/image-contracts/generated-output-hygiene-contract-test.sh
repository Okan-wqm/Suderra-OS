#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

for path in \
    build-logs/sample.log \
    build-logs/sample.warnings.json \
    release-lab-input/v0/target/lab.json \
    release-security/v0/trivy.json \
    release-reproducibility/v0/target.log \
    release-approvals/v0/target.json \
    release-governance/v0/governance-policy-validation.json \
    release-ingress/v0/ingress-manifest.json \
    release-evidence-generated/v0/target/evidence.json \
    signed-release/release/release-publication-manifest.json; do
    git -C "${ROOT}" check-ignore -q "${path}" || {
        echo "ERROR: generated/operator output should be ignored: ${path}" >&2
        exit 1
    }
done

if git -C "${ROOT}" check-ignore -q userspace/Cargo.lock; then
    echo "ERROR: userspace/Cargo.lock must remain tracked and unignored" >&2
    exit 1
fi
