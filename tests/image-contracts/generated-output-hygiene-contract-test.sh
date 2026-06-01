#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

for path in \
    build-logs/sample.log \
    build-logs/sample.warnings.json \
    release-lab-input/v0/target/lab.json \
    release-security/v0/trivy.json \
    release-reproducibility/v0/target.json \
    release-approvals/v0/target.json \
    release-governance/v0/governance-policy-validation.json \
    release-ingress/v0/ingress-manifest.json \
    release-subject-graph/v0/release-subject-graph.json \
    release-dry-run/v0/dry-run-report.json \
    release-runtime/v0/target/production-runtime.json \
    release-signing/v0/target/signing-manifest.json \
    release-retention/v0/retention-manifest.json \
    release-ota/v0/target/ota-artifacts.json \
    release-evidence-generated/v0/target/evidence.json \
    signed-release/release/release-publication-manifest.json; do
    git -C "${ROOT}" check-ignore -q "${path}" || {
        echo "ERROR: generated/operator output should be ignored: ${path}" >&2
        exit 1
    }
done

python3 - "${ROOT}" <<'PY'
import importlib.util
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "evidence_contract",
    root / "scripts/evidence/evidence_contract.py",
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for dirname in module.gitignore_required_roots(contract=module.load_contract(root / "ci/evidence-contract.yml")):
    sample = f"{dirname}/v0/.sample"
    result = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "-q", sample],
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"ERROR: output tree marked gitignore_required is not ignored: {sample}")
PY

if git -C "${ROOT}" check-ignore -q userspace/Cargo.lock; then
    echo "ERROR: userspace/Cargo.lock must remain tracked and unignored" >&2
    exit 1
fi
