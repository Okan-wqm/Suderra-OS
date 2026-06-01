#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

for doc in \
    docs/operations/operator-lifecycle.md \
    docs/operations/rc-evidence-dry-run.md \
    docs/operations/evidence-retention.md \
    docs/operations/verify-release.md \
    docs/operations/release-evidence.md \
    docs/operations/runbook.md \
    docs/security/key-ceremony.md \
    docs/assessments/INDEX.md
do
    test -s "${ROOT}/${doc}" || {
        echo "ERROR: required enterprise SSOT doc missing: ${doc}" >&2
        exit 1
    }
done

grep -q 'ci/build-matrix.yml' "${ROOT}/docs/operations/operator-lifecycle.md"
grep -q 'ci/evidence-contract.yml' "${ROOT}/docs/operations/operator-lifecycle.md"
grep -q 'ci/github-governance-policy.yml' "${ROOT}/docs/operations/operator-lifecycle.md"
grep -q 'Schema versions, retention years, replay names, signing roles' "${ROOT}/docs/README.md"
grep -q 'rc-evidence-dry-run' "${ROOT}/docs/operations/rc-evidence-dry-run.md"
grep -q 'non-promotable' "${ROOT}/docs/operations/rc-evidence-dry-run.md"
grep -q 'production_ready=false' "${ROOT}/docs/operations/rc-evidence-dry-run.md"
grep -q 'Suderra-Preflight-Profile' "${ROOT}/docs/operations/rc-evidence-dry-run.md"
grep -q 'offline/archive verification' "${ROOT}/docs/operations/rc-evidence-dry-run.md"
grep -q 'Suderra-Preflight-Profile' "${ROOT}/docs/operations/release-preflight.md"
grep -q 'legacy archive material only' "${ROOT}/docs/operations/release-preflight.md"
grep -q 'Suderra-Preflight-Profile' "${ROOT}/docs/operations/verify-release.md"
grep -q 'offline/archive verification' "${ROOT}/docs/operations/verify-release.md"
grep -q 'release-dry-run/<version>/gaps.json' "${ROOT}/docs/operations/operator-lifecycle.md"
grep -q 'suderra.signing-manifest.v2' "${ROOT}/docs/security/key-ceremony.md"
grep -q -- '--validate-subject-graph' "${ROOT}/docs/operations/verify-release.md"
if grep -n 'production-candidate' "${ROOT}/docs/operations/verify-release.md" | grep -q 'release-candidate.json'; then
    echo "ERROR: production-candidate verification docs must not use release-candidate.json" >&2
    exit 1
fi
if grep -Eq 'release evidence v[0-9]+' "${ROOT}/docs/README.md"; then
    echo "ERROR: docs/README.md must not duplicate release evidence schema versions outside generated SSOT output" >&2
    exit 1
fi
if grep -Eq '[0-9]+ yıl immutable evidence retention' "${ROOT}/docs/README.md"; then
    echo "ERROR: docs/README.md must not duplicate retention years outside generated SSOT output" >&2
    exit 1
fi

python3 - "${ROOT}" <<'PY'
import re
import sys
import importlib.util
import json
import subprocess
import tempfile
import textwrap
from pathlib import Path

root = Path(sys.argv[1])

def generated_block(path: Path, name: str) -> str:
    start = f"<!-- suderra-generated: {name} -->"
    end = "<!-- /suderra-generated -->"
    text = path.read_text(encoding="utf-8")
    if start not in text or end not in text:
        raise SystemExit(f"{path}: missing generated block {name}")
    return textwrap.dedent(text.split(start, 1)[1].split(end, 1)[0]).strip()

def fragment(name: str) -> str:
    return subprocess.check_output(
        [
            "python3",
            str(root / "scripts/evidence/evidence_contract.py"),
            "docs-fragment",
            "--fragment",
            name,
        ],
        text=True,
    ).strip()

expected_blocks = {
    "docs/operations/rc-evidence-dry-run.md": ("output-trees", "profile-gates"),
    "docs/operations/evidence-retention.md": ("retention-policy",),
    "docs/operations/verify-release.md": ("verification-schemas",),
    "docs/operations/release-evidence.md": ("schema-versions", "runtime-scenarios"),
    "docs/operations/runbook.md": ("governance-policy", "retention-policy"),
}
for rel, names in expected_blocks.items():
    path = root / rel
    for name in names:
        if generated_block(path, name) != fragment(name):
            raise SystemExit(f"{rel} generated block {name} is stale")

verify_text = (root / "docs/operations/verify-release.md").read_text(encoding="utf-8")
if "protected `publish`" in verify_text:
    raise SystemExit("verify-release docs must not use stale protected publish environment name")

def strip_generated_blocks(text: str) -> str:
    return re.sub(
        r"<!-- suderra-generated: .*?<!-- /suderra-generated -->",
        "",
        text,
        flags=re.DOTALL,
    )

rc_doc = strip_generated_blocks((root / "docs/operations/rc-evidence-dry-run.md").read_text(encoding="utf-8"))
for paragraph in re.split(r"\n\s*\n", rc_doc):
    lowered = " ".join(paragraph.lower().split())
    if "rc-evidence-dry-run" not in lowered and "dry-run" not in lowered:
        continue
    forbidden_claims = {
        "authorize publication",
        "authorizes publication",
        "publication allowed",
        "promotion allowed",
        "production readiness evidence",
        "release gate input",
        "satisfies release-candidate",
        "satisfies production-candidate",
        "can publish",
        "may publish",
    }
    matched = sorted(claim for claim in forbidden_claims if claim in lowered)
    if matched:
        raise SystemExit(
            "rc-evidence-dry-run docs contain forbidden production/publication claim: "
            + ", ".join(matched)
        )

index = root / "docs/assessments/INDEX.md"
rows = [
    line
    for line in index.read_text(encoding="utf-8").splitlines()
    if line.startswith("| [")
]
expected = {path.name for path in (root / "docs/assessments").glob("*.md") if path.name != "INDEX.md"}
seen: set[str] = set()
statuses = {"active", "superseded", "archive"}
for row in rows:
    match = re.match(r"^\| \[([^\]]+)\]\([^)]+\) \| ([^| ]+) \| ([^|]+) \|", row)
    if not match:
        raise SystemExit(f"assessment index row has invalid shape: {row}")
    name, status, reviewed_commit = match.groups()
    if status not in statuses:
        raise SystemExit(f"{name} has invalid assessment status {status!r}")
    if not reviewed_commit.strip():
        raise SystemExit(f"{name} missing reviewed commit marker")
    seen.add(name)
missing = sorted(expected - seen)
if missing:
    raise SystemExit("assessment index missing docs: " + ", ".join(missing))

spec = importlib.util.spec_from_file_location(
    "validate_release_inputs",
    root / "scripts/evidence/validate-release-inputs.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

source_sha = "0123456789abcdef0123456789abcdef01234567"
with tempfile.TemporaryDirectory() as tmp:
    tmp_root = Path(tmp)
    missing_retention = module.validate_retention_manifest(
        tmp_root / "retention-manifest.json",
        version="v9.9.9",
        source_sha=source_sha,
        source_run_id="123456789",
    )
    if not any("retention manifest missing" in item for item in missing_retention):
        raise SystemExit("missing retention manifest did not fail closed")

    bad_retention_path = tmp_root / "bad-retention-manifest.json"
    bad_retention_path.write_text(
        json.dumps(
            {
                "schema_version": "suderra.retention-manifest.v1",
                "policy_id": "suderra-enterprise-7y-immutable-evidence",
                "version": "v9.9.9",
                "source_sha": source_sha,
                "source_run_id": "123456789",
                "store_class": "immutable-encrypted-evidence-archive",
                "retention_years": 7,
                "exports": [],
                "restore_replay_tests": [],
                "kms_key_id": "kms-contract",
                "custody_chain": "custody-contract",
                "access_log": "access-log-contract",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    bad_retention = module.validate_retention_manifest(
        bad_retention_path,
        version="v9.9.9",
        source_sha=source_sha,
        source_run_id="123456789",
    )
    if not any("missing passed replay tests" in item for item in bad_retention):
        raise SystemExit("retention manifest without restore/replay coverage passed")

    missing_roles = module.validate_governance_role_bindings(
        tmp_root / "role-bindings.json",
        version="v9.9.9",
    )
    if not any("governance role bindings missing" in item for item in missing_roles):
        raise SystemExit("missing governance role bindings did not fail closed")
PY
