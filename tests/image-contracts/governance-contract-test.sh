#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

SNAPSHOT="${TMPDIR}/release-governance/v9.9.9-alpha.1"
mkdir -p "${SNAPSHOT}"

python3 - "${PROJECT_ROOT}" "${SNAPSHOT}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
policy = json.loads((root / "ci/github-governance-policy.yml").read_text(encoding="utf-8"))

branch = {
    "required_pull_request_reviews": {
        "require_code_owner_reviews": True,
        "dismiss_stale_reviews": True,
        "required_approving_review_count": 1,
    },
    "required_status_checks": {
        "strict": True,
        "contexts": policy["required_checks"],
    },
    "required_linear_history": {"enabled": True},
    "required_signatures": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
}
rulesets = [
    {
        "name": policy["ruleset"]["branch_name"],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "rules": [
            {"type": "pull_request"},
            {"type": "required_signatures"},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
        ],
    },
    {
        "name": policy["ruleset"]["tag_name"],
        "target": "tag",
        "enforcement": "active",
        "bypass_actors": [],
        "rules": [{"type": "non_fast_forward"}],
    },
]
environment = {
    "name": "release-publish",
    "deployment_branch_policy": {
        "protected_branches": False,
        "custom_branch_policies": True,
    },
    "protection_rules": [
        {
            "type": "required_reviewers",
            "reviewers": [{"type": "User", "reviewer": {"login": "release-owner"}}],
        }
    ],
}
codeowners = {
    "schema_version": "suderra.codeowners-snapshot.v1",
    "patterns": policy["required_codeowners_patterns"],
}
files = {
    "main-branch-protection.json": branch,
    "rulesets.json": rulesets,
    "release-publish-environment.json": environment,
    "tag-protection.json": [{"pattern": "v*"}],
    "workflow-permissions.json": {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
    },
    "codeowners.json": codeowners,
    "audit-log.json": {
        "schema_version": "suderra.audit-log-snapshot.v1",
        "unapproved_governance_changes": False,
    },
}
for name, payload in files.items():
    (snapshot / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${PROJECT_ROOT}/scripts/evidence/validate-governance.py" \
    --policy "${PROJECT_ROOT}/ci/github-governance-policy.yml" \
    --snapshot-root "${SNAPSHOT}" \
    --output "${SNAPSHOT}/governance-policy-validation.json" \
    >/dev/null

python3 - "${SNAPSHOT}/rulesets.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload[0]["bypass_actors"] = [{"actor_id": 1, "actor_type": "User"}]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if python3 "${PROJECT_ROOT}/scripts/evidence/validate-governance.py" \
    --policy "${PROJECT_ROOT}/ci/github-governance-policy.yml" \
    --snapshot-root "${SNAPSHOT}" \
    --output "${SNAPSHOT}/governance-policy-validation.json" \
    2>"${TMPDIR}/governance.err"; then
    echo "ERROR: governance validator accepted a bypass actor" >&2
    exit 1
fi
grep -q "bypass actors" "${TMPDIR}/governance.err" || {
    echo "ERROR: governance bypass failure did not mention bypass actors" >&2
    cat "${TMPDIR}/governance.err" >&2
    exit 1
}
