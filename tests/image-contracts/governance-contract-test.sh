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
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
policy = json.loads((root / "ci/github-governance-policy.yml").read_text(encoding="utf-8"))

branch = {
    "required_pull_request_reviews": {
        "require_code_owner_reviews": True,
        "dismiss_stale_reviews": True,
        "required_approving_review_count": 2,
    },
    "required_status_checks": {
        "strict": True,
        "contexts": policy["required_checks"],
    },
    "required_linear_history": {"enabled": True},
    "required_signatures": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
    "enforce_admins": {"enabled": True},
}
rulesets = [
    {
        "name": policy["ruleset"]["branch_name"],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
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
        "conditions": {"ref_name": {"include": [policy["release_environment"]["allowed_ref"]], "exclude": []}},
        "rules": [{"type": "non_fast_forward"}],
    },
]
def environment(name: str) -> dict:
    return {
        "name": name,
        "prevent_self_review": True,
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "reviewers": [
                    {"type": "User", "reviewer": {"login": "release-owner"}},
                    {"type": "User", "reviewer": {"login": "security-owner"}},
                ],
            }
        ],
    }

deployment_policy = {
    "branch_policies": [
        {"name": "v*", "type": "tag"}
    ]
}

release_publish_environment = environment("release-publish")
release_sign_environment = environment("release-sign")
codeowners = {
    "schema_version": "suderra.codeowners-snapshot.v1",
    "patterns": policy["required_codeowners_patterns"],
}
files = {
    "repo.json": {"full_name": policy["repository"]},
    "main-branch-protection.json": branch,
    "rulesets.json": rulesets,
    "release-sign-environment.json": release_sign_environment,
    "release-sign-deployment-branch-policies.json": deployment_policy,
    "release-publish-environment.json": release_publish_environment,
    "release-publish-deployment-branch-policies.json": deployment_policy,
    "tag-protection.json": [{"pattern": "v*"}],
    "workflow-permissions.json": {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
    },
    "codeowners.json": codeowners,
    "audit-log.json": {
        "schema_version": "suderra.audit-log-snapshot.v1",
        "status": "collected",
        "source_kind": "manual-org-export",
        "organization": "Okan-wqm",
        "repository": policy["repository"],
        "collector": {"identity": "contract", "run_id": "123456789"},
        "lookback_window": {
            "start": "2026-04-24T00:00:00Z",
            "end": "2026-05-24T00:00:00Z",
            "days": 30
        },
        "query": f"repo:{policy['repository']}",
        "event_count": 0,
        "unapproved_governance_changes": False,
        "events_sha256": "a" * 64,
        "raw_export": {
            "path": "audit-log.raw.json",
            "bytes": 2,
            "sha256": "e" * 64
        },
        "replay": {"status": "passed", "unapproved_events": []},
    },
}
for name, payload in files.items():
    (snapshot / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
manifest_files = []
for name in files:
    data = (snapshot / name).read_bytes()
    manifest_files.append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})
(snapshot / "snapshot-manifest.json").write_text(json.dumps({
    "schema_version": "suderra.github-governance-snapshot-manifest.v1",
    "version": snapshot.name,
    "repository": policy["repository"],
    "collected_at": "2026-05-24T00:00:00Z",
    "files": sorted(manifest_files, key=lambda item: item["name"]),
    "failures": [],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
