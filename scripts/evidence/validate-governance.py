#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate GitHub governance snapshots against Suderra OS policy.

The policy file is JSON-compatible YAML so this release gate stays stdlib-only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any


SCHEMA_VERSION = "suderra.github-governance-validation.v2"
LEGACY_SCHEMA_VERSIONS = {"suderra.github-governance-validation.v1"}
POLICY_SCHEMA_VERSION = "suderra.github-governance-policy.v2"
LEGACY_POLICY_SCHEMA_VERSIONS = {"suderra.github-governance-policy.v1"}


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def status_check_contexts(branch: dict[str, Any]) -> set[str]:
    contexts: set[str] = set()
    required = branch.get("required_status_checks")
    if not isinstance(required, dict):
        return contexts
    raw_contexts = required.get("contexts")
    if isinstance(raw_contexts, list):
        contexts.update(str(item) for item in raw_contexts if isinstance(item, str))
    checks = required.get("checks")
    if isinstance(checks, list):
        for item in checks:
            if isinstance(item, dict) and isinstance(item.get("context"), str):
                contexts.add(item["context"])
    return contexts


def has_rule(rules: list[Any], rule_type: str) -> bool:
    return any(isinstance(rule, dict) and rule.get("type") == rule_type for rule in rules)


def ruleset_named(rulesets: Any, name: str, target: str | None = None) -> dict[str, Any] | None:
    items = rulesets.get("rulesets") if isinstance(rulesets, dict) else rulesets
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("name") != name:
            continue
        if target is not None and item.get("target") != target:
            continue
        return item
    return None


def environment_reviewers(environment: dict[str, Any]) -> int:
    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        return 0
    reviewers = 0
    for rule in protection_rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") == "required_reviewers":
            raw = rule.get("reviewers")
            if isinstance(raw, list):
                reviewers += len(raw)
            elif isinstance(rule.get("reviewer_count"), int):
                reviewers += int(rule["reviewer_count"])
    return reviewers


def codeowners_patterns(snapshot: Any) -> set[str]:
    if isinstance(snapshot, dict) and isinstance(snapshot.get("patterns"), list):
        return {str(item) for item in snapshot["patterns"]}
    return set()


def validate(policy: dict[str, Any], snapshot_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if policy.get("schema_version") not in {POLICY_SCHEMA_VERSION} | LEGACY_POLICY_SCHEMA_VERSIONS:
        failures.append(f"policy schema_version must be {POLICY_SCHEMA_VERSION}")

    branch = read_json(snapshot_root / "main-branch-protection.json")
    rulesets = read_json(snapshot_root / "rulesets.json")
    environment = read_json(snapshot_root / "release-publish-environment.json")
    tag_protection = read_json(snapshot_root / "tag-protection.json")
    workflow_permissions = read_json(snapshot_root / "workflow-permissions.json")
    codeowners = read_json(snapshot_root / "codeowners.json")
    audit_log = read_json(snapshot_root / "audit-log.json")

    if not isinstance(branch, dict):
        failures.append("missing main-branch-protection.json")
    else:
        if not branch.get("required_pull_request_reviews"):
            failures.append("main branch must require pull request reviews")
        reviews = branch.get("required_pull_request_reviews") or {}
        if isinstance(reviews, dict):
            if not reviews.get("require_code_owner_reviews"):
                failures.append("main branch must require CODEOWNERS review")
            if not reviews.get("dismiss_stale_reviews"):
                failures.append("main branch must dismiss stale reviews")
            approvals = reviews.get("required_approving_review_count")
            if not isinstance(approvals, int) or approvals < 1:
                failures.append("main branch must require at least one approval")
        if branch.get("allow_force_pushes", {}).get("enabled") is True:
            failures.append("main branch must not allow force pushes")
        if branch.get("allow_deletions", {}).get("enabled") is True:
            failures.append("main branch must not allow deletions")
        if branch.get("required_linear_history", {}).get("enabled") is not True:
            failures.append("main branch must require linear history")
        if branch.get("required_signatures", {}).get("enabled") is not True:
            failures.append("main branch must require signed commits")
        missing_checks = sorted(set(policy.get("required_checks", [])) - status_check_contexts(branch))
        if missing_checks:
            failures.append(f"missing required status checks: {', '.join(missing_checks)}")

    rule_policy = policy.get("ruleset", {})
    branch_ruleset = ruleset_named(rulesets, str(rule_policy.get("branch_name", "")), "branch")
    if branch_ruleset is None:
        failures.append("missing active branch ruleset")
    else:
        if branch_ruleset.get("enforcement") != "active":
            failures.append("branch ruleset must be active")
        bypass = branch_ruleset.get("bypass_actors")
        if rule_policy.get("allow_bypass_actors") is False and bypass:
            failures.append("branch ruleset must not have bypass actors")
        rules = branch_ruleset.get("rules") if isinstance(branch_ruleset.get("rules"), list) else []
        for required_rule in ("pull_request", "required_signatures", "non_fast_forward", "required_linear_history"):
            if not has_rule(rules, required_rule):
                failures.append(f"branch ruleset missing rule: {required_rule}")

    tag_ruleset = ruleset_named(rulesets, str(rule_policy.get("tag_name", "")), "tag")
    if tag_ruleset is None:
        failures.append("release tag ruleset must exist")
    else:
        if tag_ruleset.get("enforcement") != "active":
            failures.append("tag ruleset must be active")
        bypass = tag_ruleset.get("bypass_actors")
        if rule_policy.get("allow_bypass_actors") is False and bypass:
            failures.append("tag ruleset must not have bypass actors")
        rules = tag_ruleset.get("rules") if isinstance(tag_ruleset.get("rules"), list) else []
        if not has_rule(rules, "non_fast_forward"):
            failures.append("tag ruleset missing rule: non_fast_forward")
    if tag_protection:
        warnings.append("legacy tag protection snapshot is ignored; release tags must be governed by rulesets")

    env_policy = policy.get("release_environment", {})
    if not isinstance(environment, dict):
        failures.append("missing release-publish-environment.json")
    else:
        if environment.get("name") != env_policy.get("name"):
            failures.append("release environment name mismatch")
        if environment_reviewers(environment) < int(env_policy.get("minimum_reviewers", 1)):
            failures.append("release environment must require reviewers")
        if env_policy.get("prevent_self_review") is True and environment.get("prevent_self_review") is not True:
            failures.append("release environment must prevent self review")
        deployment_policy = environment.get("deployment_branch_policy")
        if isinstance(deployment_policy, dict):
            if deployment_policy.get("protected_branches") is True and deployment_policy.get("custom_branch_policies") is not True:
                failures.append("release environment must use selected tag refs, not only protected branches")

    if isinstance(workflow_permissions, dict):
        default_workflow_permissions = workflow_permissions.get("default_workflow_permissions")
        if default_workflow_permissions == "write":
            failures.append("repository default workflow permissions must not be write")
        if workflow_permissions.get("can_approve_pull_request_reviews") is True:
            failures.append("GitHub Actions must not approve pull request reviews")
    else:
        warnings.append("workflow-permissions.json not collected")

    missing_codeowners = sorted(set(policy.get("required_codeowners_patterns", [])) - codeowners_patterns(codeowners))
    if missing_codeowners:
        failures.append(f"missing CODEOWNERS patterns: {', '.join(missing_codeowners)}")

    if not isinstance(audit_log, dict):
        failures.append("audit-log.json must be collected")
    else:
        if audit_log.get("status") != "collected":
            failures.append("audit log must be collected")
        if audit_log.get("unapproved_governance_changes"):
            failures.append("audit log contains unapproved governance changes")
        if not isinstance(audit_log.get("events_sha256"), str):
            failures.append("audit log must include events_sha256")

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if not failures else "failed",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "policy": str(snapshot_root),
        "failures": failures,
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = read_json(args.policy)
    if not isinstance(policy, dict):
        print(f"ERROR: cannot read policy JSON: {args.policy}", file=sys.stderr)
        return 1
    result = validate(policy, args.snapshot_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result["status"] != "passed":
        for failure in result["failures"]:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated governance policy: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
