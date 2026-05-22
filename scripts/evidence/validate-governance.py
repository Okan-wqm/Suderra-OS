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


def ruleset_ref_includes(ruleset: dict[str, Any], expected: str, aliases: set[str]) -> bool:
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    includes = ref_name.get("include")
    if not isinstance(includes, list):
        return False
    accepted = {expected, *aliases}
    return any(isinstance(item, str) and item in accepted for item in includes)


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


def environment_reviewer_identities(environment: dict[str, Any]) -> set[str]:
    identities: set[str] = set()
    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        return identities
    for rule in protection_rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_reviewers":
            continue
        raw = rule.get("reviewers")
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, dict):
                continue
            reviewer = item.get("reviewer")
            reviewer_type = str(item.get("type", "")).lower()
            if isinstance(reviewer, dict):
                for key in ("slug", "login", "name"):
                    value = reviewer.get(key)
                    if isinstance(value, str) and value:
                        identities.add(value)
                        identities.add(f"{reviewer_type}:{value}")
    return identities


def deployment_policy_patterns(snapshot: Any) -> set[str]:
    items = snapshot.get("branch_policies") if isinstance(snapshot, dict) else snapshot
    if not isinstance(items, list):
        return set()
    patterns: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str):
            patterns.add(name)
            if item.get("type") == "tag" and not name.startswith("refs/tags/"):
                patterns.add(f"refs/tags/{name}")
    return patterns


def codeowners_patterns(snapshot: Any) -> set[str]:
    if isinstance(snapshot, dict) and isinstance(snapshot.get("patterns"), list):
        return {str(item) for item in snapshot["patterns"]}
    return set()


def validate_environment_policy(
    failures: list[str],
    snapshot_root: Path,
    env_policy: Any,
    *,
    policy_name: str,
) -> None:
    if not isinstance(env_policy, dict):
        failures.append(f"{policy_name} policy must be an object")
        return
    env_name = env_policy.get("name")
    if not isinstance(env_name, str) or not env_name:
        failures.append(f"{policy_name} policy must name a GitHub environment")
        return
    environment = read_json(snapshot_root / f"{env_name}-environment.json")
    deployment_policies = read_json(snapshot_root / f"{env_name}-deployment-branch-policies.json")
    if not isinstance(environment, dict):
        failures.append(f"missing {env_name}-environment.json")
        return
    if environment.get("name") != env_name:
        failures.append(f"{env_name} environment name mismatch")
    if environment_reviewers(environment) < int(env_policy.get("minimum_reviewers", 1)):
        failures.append(f"{env_name} environment must require reviewers")
    required_reviewers = env_policy.get("required_reviewers", [])
    if isinstance(required_reviewers, list) and required_reviewers:
        identities = environment_reviewer_identities(environment)
        missing_reviewers = sorted(str(item) for item in required_reviewers if str(item) not in identities)
        if missing_reviewers:
            failures.append(
                f"{env_name} environment missing required reviewer identities: "
                + ", ".join(missing_reviewers)
            )
    if env_policy.get("prevent_self_review") is True and environment.get("prevent_self_review") is not True:
        failures.append(f"{env_name} environment must prevent self review")
    deployment_policy = environment.get("deployment_branch_policy")
    if isinstance(deployment_policy, dict):
        if deployment_policy.get("protected_branches") is True and deployment_policy.get("custom_branch_policies") is not True:
            failures.append(f"{env_name} environment must use selected tag refs, not only protected branches")
        if env_policy.get("allowed_ref") and deployment_policy.get("custom_branch_policies") is not True:
            failures.append(f"{env_name} environment must use custom selected tag refs")
    elif env_policy.get("allowed_ref"):
        failures.append(f"{env_name} environment deployment branch policy must be collected")
    allowed_ref = env_policy.get("allowed_ref")
    if allowed_ref:
        patterns = deployment_policy_patterns(deployment_policies)
        allowed_alias = str(allowed_ref).removeprefix("refs/tags/")
        if str(allowed_ref) not in patterns and allowed_alias not in patterns:
            failures.append(f"{env_name} environment deployment policy must include {allowed_ref}")


def validate(policy: dict[str, Any], snapshot_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    if policy.get("schema_version") not in {POLICY_SCHEMA_VERSION} | LEGACY_POLICY_SCHEMA_VERSIONS:
        failures.append(f"policy schema_version must be {POLICY_SCHEMA_VERSION}")

    branch = read_json(snapshot_root / "main-branch-protection.json")
    rulesets = read_json(snapshot_root / "rulesets.json")
    tag_protection = read_json(snapshot_root / "tag-protection.json")
    workflow_permissions = read_json(snapshot_root / "workflow-permissions.json")
    codeowners = read_json(snapshot_root / "codeowners.json")
    audit_log = read_json(snapshot_root / "audit-log.json")

    if not isinstance(branch, dict):
        failures.append("missing main-branch-protection.json")
    else:
        branch_policy = policy.get("branch_protection", {})
        if not isinstance(branch_policy, dict):
            branch_policy = {}
        minimum_approvals = int(branch_policy.get("minimum_approving_reviews", 1))
        if not branch.get("required_pull_request_reviews"):
            failures.append("main branch must require pull request reviews")
        reviews = branch.get("required_pull_request_reviews") or {}
        if isinstance(reviews, dict):
            if not reviews.get("require_code_owner_reviews"):
                failures.append("main branch must require CODEOWNERS review")
            if not reviews.get("dismiss_stale_reviews"):
                failures.append("main branch must dismiss stale reviews")
            approvals = reviews.get("required_approving_review_count")
            if not isinstance(approvals, int) or approvals < minimum_approvals:
                failures.append(f"main branch must require at least {minimum_approvals} approvals")
        if branch.get("allow_force_pushes", {}).get("enabled") is True:
            failures.append("main branch must not allow force pushes")
        if branch.get("allow_deletions", {}).get("enabled") is True:
            failures.append("main branch must not allow deletions")
        if branch.get("required_linear_history", {}).get("enabled") is not True:
            failures.append("main branch must require linear history")
        if branch.get("required_signatures", {}).get("enabled") is not True:
            failures.append("main branch must require signed commits")
        policy_checks = set(policy.get("required_checks", []))
        live_checks = status_check_contexts(branch)
        missing_checks = sorted(policy_checks - live_checks)
        if missing_checks:
            failures.append(f"missing required status checks: {', '.join(missing_checks)}")
        extra_checks = sorted(live_checks - policy_checks)
        if extra_checks:
            failures.append(f"unexpected required status checks: {', '.join(extra_checks)}")

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
        protected_branch = str(policy.get("protected_branch", "main"))
        if not ruleset_ref_includes(
            branch_ruleset,
            f"refs/heads/{protected_branch}",
            {protected_branch, "~DEFAULT_BRANCH"},
        ):
            failures.append(f"branch ruleset must apply to refs/heads/{protected_branch}")

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
        allowed_ref = str(policy.get("release_environment", {}).get("allowed_ref", "refs/tags/v*"))
        if not ruleset_ref_includes(tag_ruleset, allowed_ref, {allowed_ref.removeprefix("refs/tags/")}):
            failures.append(f"tag ruleset must apply to {allowed_ref}")
    if tag_protection:
        warnings.append("legacy tag protection snapshot is ignored; release tags must be governed by rulesets")

    validate_environment_policy(
        failures,
        snapshot_root,
        policy.get("signing_environment"),
        policy_name="signing_environment",
    )
    validate_environment_policy(
        failures,
        snapshot_root,
        policy.get("release_environment"),
        policy_name="release_environment",
    )

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
