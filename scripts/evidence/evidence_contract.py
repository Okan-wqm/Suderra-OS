#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Load the Suderra enterprise evidence SSOT contract.

The contract file is stored as JSON-compatible YAML so all release tooling can
consume it with Python's standard library. Evidence producers and validators
must read policy from this module instead of duplicating target gates, schema
versions, runtime scenarios, adapter roles, or signing roles.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "ci" / "evidence-contract.yml"
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
CONTRACT_SCHEMA_VERSION = "suderra.evidence-contract.v1"
EXPECTED_OUTCOMES = {
    "booted",
    "firmware-rejected",
    "kernel-rejected",
    "userspace-rejected",
    "rollback-completed",
}
OBSERVED_LAYERS = {"firmware", "kernel", "runtime", "storage", "userspace"}
UNSIGNED_SIGNING_MODES = {"unsigned-lab", "unsupported"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_VALUES = {
    "",
    "TODO",
    "TBD",
    "TO_BE_COLLECTED",
    "PLACEHOLDER",
    "not_collected",
    "NOT_COLLECTED",
    "pending",
    "PENDING",
}
EXPECTED_PROFILES = {
    "ci",
    "dev",
    "ga",
    "technical-dry-run",
    "rc-evidence-dry-run",
    "release-candidate",
    "production-candidate",
}
PROFILE_BOOL_FIELDS = {
    "production_candidate",
    "prerelease_only",
    "release_authorizing",
    "publication_allowed",
    "strict_artifact_binding",
    "subject_graph_required",
    "gap_report_required",
    "operator_ingress_required",
}
PROFILE_FIELDS = PROFILE_BOOL_FIELDS | {"required_output_trees"}


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read evidence contract {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"evidence contract must be JSON-compatible YAML: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("evidence contract top-level value must be an object")
    validate_contract(payload)
    return payload


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path} must be a non-empty string list")
    return list(value)


def _string_sequence(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path} must be a string list")
    return list(value)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def validate_contract(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise ValueError(f"evidence contract schema_version must be {CONTRACT_SCHEMA_VERSION}")
    schemas = _object(payload.get("schema_versions"), "schema_versions")
    for field in (
        "hsm_signing_session",
        "lab_evidence",
        "machine_verification",
        "hardware_subject",
        "ota_artifacts",
        "ota_target_contract",
        "production_runtime_suite",
        "release_evidence",
        "release_security_report",
        "release_subject_graph",
        "retention_manifest",
        "runtime_observation",
        "signing_manifest",
        "governance_role_bindings",
        "station_acquisition",
    ):
        if not isinstance(schemas.get(field), str) or not schemas[field]:
            raise ValueError(f"schema_versions.{field} must be a non-empty string")
    profiles = _object(payload.get("profiles"), "profiles")
    if set(profiles) != EXPECTED_PROFILES:
        missing = sorted(EXPECTED_PROFILES - set(profiles))
        extra = sorted(set(profiles) - EXPECTED_PROFILES)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise ValueError("profiles must match the governed profile catalog: " + "; ".join(detail))
    for name, profile in profiles.items():
        if not isinstance(name, str) or not name:
            raise ValueError("profiles keys must be non-empty strings")
        profile_obj = _object(profile, f"profiles.{name}")
        unknown_fields = sorted(set(profile_obj) - PROFILE_FIELDS)
        missing_fields = sorted(PROFILE_FIELDS - set(profile_obj))
        if unknown_fields:
            raise ValueError(f"profiles.{name} contains unknown fields: {', '.join(unknown_fields)}")
        if missing_fields:
            raise ValueError(f"profiles.{name} missing fields: {', '.join(missing_fields)}")
        for field in sorted(PROFILE_BOOL_FIELDS):
            if not isinstance(profile_obj.get(field), bool):
                raise ValueError(f"profiles.{name}.{field} must be a boolean")
        _string_sequence(profile_obj.get("required_output_trees"), f"profiles.{name}.required_output_trees")
    expected_profile_values = {
        "rc-evidence-dry-run": {
            "production_candidate": False,
            "prerelease_only": True,
            "release_authorizing": False,
            "publication_allowed": False,
            "strict_artifact_binding": True,
            "subject_graph_required": True,
            "gap_report_required": True,
            "operator_ingress_required": False,
        },
        "release-candidate": {
            "production_candidate": False,
            "prerelease_only": True,
            "release_authorizing": True,
            "publication_allowed": True,
            "subject_graph_required": True,
            "operator_ingress_required": True,
        },
        "production-candidate": {
            "production_candidate": True,
            "prerelease_only": False,
            "release_authorizing": True,
            "publication_allowed": True,
            "strict_artifact_binding": True,
            "subject_graph_required": True,
            "operator_ingress_required": True,
        },
    }
    for name, expected_values in expected_profile_values.items():
        profile_obj = _object(profiles.get(name), f"profiles.{name}")
        for field, expected in expected_values.items():
            if profile_obj.get(field) is not expected:
                raise ValueError(f"profiles.{name}.{field} must be {expected!r}")
    output_trees = _object(payload.get("output_trees"), "output_trees")
    if output_trees.get("schema_version") != "suderra.output-tree-policy.v1":
        raise ValueError("output_trees.schema_version must be suderra.output-tree-policy.v1")
    trees = _object(output_trees.get("trees"), "output_trees.trees")
    required_trees = {
        "build-artifacts",
        "release-inputs",
        "release-ingress",
        "release-subject-graph",
        "release-dry-run",
        "release-lab-input",
        "release-governance",
        "release-runtime",
        "release-signing",
        "release-retention",
        "release-ota",
        "release-approvals",
        "release-security",
        "release-reproducibility",
    }
    missing_trees = sorted(required_trees - set(trees))
    if missing_trees:
        raise ValueError(f"output_trees.trees missing roots: {', '.join(missing_trees)}")
    seen_templates: set[str] = set()
    for name, tree in trees.items():
        tree_obj = _object(tree, f"output_trees.trees.{name}")
        if not isinstance(name, str) or not name:
            raise ValueError("output_trees.trees keys must be non-empty strings")
        path_template = tree_obj.get("path_template")
        if not isinstance(path_template, str) or not path_template:
            raise ValueError(f"output_trees.trees.{name}.path_template must be a non-empty string")
        rendered_template = path_template.replace("{version}", "v0")
        if safe_relative_path(rendered_template) is None:
            raise ValueError(f"output_trees.trees.{name}.path_template must be a safe relative path template")
        if path_template in seen_templates:
            raise ValueError(f"output_trees.trees.{name}.path_template must be unique")
        seen_templates.add(path_template)
        if not isinstance(tree_obj.get("schema_role"), str) or not tree_obj["schema_role"]:
            raise ValueError(f"output_trees.trees.{name}.schema_role must be a non-empty string")
        for field in (
            "required_by_default",
            "promotable",
            "operator_ingress_allowed",
            "release_tag_allowed",
            "dry_run_input_allowed",
            "gitignore_required",
        ):
            if not isinstance(tree_obj.get(field), bool):
                raise ValueError(f"output_trees.trees.{name}.{field} must be a boolean")
        if tree_obj.get("release_tag_allowed") is False and tree_obj.get("promotable") is True:
            raise ValueError(f"output_trees.trees.{name}: release_tag_allowed=false requires promotable=false")
    dry_run_tree = _object(trees.get("release-dry-run"), "output_trees.trees.release-dry-run")
    for field in ("promotable", "operator_ingress_allowed", "release_tag_allowed"):
        if dry_run_tree.get(field) is not False:
            raise ValueError(f"output_trees.trees.release-dry-run.{field} must be false")
    if dry_run_tree.get("gitignore_required") is not True:
        raise ValueError("output_trees.trees.release-dry-run.gitignore_required must be true")
    if dry_run_tree.get("dry_run_input_allowed") is not True:
        raise ValueError("output_trees.trees.release-dry-run.dry_run_input_allowed must be true")
    for name, profile in profiles.items():
        for root in _string_sequence(profile.get("required_output_trees"), f"profiles.{name}.required_output_trees"):
            if root not in trees:
                raise ValueError(f"profiles.{name}.required_output_trees references unknown output tree {root}")
        if profile.get("subject_graph_required") is True and "release-subject-graph" not in profile["required_output_trees"]:
            raise ValueError(f"profiles.{name}.required_output_trees must include release-subject-graph")
        if profile.get("gap_report_required") is True and "release-dry-run" not in profile["required_output_trees"]:
            raise ValueError(f"profiles.{name}.required_output_trees must include release-dry-run")
    subjects = _object(payload.get("subjects"), "subjects")
    if subjects.get("schema_version") != schemas["release_subject_graph"]:
        raise ValueError("subjects.schema_version must match schema_versions.release_subject_graph")
    if not isinstance(subjects.get("subject_id_template"), str) or not subjects["subject_id_template"]:
        raise ValueError("subjects.subject_id_template must be a non-empty string")
    for token in ("{version}", "{target}", "{source_sha}", "{source_run_id}"):
        if token not in subjects["subject_id_template"]:
            raise ValueError(f"subjects.subject_id_template must include {token}")
    _string_list(subjects.get("identity_fields"), "subjects.identity_fields")
    _string_list(subjects.get("artifact_fields"), "subjects.artifact_fields")
    _string_list(subjects.get("subject_roles"), "subjects.subject_roles")
    exports = _object(subjects.get("required_subject_exports"), "subjects.required_subject_exports")
    for name, template in exports.items():
        if not isinstance(name, str) or not name:
            raise ValueError("subjects.required_subject_exports keys must be non-empty strings")
        if not isinstance(template, str) or not template:
            raise ValueError(f"subjects.required_subject_exports.{name} must be a non-empty string")
    join_requirements = _object(subjects.get("join_requirements"), "subjects.join_requirements")
    for field in (
        "fail_closed_on_unknown_target",
        "runtime_required_targets_require_suite",
        "signing_required_targets_require_manifest",
        "hardware_required_targets_require_subject",
        "release_public_must_match_matrix_release",
        "all_evidence_must_bind_subject_id",
    ):
        if join_requirements.get(field) is not True:
            raise ValueError(f"subjects.join_requirements.{field} must be true")
    runtime = _object(payload.get("runtime"), "runtime")
    authority = _object(runtime.get("observation_authority"), "runtime.observation_authority")
    if authority.get("schema_version") != schemas["runtime_observation"]:
        raise ValueError("runtime.observation_authority.schema_version must match schema_versions.runtime_observation")
    _string_list(authority.get("observed_outcome_sources"), "runtime.observation_authority.observed_outcome_sources")
    _string_list(authority.get("forbidden_sources"), "runtime.observation_authority.forbidden_sources")
    if authority.get("raw_replay_required") is not True:
        raise ValueError("runtime.observation_authority.raw_replay_required must be true")
    required_checks = _string_list(runtime.get("required_checks"), "runtime.required_checks")
    required_scenarios = _string_list(runtime.get("required_scenarios"), "runtime.required_scenarios")
    scenario_to_checks = _object(runtime.get("scenario_to_checks"), "runtime.scenario_to_checks")
    for scenario, checks in scenario_to_checks.items():
        if scenario not in required_scenarios:
            raise ValueError(f"runtime.scenario_to_checks.{scenario} is not a required scenario")
        for check in _string_list(checks, f"runtime.scenario_to_checks.{scenario}"):
            if check not in required_checks:
                raise ValueError(f"runtime.scenario_to_checks.{scenario} references unknown check {check}")
    scenario_contracts = _object(runtime.get("scenario_contracts"), "runtime.scenario_contracts")
    missing_contracts = sorted(set(required_scenarios) - set(scenario_contracts))
    unexpected_contracts = sorted(set(scenario_contracts) - set(required_scenarios))
    if missing_contracts:
        raise ValueError(f"runtime.scenario_contracts missing scenarios: {', '.join(missing_contracts)}")
    if unexpected_contracts:
        raise ValueError(f"runtime.scenario_contracts contains unknown scenarios: {', '.join(unexpected_contracts)}")
    for scenario, contract in scenario_contracts.items():
        contract_obj = _object(contract, f"runtime.scenario_contracts.{scenario}")
        if contract_obj.get("expected_outcome") not in EXPECTED_OUTCOMES:
            raise ValueError(f"runtime.scenario_contracts.{scenario}.expected_outcome is unsupported")
        if contract_obj.get("observed_layer") not in OBSERVED_LAYERS:
            raise ValueError(f"runtime.scenario_contracts.{scenario}.observed_layer is unsupported")
        _string_list(contract_obj.get("observation_source"), f"runtime.scenario_contracts.{scenario}.observation_source")
        _string_list(contract_obj.get("required_log_roles"), f"runtime.scenario_contracts.{scenario}.required_log_roles")
        for field in ("mutation_type", "mutation_target"):
            if not isinstance(contract_obj.get(field), str) or not contract_obj[field]:
                raise ValueError(f"runtime.scenario_contracts.{scenario}.{field} must be a non-empty string")
        if not isinstance(contract_obj.get("guest_facts_required"), bool):
            raise ValueError(f"runtime.scenario_contracts.{scenario}.guest_facts_required must be a boolean")
    suite_targets = _object(runtime.get("suite_targets"), "runtime.suite_targets")
    for target, suites in suite_targets.items():
        if not isinstance(target, str) or not target:
            raise ValueError("runtime.suite_targets keys must be non-empty strings")
        if not isinstance(suites, list) or not all(isinstance(item, str) and item for item in suites):
            raise ValueError(f"runtime.suite_targets.{target} must be a string list")
    hardware = _object(payload.get("hardware"), "hardware")
    _string_list(hardware.get("adapter_roles"), "hardware.adapter_roles")
    subject_binding = _object(hardware.get("subject_binding"), "hardware.subject_binding")
    if subject_binding.get("schema_version") != schemas["hardware_subject"]:
        raise ValueError("hardware.subject_binding.schema_version must match schema_versions.hardware_subject")
    _string_list(subject_binding.get("required_fields"), "hardware.subject_binding.required_fields")
    for field in (
        "readback_must_match_build_subject",
        "station_registry_required",
        "adapter_inventory_must_match_registry",
        "station_acquisition_event_required",
    ):
        if subject_binding.get(field) is not True:
            raise ValueError(f"hardware.subject_binding.{field} must be true")
    if subject_binding.get("producer_source") != "station-acquisition":
        raise ValueError("hardware.subject_binding.producer_source must be station-acquisition")
    _string_list(hardware.get("required_checks"), "hardware.required_checks")
    _string_list(hardware.get("x86_required_checks"), "hardware.x86_required_checks")
    _string_list(hardware.get("x86_required_negative_tests"), "hardware.x86_required_negative_tests")
    boards = _object(hardware.get("required_boards_by_target"), "hardware.required_boards_by_target")
    for target, target_boards in boards.items():
        _string_list(target_boards, f"hardware.required_boards_by_target.{target}")
    signing = _object(payload.get("signing"), "signing")
    if signing.get("manifest_schema_version") != schemas["signing_manifest"]:
        raise ValueError("signing.manifest_schema_version must match schema_versions.signing_manifest")
    if not isinstance(signing.get("request_schema_version"), str) or not signing["request_schema_version"]:
        raise ValueError("signing.request_schema_version must be a non-empty string")
    _string_list(signing.get("manifest_required_fields"), "signing.manifest_required_fields")
    _string_list(signing.get("role_required_fields"), "signing.role_required_fields")
    digest_semantics = _object(signing.get("digest_semantics"), "signing.digest_semantics")
    for field in ("input_sha256", "output_sha256", "certificate_sha256", "challenge_transcript_sha256", "artifact_signature_sha256"):
        if not isinstance(digest_semantics.get(field), str) or not digest_semantics[field]:
            raise ValueError(f"signing.digest_semantics.{field} must be a non-empty string")
    replay = _object(signing.get("replay_requirements"), "signing.replay_requirements")
    for field in (
        "certificate_key_match_required",
        "challenge_signature_replay_required",
        "artifact_signature_replay_required",
        "transcript_digest_replay_required",
        "software_hsm_rejected_for_production",
    ):
        if replay.get(field) is not True:
            raise ValueError(f"signing.replay_requirements.{field} must be true")
    signing_roles = _string_list(signing.get("signed_artifact_roles"), "signing.signed_artifact_roles")
    role_bindings = _object(signing.get("role_bindings"), "signing.role_bindings")
    missing_role_bindings = sorted(set(signing_roles) - set(role_bindings))
    if missing_role_bindings:
        raise ValueError(f"signing.role_bindings missing roles: {', '.join(missing_role_bindings)}")
    for role, binding in role_bindings.items():
        if role not in signing_roles:
            raise ValueError(f"signing.role_bindings.{role} is not a signed artifact role")
        binding_obj = _object(binding, f"signing.role_bindings.{role}")
        if not isinstance(binding_obj.get("digest_source"), str) or not binding_obj["digest_source"]:
            raise ValueError(f"signing.role_bindings.{role}.digest_source must be a non-empty string")
        for field in ("final_digest_field", "input_digest_field"):
            if not isinstance(binding_obj.get(field), str) or not binding_obj[field]:
                raise ValueError(f"signing.role_bindings.{role}.{field} must be a non-empty string")
    ota = _object(payload.get("ota"), "ota")
    if ota.get("target_contract_schema_version") != schemas["ota_target_contract"]:
        raise ValueError("ota.target_contract_schema_version must match schema_versions.ota_target_contract")
    ota_targets = _object(ota.get("targets"), "ota.targets")
    targets = _object(payload.get("targets"), "targets")
    for target, policy in targets.items():
        policy_obj = _object(policy, f"targets.{target}")
        for field in (
            "hardware_required",
            "ota_capable",
            "production_gate",
            "release_image_scan_required",
            "release_public",
            "runtime_required",
            "signing_required",
        ):
            if not isinstance(policy_obj.get(field), bool):
                raise ValueError(f"targets.{target}.{field} must be a boolean")
        ota_policy = _object(ota_targets.get(target), f"ota.targets.{target}")
        if ota_policy.get("ota_capable") != policy_obj.get("ota_capable"):
            raise ValueError(f"ota.targets.{target}.ota_capable must match targets.{target}.ota_capable")
        for field in (
            "backend",
            "boot_backend",
            "compatible",
            "health_policy",
            "lifecycle",
            "mark_good_policy",
            "rollback_state",
            "rollback_storage",
        ):
            if not isinstance(ota_policy.get(field), str) or not ota_policy[field]:
                raise ValueError(f"ota.targets.{target}.{field} must be a non-empty string")
        for field in ("bundle_artifacts", "health_checks", "slot_labels", "verity_devices"):
            values = _string_sequence(ota_policy.get(field), f"ota.targets.{target}.{field}")
            if policy_obj.get("ota_capable") is True and not values:
                raise ValueError(f"ota.targets.{target}.{field} must be non-empty for ota_capable targets")
        if policy_obj.get("ota_capable") is False and ota_policy.get("rollback_storage") != "not-applicable":
            raise ValueError(f"ota.targets.{target}.rollback_storage must be not-applicable for non-OTA targets")
    for target in ota_targets:
        if target not in targets:
            raise ValueError(f"ota.targets.{target} has no matching target policy")
    retention = _object(payload.get("retention"), "retention")
    if retention.get("manifest_schema_version") != schemas["retention_manifest"]:
        raise ValueError("retention.manifest_schema_version must match schema_versions.retention_manifest")
    if not isinstance(retention.get("policy_id"), str) or not retention["policy_id"]:
        raise ValueError("retention.policy_id must be a non-empty string")
    if not isinstance(retention.get("store_class"), str) or not retention["store_class"]:
        raise ValueError("retention.store_class must be a non-empty string")
    if not isinstance(retention.get("minimum_years"), int) or retention["minimum_years"] < 7:
        raise ValueError("retention.minimum_years must be at least 7")
    for field in ("kms_required", "legal_hold_supported", "access_log_required"):
        if retention.get(field) is not True:
            raise ValueError(f"retention.{field} must be true")
    _string_list(retention.get("required_replay"), "retention.required_replay")
    retention_exports = _string_list(retention.get("required_exports"), "retention.required_exports")
    for required_export in ("release-inputs", "release-subject-graph"):
        if required_export not in retention_exports:
            raise ValueError(f"retention.required_exports must include {required_export}")


def schema_version(name: str, contract: dict[str, Any] | None = None) -> str:
    payload = contract or load_contract()
    value = payload["schema_versions"].get(name)
    if not isinstance(value, str) or not value:
        raise KeyError(name)
    return value


def target_policy(target: str, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    policy = payload.get("targets", {}).get(target, {})
    return dict(policy) if isinstance(policy, dict) else {}


def runtime_required_checks(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["runtime"]["required_checks"])


def runtime_required_scenarios(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["runtime"]["required_scenarios"])


def runtime_scenario_to_checks(contract: dict[str, Any] | None = None) -> dict[str, tuple[str, ...]]:
    payload = contract or load_contract()
    return {
        str(name): tuple(str(item) for item in checks)
        for name, checks in payload["runtime"]["scenario_to_checks"].items()
    }


def runtime_scenario_contracts(contract: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    payload = contract or load_contract()
    return {
        str(name): dict(value)
        for name, value in payload["runtime"]["scenario_contracts"].items()
        if isinstance(value, dict)
    }


def runtime_suite_targets_for(target: str, contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    suites = payload["runtime"]["suite_targets"].get(target, [])
    return [str(item) for item in suites]


def hardware_required_checks(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["hardware"]["required_checks"])


def x86_hardware_required_checks(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["hardware"]["x86_required_checks"])


def x86_required_negative_tests(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["hardware"]["x86_required_negative_tests"])


def required_hardware_boards_by_target(contract: dict[str, Any] | None = None) -> dict[str, tuple[str, ...]]:
    payload = contract or load_contract()
    return {
        str(target): tuple(str(board) for board in boards)
        for target, boards in payload["hardware"]["required_boards_by_target"].items()
    }


def adapter_roles(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["hardware"]["adapter_roles"])


def signed_artifact_roles(contract: dict[str, Any] | None = None) -> set[str]:
    payload = contract or load_contract()
    return {str(item) for item in payload["signing"]["signed_artifact_roles"]}


def signing_role_bindings(contract: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    payload = contract or load_contract()
    return {
        str(role): dict(binding)
        for role, binding in payload["signing"]["role_bindings"].items()
        if isinstance(binding, dict)
    }


def ota_target_policy(target: str, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    policy = payload["ota"]["targets"].get(target, {})
    return dict(policy) if isinstance(policy, dict) else {}


def retention_required_exports(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return list(payload["retention"]["required_exports"])


def subject_policy(contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    return dict(payload["subjects"])


def retention_policy(contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    return dict(payload["retention"])


def profile_policy(profile: str, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    policy = payload.get("profiles", {}).get(profile)
    if not isinstance(policy, dict):
        raise ValueError(f"profile {profile!r} is missing from ci/evidence-contract.yml")
    return dict(policy)


def all_profiles(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return sorted(str(name) for name in payload["profiles"])


def release_authorizing_profiles(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return sorted(
        str(name)
        for name, profile in payload["profiles"].items()
        if isinstance(profile, dict) and profile.get("release_authorizing") is True
    )


def publication_allowed_profiles(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return sorted(
        str(name)
        for name, profile in payload["profiles"].items()
        if isinstance(profile, dict) and profile.get("publication_allowed") is True
    )


def operator_ingress_required_profiles(contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    return sorted(
        str(name)
        for name, profile in payload["profiles"].items()
        if isinstance(profile, dict) and profile.get("operator_ingress_required") is True
    )


def release_subject_id(
    *,
    version: str,
    target: str,
    source_sha: str,
    source_run_id: str,
    contract: dict[str, Any] | None = None,
) -> str:
    payload = contract or load_contract()
    template = str(payload["subjects"]["subject_id_template"])
    return template.format(
        version=version,
        target=target,
        source_sha=source_sha,
        source_run_id=source_run_id,
    )


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip() in PLACEHOLDER_VALUES


def safe_relative_path(value: Any) -> Path | None:
    if is_placeholder(value) or not isinstance(value, str) or not value.strip():
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    return rel


def _matrix_row_for_target(matrix: dict[str, Any], target: str) -> dict[str, Any]:
    for row in matrix.get("defconfigs", []):
        if isinstance(row, dict) and row.get("target") == target:
            return row
    raise ValueError(f"target {target!r} is missing from ci/build-matrix.yml")


def _format_subject_export(template: str, *, version: str, target: str, profile: str) -> str:
    return template.format(version=version, target=target, profile=profile, scan="{scan}")


def output_tree_policy(contract: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = contract or load_contract()
    return payload["output_trees"]


def output_tree_roots(*, contract: dict[str, Any] | None = None) -> list[str]:
    policy = output_tree_policy(contract)
    return sorted(policy["trees"])


def output_tree_for_root(root: str, *, contract: dict[str, Any] | None = None) -> dict[str, Any] | None:
    policy = output_tree_policy(contract)
    tree = policy["trees"].get(root)
    return dict(tree) if isinstance(tree, dict) else None


def output_tree_path(root: str, *, version: str, contract: dict[str, Any] | None = None) -> str:
    tree = output_tree_for_root(root, contract=contract)
    if tree is None:
        raise ValueError(f"output tree {root!r} is missing from ci/evidence-contract.yml")
    return str(tree["path_template"]).format(version=version)


def required_output_roots(profile: str, *, contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    profile_obj = profile_policy(profile, payload)
    required = {
        name
        for name, tree in output_tree_policy(payload)["trees"].items()
        if isinstance(tree, dict) and tree.get("required_by_default") is True
    }
    required.update(str(root) for root in profile_obj.get("required_output_trees", []))
    return sorted(required)


def preflight_input_roots(profile: str, *, contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    roots = {root for root in required_output_roots(profile, contract=payload) if root != "build-artifacts"}
    if profile == "rc-evidence-dry-run":
        roots.update(
            root
            for root, tree in output_tree_policy(payload)["trees"].items()
            if isinstance(tree, dict) and tree.get("dry_run_input_allowed") is True
        )
    else:
        roots.update(
            root
            for root, tree in output_tree_policy(payload)["trees"].items()
            if isinstance(tree, dict) and (tree.get("operator_ingress_allowed") is True or tree.get("required_by_default") is True)
        )
    return sorted(roots)


def release_tag_allowed_roots(*, contract: dict[str, Any] | None = None) -> list[str]:
    policy = output_tree_policy(contract)
    return sorted(
        root
        for root, tree in policy["trees"].items()
        if isinstance(tree, dict) and tree.get("release_tag_allowed") is True
    )


def output_tree_schema_role(root: str, *, contract: dict[str, Any] | None = None) -> str:
    tree = output_tree_for_root(root, contract=contract)
    if tree is None:
        raise ValueError(f"output tree {root!r} is missing from ci/evidence-contract.yml")
    return str(tree["schema_role"])


def preflight_input_role_for_path(rel_path: Path, *, contract: dict[str, Any] | None = None) -> str:
    parts = rel_path.parts
    if not parts:
        return "preflight-input"
    root = parts[0]
    if root == "release-inputs":
        return "binding-manifest"
    if root == "release-lab-input" and rel_path.name == "qemu.json":
        return "qemu-input"
    if root == "release-lab-input" and rel_path.name == "qemu-semantic.json":
        return "qemu-semantic"
    if root == "release-lab-input" and rel_path.name in {"qemu-stderr.log", "stderr.log"}:
        return "qemu-stderr"
    if root == "release-lab-input" and rel_path.name == "lab.json":
        return "lab-input"
    if root == "release-lab-input" and rel_path.name == "hardware-subject.json":
        return "hardware-subject"
    if root == "release-lab-input" and rel_path.name == "station-acquisition.json":
        return "station-acquisition"
    if root == "release-lab-input" and rel_path.name == "station-bundle.json":
        return "lab-station-bundle"
    if root == "release-lab-input" and rel_path.name == "station-bundle.json.sig":
        return "lab-station-signature"
    if root == "release-lab-input" and rel_path.name == "station-public.pem":
        return "lab-station-public-key"
    if root == "release-governance" and rel_path.name == "role-bindings.json":
        return "governance-role-bindings"
    if root == "release-governance":
        return "governance-snapshot"
    if root == "release-approvals":
        return "approval"
    if root == "release-security":
        return "security-report"
    if root == "release-reproducibility":
        return "reproducibility-report"
    if root == "release-runtime" and rel_path.name == "production-runtime.json":
        return "production-runtime-suite"
    if root == "release-signing" and rel_path.name == "signing-manifest.json":
        return "signing-manifest"
    if root == "release-signing" and rel_path.suffix == ".json":
        return "hsm-signing-session"
    if root == "release-retention" and rel_path.name == "retention-manifest.json":
        return "retention-manifest"
    if root == "release-ota" and rel_path.name == "ota-artifacts.json":
        return "ota-artifacts"
    if root == "release-subject-graph" and rel_path.name == "release-subject-graph.json":
        return "release-subject-graph"
    if root == "release-ingress" and rel_path.name == "evidence-ingress-manifest.json":
        return "evidence-ingress"
    if root == "release-ingress" and rel_path.name in {
        "evidence-ingress-manifest.json.sig",
        "evidence-ingress-manifest.json.cert",
    }:
        return "evidence-ingress-signature"
    if root == "release-dry-run":
        return "rc-evidence-dry-run"
    return output_tree_schema_role(root, contract=contract) if output_tree_for_root(root, contract=contract) else "preflight-input"


def _release_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix.get("defconfigs", []) if isinstance(row, dict) and row.get("release") is True]


def _release_targets_requiring_hardware(matrix: dict[str, Any]) -> set[str]:
    targets: set[str] = set()
    for row in _release_rows(matrix):
        target = str(row.get("target", ""))
        acceptance = str(row.get("acceptance", ""))
        if row.get("production_required") or "hardware" in acceptance:
            targets.add(target)
    return targets


def operator_required_evidence_paths(
    *,
    version: str,
    matrix: dict[str, Any],
    contract: dict[str, Any] | None = None,
) -> set[str]:
    payload = contract or load_contract()
    required: set[str] = {
        f"release-governance/{version}/audit-log.json",
        f"release-governance/{version}/station-registry.json",
    }
    production_profile = "-" not in version
    if production_profile:
        required.add(f"release-governance/{version}/role-bindings.json")
        required.add(f"release-retention/{version}/retention-manifest.json")
        for scan in matrix.get("security_scans", []):
            required.add(f"release-security/{version}/{scan}.json")
    hardware_targets = _release_targets_requiring_hardware(matrix)
    for row in _release_rows(matrix):
        target = str(row["target"])
        policy = target_policy(target, payload)
        if row.get("qemu_test"):
            required.add(f"release-lab-input/{version}/{target}/qemu.json")
        if target in hardware_targets:
            required.add(f"release-lab-input/{version}/{target}/lab.json")
        if production_profile and policy.get("hardware_required") is True:
            required.add(f"release-lab-input/{version}/{target}/hardware-subject.json")
            required.add(f"release-lab-input/{version}/{target}/station-acquisition.json")
        if production_profile and policy.get("signing_required") is True:
            required.add(f"release-signing/{version}/{target}/signing-manifest.json")
        required.add(f"release-approvals/{version}/{target}.json")
        required.add(f"release-reproducibility/{version}/{target}.json")
    if production_profile:
        for target, policy in payload.get("targets", {}).items():
            if not isinstance(policy, dict) or policy.get("release_public") is True:
                continue
            if policy.get("runtime_required") is True:
                required.add(f"release-runtime/{version}/{target}/production-runtime.json")
            if policy.get("signing_required") is True:
                required.add(f"release-signing/{version}/{target}/signing-manifest.json")
            if policy.get("ota_capable") is True:
                required.add(f"release-ota/{version}/{target}/ota-artifacts.json")
    return required


def gitignore_required_roots(*, contract: dict[str, Any] | None = None) -> list[str]:
    policy = output_tree_policy(contract)
    return sorted(
        root
        for root, tree in policy["trees"].items()
        if isinstance(tree, dict) and tree.get("gitignore_required") is True
    )


def operator_ingress_allowed_roots(*, contract: dict[str, Any] | None = None) -> list[str]:
    policy = output_tree_policy(contract)
    return sorted(
        root
        for root, tree in policy["trees"].items()
        if isinstance(tree, dict) and tree.get("operator_ingress_allowed") is True
    )


def non_promotable_roots(*, contract: dict[str, Any] | None = None) -> list[str]:
    policy = output_tree_policy(contract)
    return sorted(
        root
        for root, tree in policy["trees"].items()
        if isinstance(tree, dict) and tree.get("promotable") is False
    )


def expected_release_artifact_map(matrix: dict[str, Any], matrix_module: Any) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(row["name"]), artifact): row
        for row in matrix.get("defconfigs", [])
        if isinstance(row, dict) and row.get("release") is True
        for artifact in matrix_module.expected_artifacts(row)
    }


def validate_release_artifact_bindings(
    artifacts: Any,
    expected_artifacts: dict[tuple[str, str], dict[str, Any]],
    *,
    artifact_root: Path | None = None,
    file_hasher: Any | None = None,
) -> list[str]:
    failures: list[str] = []
    if not isinstance(artifacts, list) or not artifacts:
        return ["binding artifacts must be a non-empty list"]
    seen: set[tuple[str, str]] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            failures.append(f"binding artifacts[{index}] must be an object")
            continue
        key = (str(artifact.get("defconfig")), str(artifact.get("artifact")))
        expected_row = expected_artifacts.get(key)
        if expected_artifacts and expected_row is None:
            failures.append(f"unexpected binding artifact: {key[0]} {key[1]}")
        elif expected_row is not None and artifact.get("target") != expected_row.get("target"):
            failures.append(f"binding artifact {key[0]} {key[1]} target must be {expected_row.get('target')}")
        if key in seen:
            failures.append(f"duplicate binding artifact: {key[0]} {key[1]}")
        seen.add(key)
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            failures.append(f"binding artifact {key[0]} {key[1]} has invalid sha256")
        elif digest == "0" * 64:
            failures.append(f"binding artifact {key[0]} {key[1]} must not use all-zero sha256")
        if not isinstance(artifact.get("bytes"), int) or artifact.get("bytes", 0) <= 0:
            failures.append(f"binding artifact {key[0]} {key[1]} must have positive byte size")
        rel_path = safe_relative_path(artifact.get("path"))
        if rel_path is None:
            failures.append(f"binding artifact {key[0]} {key[1]} path must be a relative non-placeholder path")
        if artifact_root is not None and rel_path is not None:
            path = artifact_root / rel_path
            if not path.is_file():
                failures.append(f"binding artifact file missing: {path}")
            elif file_hasher is not None and isinstance(digest, str) and file_hasher(path) != digest:
                failures.append(f"binding artifact sha mismatch: {path}")
    if expected_artifacts:
        missing = sorted(set(expected_artifacts) - seen)
        if missing:
            failures.append(
                "binding artifacts missing matrix-required files: "
                + ", ".join(f"{defconfig}:{artifact}" for defconfig, artifact in missing)
            )
    return failures


def subject_plan(
    *,
    version: str,
    profile: str,
    target: str,
    source_sha: str,
    source_run_id: str,
    matrix: dict[str, Any],
    raw_image_sha256: str | None = None,
    raw_image_bytes: int | None = None,
    compressed_artifact_sha256: str | None = None,
    compressed_artifact_bytes: int | None = None,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = contract or load_contract()
    profiles = payload.get("profiles", {})
    if profile not in profiles:
        raise ValueError(f"profile {profile!r} is missing from ci/evidence-contract.yml")
    profile_obj = profiles.get(profile)
    strict_artifacts = bool(
        isinstance(profile_obj, dict)
        and (
            profile_obj.get("production_candidate") is True
            or profile_obj.get("strict_artifact_binding") is True
        )
    )
    if strict_artifacts:
        for field, value in (
            ("raw_image_sha256", raw_image_sha256),
            ("raw_image_bytes", raw_image_bytes),
            ("compressed_artifact_sha256", compressed_artifact_sha256),
            ("compressed_artifact_bytes", compressed_artifact_bytes),
        ):
            if value is None:
                raise ValueError(f"--{field.replace('_', '-')} is required for {profile}")
    row = _matrix_row_for_target(matrix, target)
    policy = target_policy(target, payload)
    if not policy:
        raise ValueError(f"target {target!r} is missing from ci/evidence-contract.yml")
    subject_id = release_subject_id(
        version=version,
        target=target,
        source_sha=source_sha,
        source_run_id=source_run_id,
        contract=payload,
    )
    exports = {
        name: _format_subject_export(str(template), version=version, target=target, profile=profile)
        for name, template in payload["subjects"]["required_subject_exports"].items()
    }
    evidence_nodes = []
    evidence_edges = []
    export_schema_roles = {
        "release-inputs": "binding_manifest",
        "release-subject-graph": "release_subject_graph",
        "release-runtime": "production_runtime_suite",
        "release-signing": "signing_manifest",
        "release-lab-input": "hardware_subject",
        "release-security": "release_security_report",
        "release-governance": "governance_role_bindings",
        "release-retention": "retention_manifest",
        "release-ota": "ota_artifacts",
    }
    export_schema_versions = {
        "release-inputs": "suderra.release-input-binding.v2",
        "release-subject-graph": payload["schema_versions"]["release_subject_graph"],
        "release-runtime": payload["schema_versions"]["production_runtime_suite"],
        "release-signing": payload["schema_versions"]["signing_manifest"],
        "release-lab-input": payload["schema_versions"]["hardware_subject"],
        "release-security": payload["schema_versions"]["release_security_report"],
        "release-governance": payload["schema_versions"]["governance_role_bindings"],
        "release-retention": payload["schema_versions"]["retention_manifest"],
        "release-ota": payload["schema_versions"]["ota_artifacts"],
    }
    for name, path in sorted(exports.items()):
        required = name in {"release-inputs", "release-subject-graph"}
        if name == "release-runtime":
            required = bool(policy.get("runtime_required"))
        elif name == "release-signing":
            required = bool(policy.get("signing_required"))
        elif name == "release-lab-input":
            required = bool(policy.get("hardware_required"))
        elif name == "release-security":
            required = bool(policy.get("release_image_scan_required"))
        elif name in {"release-governance", "release-retention"}:
            required = bool(policy.get("production_gate"))
        elif name == "release-ota":
            required = bool(policy.get("ota_capable"))
        node_id = f"{subject_id}:{name}"
        evidence_nodes.append(
            {
                "node_id": node_id,
                "subject_id": subject_id,
                "target": target,
                "role": name,
                "path": path,
                "schema_role": export_schema_roles.get(name, name),
                "schema_version": export_schema_versions.get(name, "unknown"),
                "required": required,
                "producer": "ci/evidence-contract.yml",
            }
        )
        evidence_edges.append(
            {
                "from": subject_id,
                "to": node_id,
                "relationship": "requires" if required else "observes",
                "role": name,
            }
        )
    return {
        "schema_version": payload["schema_versions"]["release_subject_graph"],
        "subject_id": subject_id,
        "version": version,
        "profile": profile,
        "target": target,
        "defconfig": row.get("name"),
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "matrix": {
            "artifact": row.get("artifact"),
            "release_artifact": row.get("release_artifact"),
            "release_public": bool(row.get("release")),
            "production_required": bool(row.get("production_required")),
            "production_ready": bool(row.get("production_ready")),
        },
        "artifacts": {
            "raw_image": {
                "role": "raw-image",
                "name": row.get("artifact"),
                "sha256": raw_image_sha256,
                "bytes": raw_image_bytes,
            },
            "compressed_release_artifact": {
                "role": "compressed-release-artifact",
                "name": row.get("release_artifact"),
                "sha256": compressed_artifact_sha256,
                "bytes": compressed_artifact_bytes,
            },
        },
        "required_evidence": exports,
        "evidence_nodes": evidence_nodes,
        "evidence_edges": evidence_edges,
        "retention_closure": {
            "policy_id": payload["retention"]["policy_id"],
            "required_exports": list(payload["retention"]["required_exports"]),
        },
        "producer": {
            "name": "evidence_contract.py subject-plan",
            "source": "ci/evidence-contract.yml",
        },
        "target_policy": policy,
        "ota": ota_target_policy(target, payload),
        "runtime_suite_targets": runtime_suite_targets_for(target, payload),
        "signing_roles": sorted(signed_artifact_roles(payload)) if policy.get("signing_required") else [],
    }


def retention_plan(
    *,
    version: str,
    source_sha: str | None = None,
    source_run_id: str | None = None,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = contract or load_contract()
    retention = payload["retention"]
    required_exports = []
    for name in retention["required_exports"]:
        required_exports.append(
            {
                "name": name,
                "path": f"{name}/{version}",
            }
        )
    return {
        "schema_version": retention["manifest_schema_version"],
        "policy_id": retention["policy_id"],
        "version": version,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "store_class": retention["store_class"],
        "minimum_years": retention["minimum_years"],
        "kms_required": retention["kms_required"],
        "legal_hold_supported": retention["legal_hold_supported"],
        "access_log_required": retention["access_log_required"],
        "required_exports": required_exports,
        "required_replay": list(retention["required_replay"]),
        "manifest_path": f"release-retention/{version}/retention-manifest.json",
    }


def output_tree_plan(
    *,
    version: str,
    profile: str,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = contract or load_contract()
    profile_obj = profile_policy(profile, payload)
    tree_policy = output_tree_policy(payload)
    required_dirs = set(required_output_roots(profile, contract=payload))
    outputs = []
    for name, tree in tree_policy["trees"].items():
        if not isinstance(tree, dict):
            continue
        outputs.append(
            {
                "name": name,
                "path": str(tree["path_template"]).format(version=version),
                "schema_role": tree["schema_role"],
                "required": name in required_dirs,
                "promotable": tree["promotable"],
                "operator_ingress_allowed": tree["operator_ingress_allowed"],
                "release_tag_allowed": tree["release_tag_allowed"],
                "dry_run_input_allowed": tree["dry_run_input_allowed"],
                "gitignore_required": tree["gitignore_required"],
            }
        )
    return {
        "schema_version": "suderra.profile-output-tree-plan.v1",
        "version": version,
        "profile": profile,
        "release_authorizing": bool(profile_obj.get("release_authorizing")),
        "publication_allowed": bool(profile_obj.get("publication_allowed")),
        "production_candidate": bool(profile_obj.get("production_candidate")),
        "strict_artifact_binding": bool(profile_obj.get("strict_artifact_binding")),
        "subject_graph_required": bool(profile_obj.get("subject_graph_required")),
        "gap_report_required": bool(profile_obj.get("gap_report_required")),
        "operator_ingress_required": bool(profile_obj.get("operator_ingress_required")),
        "outputs": sorted(outputs, key=lambda item: (not item["required"], item["name"])),
    }


def runtime_plan(
    *,
    version: str,
    target: str,
    source_sha: str,
    source_run_id: str,
    source_run_attempt: str,
    defconfig: str,
    image: str,
    raw_image_sha256: str,
    compressed_artifact_sha256: str,
    release_artifact: str,
    ovmf_code: str,
    ovmf_vars: str,
    swtpm_state: str,
    scenario_command: str,
    ovmf_enrollment_mode: str,
    ovmf_enrolled_vars_sha256: str,
    secure_boot_db_sha256: str,
    mutation_inputs: dict[str, Any] | None = None,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = contract or load_contract()
    command_base = shlex.split(scenario_command)
    if not command_base:
        raise ValueError("--scenario-command must not be empty")
    # Per-scenario mutation producer inputs (image, ESP offset, keys, ...) that
    # the runner feeds to tests/qemu/runtime_mutations.py. Only governed scenario
    # names are accepted so a plan cannot smuggle inputs for unknown scenarios.
    governed = set(runtime_required_scenarios(payload))
    resolved_mutation_inputs: dict[str, Any] = {}
    if mutation_inputs is not None:
        if not isinstance(mutation_inputs, dict):
            raise ValueError("mutation_inputs must be a JSON object keyed by scenario")
        for scenario_name, values in mutation_inputs.items():
            if scenario_name not in governed:
                raise ValueError(f"mutation_inputs references ungoverned scenario: {scenario_name}")
            if not isinstance(values, dict):
                raise ValueError(f"mutation_inputs[{scenario_name}] must be an object")
            resolved_mutation_inputs[scenario_name] = values
    scenarios = []
    contracts = runtime_scenario_contracts(payload)
    for name in runtime_required_scenarios(payload):
        scenario_contract = contracts[name]
        scenarios.append(
            {
                "name": name,
                "expected_outcome": scenario_contract["expected_outcome"],
                "expected_exit_code": 0,
                "guest_facts_required": scenario_contract["guest_facts_required"],
                "mutation_target": scenario_contract["mutation_target"],
                "mutation_type": scenario_contract["mutation_type"],
                "observed_layer": scenario_contract["observed_layer"],
                "observation_source": list(scenario_contract["observation_source"]),
                "required_log_roles": list(scenario_contract["required_log_roles"]),
                "command": [*command_base, name],
            }
        )
    return {
        "version": version,
        "target": target,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "source_run_attempt": source_run_attempt,
        "defconfig": defconfig,
        "subject_id": release_subject_id(
            version=version,
            target=target,
            source_sha=source_sha,
            source_run_id=source_run_id,
            contract=payload,
        ),
        "image": image,
        "artifact_digest": compressed_artifact_sha256,
        "raw_image_sha256": raw_image_sha256,
        "compressed_artifact_sha256": compressed_artifact_sha256,
        "release_artifact": release_artifact,
        "ovmf_code": ovmf_code,
        "ovmf_vars": ovmf_vars,
        "ovmf_enrollment_mode": ovmf_enrollment_mode,
        "ovmf_enrolled_vars_sha256": ovmf_enrolled_vars_sha256,
        "secure_boot_db_sha256": secure_boot_db_sha256,
        "swtpm_state": swtpm_state,
        "mutation_inputs": resolved_mutation_inputs,
        "scenarios": scenarios,
    }


def docs_fragment(fragment: str, *, contract: dict[str, Any] | None = None) -> str:
    payload = contract or load_contract()
    if fragment == "schema-versions":
        lines = ["| Role | Schema Version |", "| --- | --- |"]
        for key, value in sorted(payload["schema_versions"].items()):
            lines.append(f"| `{key}` | `{value}` |")
        return "\n".join(lines)
    if fragment == "retention-policy":
        retention = retention_policy(payload)
        lines = [
            f"- Policy ID: `{retention['policy_id']}`",
            f"- Minimum years: `{retention['minimum_years']}`",
            f"- Store class: `{retention['store_class']}`",
            f"- Required replay: `{', '.join(retention['required_replay'])}`",
        ]
        return "\n".join(lines)
    if fragment == "runtime-scenarios":
        lines = ["| Scenario | Required Checks |", "| --- | --- |"]
        scenario_checks = runtime_scenario_to_checks(payload)
        for name in runtime_required_scenarios(payload):
            checks = ", ".join(f"`{check}`" for check in scenario_checks.get(name, ()))
            lines.append(f"| `{name}` | {checks} |")
        return "\n".join(lines)
    if fragment == "signing-roles":
        return "\n".join(f"- `{name}`" for name in sorted(signed_artifact_roles(payload)))
    if fragment == "output-trees":
        lines = [
            "| Root | Path Template | Schema Role | Required By Default | Promotable | Operator Ingress | Release Tag | Dry-Run Input | Gitignore |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for root, tree in sorted(output_tree_policy(payload)["trees"].items()):
            lines.append(
                f"| `{root}` | `{tree['path_template']}` | `{tree['schema_role']}` | "
                f"`{tree['required_by_default']}` | `{tree['promotable']}` | "
                f"`{tree['operator_ingress_allowed']}` | `{tree['release_tag_allowed']}` | "
                f"`{tree['dry_run_input_allowed']}` | "
                f"`{tree['gitignore_required']}` |"
            )
        return "\n".join(lines)
    if fragment == "profile-gates":
        lines = [
            "| Profile | Release Authorizing | Publication Allowed | Operator Ingress Required | Required Output Trees |",
            "| --- | --- | --- | --- | --- |",
        ]
        for name, profile in sorted(payload["profiles"].items()):
            roots = ", ".join(f"`{root}`" for root in profile["required_output_trees"]) or "`none`"
            lines.append(
                f"| `{name}` | `{profile['release_authorizing']}` | `{profile['publication_allowed']}` | "
                f"`{profile['operator_ingress_required']}` | {roots} |"
            )
        return "\n".join(lines)
    if fragment == "subject-export-paths":
        lines = ["| Evidence Root | Path Template |", "| --- | --- |"]
        for root, template in sorted(subject_policy(payload)["required_subject_exports"].items()):
            lines.append(f"| `{root}` | `{template}` |")
        return "\n".join(lines)
    if fragment == "governance-policy":
        governance_path = ROOT / "ci" / "github-governance-policy.yml"
        governance = json.loads(governance_path.read_text(encoding="utf-8"))
        environments = governance.get("environments", {})
        rulesets = governance.get("rulesets", {})
        checks = governance.get("required_checks", {})
        lines = ["| Category | Name |", "| --- | --- |"]
        for name in sorted(environments):
            lines.append(f"| `environment` | `{name}` |")
        for name in sorted(rulesets):
            lines.append(f"| `ruleset` | `{name}` |")
        for name in sorted(checks):
            lines.append(f"| `required_check` | `{name}` |")
        return "\n".join(lines)
    if fragment == "verification-schemas":
        selected = (
            "release_evidence",
            "release_subject_graph",
            "production_runtime_suite",
            "runtime_observation",
            "signing_manifest",
            "hardware_subject",
            "release_security_report",
            "retention_manifest",
        )
        lines = ["| Role | Schema Version |", "| --- | --- |"]
        for key in selected:
            lines.append(f"| `{key}` | `{payload['schema_versions'][key]}` |")
        return "\n".join(lines)
    raise ValueError(f"unknown docs fragment {fragment!r}")


def validate_matrix_join(matrix: dict[str, Any], contract: dict[str, Any] | None = None) -> list[str]:
    payload = contract or load_contract()
    rows = {
        str(row.get("target")): row
        for row in matrix.get("defconfigs", [])
        if isinstance(row, dict) and isinstance(row.get("target"), str)
    }
    errors: list[str] = []
    contract_targets = payload["targets"]
    production_targets = {
        str(row.get("target"))
        for row in rows.values()
        if row.get("production_required") is True
    }
    missing_contract_targets = sorted(production_targets - set(contract_targets))
    if missing_contract_targets:
        errors.append(
            "ci/evidence-contract.yml must define every production_required target: "
            + ", ".join(missing_contract_targets)
        )
    release_targets = {
        str(row.get("target"))
        for row in rows.values()
        if row.get("release") is True
    }
    missing_release_targets = sorted(release_targets - set(contract_targets))
    if missing_release_targets:
        errors.append(
            "ci/evidence-contract.yml must define every release=true target: "
            + ", ".join(missing_release_targets)
        )
    for target, policy in contract_targets.items():
        row = rows.get(target)
        if row is None:
            errors.append(f"ci/evidence-contract.yml target {target} is missing from ci/build-matrix.yml")
            continue
        if bool(row.get("release")) != bool(policy.get("release_public")):
            errors.append(f"{target}: matrix release must match evidence-contract release_public")
        if row.get("production_required") is True and row.get("production_ready") is not False:
            errors.append(f"{target}: production_required targets must keep production_ready=false until retained production evidence closes")
        if policy.get("production_gate") is True and row.get("production_required") is not True:
            errors.append(f"{target}: production_gate requires matrix production_required=true")
        if policy.get("runtime_required") is True:
            suites = runtime_suite_targets_for(target, payload)
            if not suites:
                errors.append(f"{target}: runtime_required requires a runtime suite target mapping")
            for suite in suites:
                if suite not in rows:
                    errors.append(f"{target}: runtime suite target {suite} is missing from ci/build-matrix.yml")
                if suite not in contract_targets:
                    errors.append(f"{target}: runtime suite target {suite} is missing from ci/evidence-contract.yml")
        if policy.get("hardware_required") is True:
            if target not in payload["hardware"]["required_boards_by_target"]:
                errors.append(f"{target}: hardware_required requires hardware.required_boards_by_target entry")
            subject_binding = payload.get("hardware", {}).get("subject_binding")
            if not isinstance(subject_binding, dict) or not subject_binding.get("required_fields"):
                errors.append(f"{target}: hardware_required requires hardware.subject_binding policy")
        if policy.get("signing_required") is True and str(row.get("signing")) in UNSIGNED_SIGNING_MODES:
            errors.append(f"{target}: signing_required cannot use matrix signing={row.get('signing')!r}")
        if policy.get("signing_required") is True:
            bindings = signing_role_bindings(payload)
            required_roles = []
            if policy.get("ota_capable") is True:
                required_roles.extend(
                    role
                    for role, binding in bindings.items()
                    if binding.get("required_for_ota_capable") is True
                )
            if policy.get("release_public") is True:
                required_roles.extend(
                    role
                    for role, binding in bindings.items()
                    if binding.get("required_for_release_public") is True
                )
            if not required_roles:
                errors.append(f"{target}: signing_required requires signing manifest role binding")
            for role in sorted(set(required_roles)):
                binding = bindings.get(role, {})
                if not binding.get("final_digest_field") or not binding.get("input_digest_field"):
                    errors.append(f"{target}: signing role {role} requires input/final digest fields")
        ota_policy = ota_target_policy(target, payload)
        if bool(ota_policy.get("ota_capable")) != bool(policy.get("ota_capable")):
            errors.append(f"{target}: ota target policy must match evidence target ota_capable")
    for target in payload["ota"]["targets"]:
        if target not in contract_targets:
            errors.append(f"ota target {target} is missing from evidence-contract targets")
    return errors


def _required_runtime_arg(args: argparse.Namespace, field: str) -> str:
    value = getattr(args, field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"--{field.replace('_', '-')} is required")
    return value


def _load_matrix(path: Path) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import matrix loader from {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = module.load_matrix(path)
    if not isinstance(matrix, dict):
        raise ValueError(f"build matrix loader returned non-object for {path}")
    return matrix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument(
        "command",
        choices=(
            "dump",
            "validate",
            "validate-join",
            "runtime-plan",
            "subject-plan",
            "retention-plan",
            "output-tree-plan",
            "required-output-roots",
            "preflight-input-roots",
            "release-authorizing-profiles",
            "operator-ingress-required-profiles",
            "docs-fragment",
        ),
    )
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--version")
    parser.add_argument("--target")
    parser.add_argument("--source-sha")
    parser.add_argument("--source-run-id")
    parser.add_argument("--source-run-attempt")
    parser.add_argument("--profile", default="release-candidate")
    parser.add_argument("--defconfig")
    parser.add_argument("--image")
    parser.add_argument("--release-artifact")
    parser.add_argument("--ovmf-code")
    parser.add_argument("--ovmf-vars")
    parser.add_argument("--ovmf-enrollment-mode")
    parser.add_argument("--ovmf-enrolled-vars-sha256")
    parser.add_argument("--secure-boot-db-sha256")
    parser.add_argument("--mutation-inputs-file")
    parser.add_argument("--swtpm-state")
    parser.add_argument("--raw-image-sha256")
    parser.add_argument("--raw-image-bytes", type=int)
    parser.add_argument("--artifact-digest")
    parser.add_argument("--compressed-artifact-sha256")
    parser.add_argument("--compressed-artifact-bytes", type=int)
    parser.add_argument("--scenario-command", default="tests/qemu/production-runtime-scenario.sh")
    parser.add_argument("--fragment")
    args = parser.parse_args()
    try:
        payload = load_contract(args.contract)
        if args.command == "dump":
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif args.command == "validate":
            print(f"validated evidence contract: {args.contract}")
        elif args.command == "validate-join":
            errors = validate_matrix_join(_load_matrix(args.matrix), payload)
            if errors:
                for item in errors:
                    print(f"ERROR: {item}")
                return 1
            print(f"validated evidence contract/build matrix join: {args.contract} <-> {args.matrix}")
        elif args.command == "runtime-plan":
            compressed_artifact_sha256 = args.compressed_artifact_sha256 or args.artifact_digest
            if compressed_artifact_sha256:
                args.compressed_artifact_sha256 = compressed_artifact_sha256
            print(
                json.dumps(
                    runtime_plan(
                        version=_required_runtime_arg(args, "version"),
                        target=_required_runtime_arg(args, "target"),
                        source_sha=_required_runtime_arg(args, "source_sha"),
                        source_run_id=_required_runtime_arg(args, "source_run_id"),
                        source_run_attempt=_required_runtime_arg(args, "source_run_attempt"),
                        defconfig=_required_runtime_arg(args, "defconfig"),
                        image=_required_runtime_arg(args, "image"),
                        raw_image_sha256=_required_runtime_arg(args, "raw_image_sha256"),
                        compressed_artifact_sha256=_required_runtime_arg(args, "compressed_artifact_sha256"),
                        release_artifact=_required_runtime_arg(args, "release_artifact"),
                        ovmf_code=_required_runtime_arg(args, "ovmf_code"),
                        ovmf_vars=_required_runtime_arg(args, "ovmf_vars"),
                        swtpm_state=_required_runtime_arg(args, "swtpm_state"),
                        scenario_command=args.scenario_command,
                        ovmf_enrollment_mode=_required_runtime_arg(args, "ovmf_enrollment_mode"),
                        ovmf_enrolled_vars_sha256=_required_runtime_arg(args, "ovmf_enrolled_vars_sha256"),
                        secure_boot_db_sha256=_required_runtime_arg(args, "secure_boot_db_sha256"),
                        mutation_inputs=(
                            json.loads(Path(args.mutation_inputs_file).read_text(encoding="utf-8"))
                            if args.mutation_inputs_file
                            else None
                        ),
                        contract=payload,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "subject-plan":
            print(
                json.dumps(
                    subject_plan(
                        version=_required_runtime_arg(args, "version"),
                        profile=args.profile,
                        target=_required_runtime_arg(args, "target"),
                        source_sha=_required_runtime_arg(args, "source_sha"),
                        source_run_id=_required_runtime_arg(args, "source_run_id"),
                        matrix=_load_matrix(args.matrix),
                        raw_image_sha256=args.raw_image_sha256,
                        raw_image_bytes=args.raw_image_bytes,
                        compressed_artifact_sha256=args.compressed_artifact_sha256,
                        compressed_artifact_bytes=args.compressed_artifact_bytes,
                        contract=payload,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "retention-plan":
            print(
                json.dumps(
                    retention_plan(
                        version=_required_runtime_arg(args, "version"),
                        source_sha=args.source_sha,
                        source_run_id=args.source_run_id,
                        contract=payload,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "output-tree-plan":
            print(
                json.dumps(
                    output_tree_plan(
                        version=_required_runtime_arg(args, "version"),
                        profile=args.profile,
                        contract=payload,
                    ),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "required-output-roots":
            print(json.dumps(required_output_roots(args.profile, contract=payload), indent=2, sort_keys=True))
        elif args.command == "preflight-input-roots":
            print(json.dumps(preflight_input_roots(args.profile, contract=payload), indent=2, sort_keys=True))
        elif args.command == "release-authorizing-profiles":
            print(json.dumps(release_authorizing_profiles(payload), indent=2, sort_keys=True))
        elif args.command == "operator-ingress-required-profiles":
            print(json.dumps(operator_ingress_required_profiles(payload), indent=2, sort_keys=True))
        else:
            print(docs_fragment(_required_runtime_arg(args, "fragment"), contract=payload))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
