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


def _matrix_row_for_target(matrix: dict[str, Any], target: str) -> dict[str, Any]:
    for row in matrix.get("defconfigs", []):
        if isinstance(row, dict) and row.get("target") == target:
            return row
    raise ValueError(f"target {target!r} is missing from ci/build-matrix.yml")


def _format_subject_export(template: str, *, version: str, target: str, profile: str) -> str:
    return template.format(version=version, target=target, profile=profile, scan="{scan}")


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
    strict_artifacts = bool(isinstance(profiles.get(profile), dict) and profiles[profile].get("production_candidate") is True)
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
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = contract or load_contract()
    command_base = shlex.split(scenario_command)
    if not command_base:
        raise ValueError("--scenario-command must not be empty")
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
        "swtpm_state": swtpm_state,
        "scenarios": scenarios,
    }


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
        choices=("dump", "validate", "validate-join", "runtime-plan", "subject-plan", "retention-plan"),
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
    parser.add_argument("--swtpm-state")
    parser.add_argument("--raw-image-sha256")
    parser.add_argument("--raw-image-bytes", type=int)
    parser.add_argument("--artifact-digest")
    parser.add_argument("--compressed-artifact-sha256")
    parser.add_argument("--compressed-artifact-bytes", type=int)
    parser.add_argument("--scenario-command", default="tests/qemu/production-runtime-scenario.sh")
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
        else:
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
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
