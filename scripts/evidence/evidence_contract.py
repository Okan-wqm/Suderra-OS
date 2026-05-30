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
import json
from pathlib import Path
import shlex
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "ci" / "evidence-contract.yml"
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
        "ota_target_contract",
        "production_runtime_suite",
        "release_evidence",
        "release_security_report",
        "runtime_observation",
        "signing_manifest",
        "station_acquisition",
    ):
        if not isinstance(schemas.get(field), str) or not schemas[field]:
            raise ValueError(f"schema_versions.{field} must be a non-empty string")
    runtime = _object(payload.get("runtime"), "runtime")
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
        for field in ("backend", "compatible", "health_policy", "lifecycle", "rollback_state"):
            if not isinstance(ota_policy.get(field), str) or not ota_policy[field]:
                raise ValueError(f"ota.targets.{target}.{field} must be a non-empty string")
    for target in ota_targets:
        if target not in targets:
            raise ValueError(f"ota.targets.{target} has no matching target policy")
    retention = _object(payload.get("retention"), "retention")
    _string_list(retention.get("required_exports"), "retention.required_exports")


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


def runtime_plan(
    *,
    version: str,
    target: str,
    source_sha: str,
    image: str,
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
        "image": image,
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
        if policy.get("hardware_required") is True and target not in payload["hardware"]["required_boards_by_target"]:
            errors.append(f"{target}: hardware_required requires hardware.required_boards_by_target entry")
        if policy.get("signing_required") is True and str(row.get("signing")) in UNSIGNED_SIGNING_MODES:
            errors.append(f"{target}: signing_required cannot use matrix signing={row.get('signing')!r}")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("command", choices=("dump", "validate", "runtime-plan"))
    parser.add_argument("--version")
    parser.add_argument("--target")
    parser.add_argument("--source-sha")
    parser.add_argument("--image")
    parser.add_argument("--ovmf-code")
    parser.add_argument("--ovmf-vars")
    parser.add_argument("--swtpm-state")
    parser.add_argument("--scenario-command", default="tests/qemu/production-runtime-scenario.sh")
    args = parser.parse_args()
    payload = load_contract(args.contract)
    if args.command == "dump":
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.command == "validate":
        print(f"validated evidence contract: {args.contract}")
    else:
        print(
            json.dumps(
                runtime_plan(
                    version=_required_runtime_arg(args, "version"),
                    target=_required_runtime_arg(args, "target"),
                    source_sha=_required_runtime_arg(args, "source_sha"),
                    image=_required_runtime_arg(args, "image"),
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
