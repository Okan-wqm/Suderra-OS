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
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "ci" / "evidence-contract.yml"
CONTRACT_SCHEMA_VERSION = "suderra.evidence-contract.v1"


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
        "production_runtime_suite",
        "release_evidence",
        "release_security_report",
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
    _string_list(signing.get("signed_artifact_roles"), "signing.signed_artifact_roles")
    targets = _object(payload.get("targets"), "targets")
    for target, policy in targets.items():
        policy_obj = _object(policy, f"targets.{target}")
        for field in (
            "hardware_required",
            "production_gate",
            "release_image_scan_required",
            "release_public",
            "runtime_required",
            "signing_required",
        ):
            if not isinstance(policy_obj.get(field), bool):
                raise ValueError(f"targets.{target}.{field} must be a boolean")


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("command", choices=("dump", "validate"))
    args = parser.parse_args()
    payload = load_contract(args.contract)
    if args.command == "dump":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"validated evidence contract: {args.contract}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
