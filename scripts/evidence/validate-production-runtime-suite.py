#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate production-runtime QEMU scenario suite evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA_VERSION = "suderra.qemu-production-runtime-suite.v2"
LEGACY_SCHEMA_VERSIONS = {"suderra.qemu-production-runtime-suite.v1"}
V2_REQUIRED_PROFILES = {"production-candidate", "production-runtime"}
REQUIRED_SCENARIOS = (
    "signed-boot",
    "unsigned-boot-rejection",
    "cmdline-tamper-rejection",
    "dm-verity-rootfs-tamper-rejection",
    "rauc-good-update",
    "rauc-bad-signature-rejection",
    "rauc-health-rollback",
    "anti-rollback-downgrade-rejection",
    "data-luks-swtpm",
)
SCENARIO_STATUSES = {"passed", "failed", "infra-error", "timeout"}
EXPECTED_OUTCOMES = {
    "booted",
    "firmware-rejected",
    "kernel-rejected",
    "userspace-rejected",
    "rollback-completed",
}
REQUIRED_V2_LOG_ROLES = {"serial", "qmp-events"}
REQUIRED_V2_GUEST_FACTS = (
    "secure_boot",
    "dm_verity",
    "rauc",
    "data_encryption",
    "anti_rollback",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDERS = {"", "TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_placeholder(value: Any) -> bool:
    return not isinstance(value, str) or value.strip() in PLACEHOLDERS


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def check_string(errors: list[str], path: str, value: Any) -> None:
    if is_placeholder(value):
        error(errors, path, "must be a non-placeholder string")


def check_sha256(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        error(errors, path, "must be a lowercase sha256")
    elif value == "0" * 64:
        error(errors, path, "must not be the all-zero sha256")


def check_string_list(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, list) or not value:
        error(errors, path, "must be a non-empty string list")
        return
    for idx, item in enumerate(value):
        check_string(errors, f"{path}[{idx}]", item)


def check_object(errors: list[str], path: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(errors, path, "must be an object")
        return {}
    return value


def check_relative_file(
    errors: list[str],
    root: Path,
    path: str,
    value: Any,
    check_files: bool,
    expected_sha256: str | None = None,
) -> None:
    check_string(errors, path, value)
    if not isinstance(value, str):
        return
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return
    actual = root / rel
    if not check_files:
        return
    if not actual.is_file() or actual.stat().st_size <= 0:
        error(errors, path, f"referenced file is missing or empty: {value}")
        return
    if expected_sha256 is not None and actual.is_file() and sha256_file(actual) != expected_sha256:
        error(errors, path, "referenced file sha256 mismatch")


def validate_top_level_v2(errors: list[str], payload: dict[str, Any]) -> None:
    check_string(errors, "$.qemu_version", payload.get("qemu_version"))
    check_string_list(errors, "$.qemu_argv", payload.get("qemu_argv"))
    if isinstance(payload.get("qemu_argv"), list):
        argv = [str(item) for item in payload["qemu_argv"]]
        if not any(Path(item).name == "qemu-system-x86_64" for item in argv):
            error(errors, "$.qemu_argv", "must include qemu-system-x86_64")
        if "-qmp" not in argv:
            error(errors, "$.qemu_argv", "must include QMP")

    enrollment = check_object(errors, "$.ovmf_enrollment", payload.get("ovmf_enrollment"))
    if enrollment:
        for field in ("enrolled_vars_sha256", "secure_boot_db_sha256"):
            check_sha256(errors, f"$.ovmf_enrollment.{field}", enrollment.get(field))
        check_string(errors, "$.ovmf_enrollment.mode", enrollment.get("mode"))

    for field in ("swtpm_state_before_sha256", "swtpm_state_after_sha256"):
        check_sha256(errors, f"$.{field}", payload.get(field))


def validate_guest_facts_v2(errors: list[str], scenario_path: str, name: Any, facts: Any) -> None:
    facts_obj = check_object(errors, f"{scenario_path}.guest_facts", facts)
    if not facts_obj:
        return
    missing = sorted(set(REQUIRED_V2_GUEST_FACTS) - set(facts_obj))
    if missing:
        error(errors, f"{scenario_path}.guest_facts", f"missing required facts: {', '.join(missing)}")

    secure_boot = facts_obj.get("secure_boot")
    if isinstance(secure_boot, dict):
        if secure_boot.get("enabled") is not True:
            error(errors, f"{scenario_path}.guest_facts.secure_boot.enabled", "must be true")
        check_string(errors, f"{scenario_path}.guest_facts.secure_boot.source", secure_boot.get("source"))
    elif "secure_boot" in facts_obj:
        error(errors, f"{scenario_path}.guest_facts.secure_boot", "must be an object")

    dm_verity = facts_obj.get("dm_verity")
    if isinstance(dm_verity, dict):
        if dm_verity.get("active") is not True:
            error(errors, f"{scenario_path}.guest_facts.dm_verity.active", "must be true")
        table = dm_verity.get("table")
        if isinstance(table, list):
            if not table:
                error(errors, f"{scenario_path}.guest_facts.dm_verity.table", "must be non-empty")
        else:
            check_string(errors, f"{scenario_path}.guest_facts.dm_verity.table", table)
    elif "dm_verity" in facts_obj:
        error(errors, f"{scenario_path}.guest_facts.dm_verity", "must be an object")

    rauc = facts_obj.get("rauc")
    if isinstance(rauc, dict):
        if rauc.get("available") is not True:
            error(errors, f"{scenario_path}.guest_facts.rauc.available", "must be true")
        status = rauc.get("status")
        if isinstance(status, list):
            if not status:
                error(errors, f"{scenario_path}.guest_facts.rauc.status", "must be non-empty")
        else:
            check_string(errors, f"{scenario_path}.guest_facts.rauc.status", status)
    elif "rauc" in facts_obj:
        error(errors, f"{scenario_path}.guest_facts.rauc", "must be an object")

    data_encryption = facts_obj.get("data_encryption")
    if isinstance(data_encryption, dict):
        mapper = data_encryption.get("luks_mapper_state")
        if not isinstance(mapper, dict):
            error(errors, f"{scenario_path}.guest_facts.data_encryption.luks_mapper_state", "must be an object")
        else:
            check_string(errors, f"{scenario_path}.guest_facts.data_encryption.luks_mapper_state.mapper", mapper.get("mapper"))
            if name == "data-luks-swtpm" and mapper.get("open") is not True:
                error(errors, f"{scenario_path}.guest_facts.data_encryption.luks_mapper_state.open", "must be true")
        if name == "data-luks-swtpm" and data_encryption.get("encrypted") is not True:
            error(errors, f"{scenario_path}.guest_facts.data_encryption.encrypted", "must be true")
    elif "data_encryption" in facts_obj:
        error(errors, f"{scenario_path}.guest_facts.data_encryption", "must be an object")

    anti_rollback = facts_obj.get("anti_rollback")
    if isinstance(anti_rollback, dict):
        check_string(
            errors,
            f"{scenario_path}.guest_facts.anti_rollback.rollback_floor",
            anti_rollback.get("rollback_floor"),
        )
    elif "anti_rollback" in facts_obj:
        error(errors, f"{scenario_path}.guest_facts.anti_rollback", "must be an object")


def validate_scenario_v2(
    errors: list[str],
    root: Path,
    scenario_path: str,
    scenario: dict[str, Any],
    name: Any,
    logs_by_role: dict[str, dict[str, Any]],
    check_files: bool,
) -> None:
    check_string_list(errors, f"{scenario_path}.qemu_argv", scenario.get("qemu_argv"))
    if isinstance(scenario.get("qemu_argv"), list):
        argv = [str(item) for item in scenario["qemu_argv"]]
        if not any(Path(item).name == "qemu-system-x86_64" for item in argv):
            error(errors, f"{scenario_path}.qemu_argv", "must include qemu-system-x86_64")
        if "-qmp" not in argv:
            error(errors, f"{scenario_path}.qemu_argv", "must include QMP")

    termination = check_object(errors, f"{scenario_path}.termination", scenario.get("termination"))
    if termination:
        check_string(errors, f"{scenario_path}.termination.class", termination.get("class"))
        check_string(errors, f"{scenario_path}.termination.reason", termination.get("reason"))
        if "qmp_quit_sent" in termination and termination.get("qmp_quit_sent") is not True:
            error(errors, f"{scenario_path}.termination.qmp_quit_sent", "must be true when present")

    swtpm = check_object(errors, f"{scenario_path}.swtpm_state", scenario.get("swtpm_state"))
    if swtpm:
        for field in ("before_sha256", "after_sha256"):
            check_sha256(errors, f"{scenario_path}.swtpm_state.{field}", swtpm.get(field))
        check_string(errors, f"{scenario_path}.swtpm_state.path", swtpm.get("path"))
        if name == "data-luks-swtpm" and swtpm.get("before_sha256") == swtpm.get("after_sha256"):
            error(errors, f"{scenario_path}.swtpm_state.after_sha256", "must differ for data LUKS/swtpm persistence")

    raw = check_object(errors, f"{scenario_path}.raw_evidence", scenario.get("raw_evidence"))
    if raw:
        for role, field in (("serial", "serial_sha256"), ("qmp-events", "qmp_events_sha256")):
            check_sha256(errors, f"{scenario_path}.raw_evidence.{field}", raw.get(field))
            if role in logs_by_role and isinstance(raw.get(field), str) and raw.get(field) != logs_by_role[role].get("sha256"):
                error(errors, f"{scenario_path}.raw_evidence.{field}", f"must match {role} log sha256")

    missing_logs = sorted(REQUIRED_V2_LOG_ROLES - set(logs_by_role))
    if missing_logs:
        error(errors, f"{scenario_path}.logs", f"missing required raw log roles: {', '.join(missing_logs)}")

    validate_guest_facts_v2(errors, scenario_path, name, scenario.get("guest_facts"))

    mutation = scenario.get("mutation")
    if isinstance(mutation, dict) and name != "signed-boot":
        artifact = mutation.get("artifact")
        if isinstance(artifact, dict):
            for field in ("path", "role"):
                check_string(errors, f"{scenario_path}.mutation.artifact.{field}", artifact.get(field))
            for field in ("before_sha256", "after_sha256"):
                check_sha256(errors, f"{scenario_path}.mutation.artifact.{field}", artifact.get(field))
            if artifact.get("before_sha256") == artifact.get("after_sha256"):
                error(errors, f"{scenario_path}.mutation.artifact.after_sha256", "must differ from before_sha256")
            check_relative_file(
                errors,
                root,
                f"{scenario_path}.mutation.artifact.path",
                artifact.get("path"),
                check_files,
            )
        else:
            error(errors, f"{scenario_path}.mutation.artifact", "must bind mutation artifact before/after hashes")


def validate(
    path: Path,
    *,
    check_files: bool,
    require_pass: bool,
    expected_version: str | None = None,
    expected_target: str | None = None,
    expected_source_sha: str | None = None,
    expected_artifact_sha256: str | None = None,
    profile: str = "release-candidate",
) -> list[str]:
    root = path.parent
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{path}: cannot read production-runtime suite: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]

    schema_version = payload.get("schema_version")
    if schema_version not in LEGACY_SCHEMA_VERSIONS | {SCHEMA_VERSION}:
        error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
    is_v2 = schema_version == SCHEMA_VERSION
    if profile in V2_REQUIRED_PROFILES and not is_v2:
        error(errors, "$.schema_version", f"{profile} requires {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at", "image", "ovmf_code", "ovmf_vars", "swtpm_state"):
        check_string(errors, f"$.{field}", payload.get(field))
    if expected_version is not None and payload.get("version") != expected_version:
        error(errors, "$.version", f"must match expected version {expected_version}")
    if expected_target is not None and payload.get("target") != expected_target:
        error(errors, "$.target", f"must match expected target {expected_target}")
    source_sha = payload.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        error(errors, "$.source_sha", "must be a lowercase git commit sha")
    elif expected_source_sha is not None and source_sha != expected_source_sha:
        error(errors, "$.source_sha", f"must match expected source sha {expected_source_sha}")
    for field in ("image_sha256", "ovmf_code_sha256", "ovmf_vars_sha256", "swtpm_state_sha256"):
        check_sha256(errors, f"$.{field}", payload.get(field))
    if expected_artifact_sha256 is not None and payload.get("image_sha256") != expected_artifact_sha256:
        error(errors, "$.image_sha256", f"must match expected artifact sha256 {expected_artifact_sha256}")
    if is_v2:
        validate_top_level_v2(errors, payload)

    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        error(errors, "$.scenarios", "must be a non-empty list")
        scenarios = []
    by_name: dict[str, dict[str, Any]] = {}
    for idx, scenario in enumerate(scenarios):
        scenario_path = f"$.scenarios[{idx}]"
        if not isinstance(scenario, dict):
            error(errors, scenario_path, "must be an object")
            continue
        name = scenario.get("name")
        check_string(errors, f"{scenario_path}.name", name)
        if isinstance(name, str):
            if name in by_name:
                error(errors, f"{scenario_path}.name", "must be unique")
            by_name[name] = scenario
        if scenario.get("status") not in SCENARIO_STATUSES:
            error(errors, f"{scenario_path}.status", f"must be one of: {', '.join(sorted(SCENARIO_STATUSES))}")
        if require_pass and scenario.get("status") != "passed":
            error(errors, f"{scenario_path}.status", "must be passed")
        if scenario.get("expected_outcome") not in EXPECTED_OUTCOMES:
            error(
                errors,
                f"{scenario_path}.expected_outcome",
                f"must be one of: {', '.join(sorted(EXPECTED_OUTCOMES))}",
            )
        if scenario.get("observed_outcome") != scenario.get("expected_outcome"):
            error(errors, f"{scenario_path}.observed_outcome", "must match expected_outcome")
        for field in ("command", "started_at", "completed_at", "termination_class", "failure_class"):
            check_string(errors, f"{scenario_path}.{field}", scenario.get(field))
        mutation = scenario.get("mutation")
        if not isinstance(mutation, dict):
            error(errors, f"{scenario_path}.mutation", "must be an object")
        else:
            if name == "signed-boot":
                if mutation.get("type") != "none":
                    error(errors, f"{scenario_path}.mutation.type", "signed-boot must not mutate the base image")
            else:
                for field in ("type", "target", "before_sha256", "after_sha256"):
                    if field.endswith("sha256"):
                        check_sha256(errors, f"{scenario_path}.mutation.{field}", mutation.get(field))
                    else:
                        check_string(errors, f"{scenario_path}.mutation.{field}", mutation.get(field))
                if mutation.get("before_sha256") == mutation.get("after_sha256"):
                    error(errors, f"{scenario_path}.mutation.after_sha256", "must differ from before_sha256")
        logs = scenario.get("logs")
        if not isinstance(logs, list) or not logs:
            error(errors, f"{scenario_path}.logs", "must be a non-empty list")
        else:
            roles = set()
            logs_by_role: dict[str, dict[str, Any]] = {}
            for log_idx, log in enumerate(logs):
                log_path = f"{scenario_path}.logs[{log_idx}]"
                if not isinstance(log, dict):
                    error(errors, log_path, "must be an object")
                    continue
                role = log.get("role")
                check_string(errors, f"{log_path}.role", role)
                if isinstance(role, str):
                    roles.add(role)
                    logs_by_role[role] = log
                check_sha256(errors, f"{log_path}.sha256", log.get("sha256"))
                check_relative_file(
                    errors,
                    root,
                    f"{log_path}.path",
                    log.get("path"),
                    check_files,
                    log.get("sha256") if isinstance(log.get("sha256"), str) else None,
                )
            if "serial" not in roles and "qmp-events" not in roles:
                error(errors, f"{scenario_path}.logs", "must include serial or qmp-events evidence")
            if is_v2:
                validate_scenario_v2(errors, root, scenario_path, scenario, name, logs_by_role, check_files)
    missing = sorted(set(REQUIRED_SCENARIOS) - set(by_name))
    if missing:
        error(errors, "$.scenarios", f"missing required scenarios: {', '.join(missing)}")
    unexpected = sorted(set(by_name) - set(REQUIRED_SCENARIOS))
    if unexpected:
        error(errors, "$.scenarios", f"unknown production-runtime scenarios: {', '.join(unexpected)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-target")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-artifact-sha256")
    parser.add_argument(
        "--profile",
        choices=("technical-dry-run", "release-candidate", "production-candidate", "production-runtime"),
        default="release-candidate",
    )
    args = parser.parse_args()
    errors = validate(
        args.input,
        check_files=args.check_files,
        require_pass=args.require_pass,
        expected_version=args.expected_version,
        expected_target=args.expected_target,
        expected_source_sha=args.expected_source_sha,
        expected_artifact_sha256=args.expected_artifact_sha256,
        profile=args.profile,
    )
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated production-runtime QEMU suite: {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
