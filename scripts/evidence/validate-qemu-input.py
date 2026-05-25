#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate Suderra QEMU acceptance input evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA_VERSION = "suderra.qemu-acceptance.v4"
LEGACY_SCHEMA_VERSIONS = {"suderra.qemu-acceptance.v2", "suderra.qemu-acceptance.v3"}
STATUS_VALUES = {"passed", "failed", "infra-error", "infra_error", "timeout", "not-applicable", "not_applicable"}
FAILURE_CLASSES = {"none", "timeout", "infra_error", "semantic_failure", "security_failure", "operator_error"}
REQUIRED_CHECKS = {
    "boot",
    "systemd",
    "zero-failed-units",
    "no-kernel-panic",
    "no-emergency-mode",
    "os-release",
    "kernel",
    "rootfs",
    "network",
    "firstboot-idempotence",
    "lockdown-transition",
    "listeners",
    "firewall",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_LOG_ROLES = {"serial", "qmp-events", "qemu-stderr"}
REQUIRED_STRICT_LOG_ROLES = REQUIRED_LOG_ROLES | {"qemu-semantic"}
PLACEHOLDER_VALUES = {"TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING"}
SEMANTIC_FACT_FIELDS = (
    "os_release",
    "kernel",
    "rootfs",
    "failed_units",
    "network",
    "listeners",
    "firewall",
    "firstboot",
    "lockdown",
)
PRODUCTION_FACT_FIELDS = (
    "secure_boot",
    "dm_verity",
    "rauc",
    "data_encryption",
    "anti_rollback",
)
SEMANTIC_CHECKS = {
    "zero-failed-units",
    "os-release",
    "kernel",
    "rootfs",
    "network",
    "firstboot-idempotence",
    "lockdown-transition",
    "listeners",
    "firewall",
}
PRODUCTION_RUNTIME_CHECKS = {
    "secure-boot-enforced",
    "dm-verity-tamper-rejection",
    "rauc-good-update",
    "rauc-bad-signature-rejection",
    "rauc-health-rollback",
    "data-luks",
    "anti-rollback",
}
STRICT_PROFILES = {"release-candidate", "production-candidate", "production-runtime"}
PRODUCTION_PROFILES = {"production-candidate", "production-runtime"}


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def check_string(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        error(errors, path, "must be a non-empty string")


def check_non_placeholder(errors: list[str], path: str, value: Any) -> None:
    if isinstance(value, str) and value.strip() in PLACEHOLDER_VALUES:
        error(errors, path, "must not be placeholder evidence")


def check_sha256(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        error(errors, path, "must be a lowercase sha256 hex digest")
    elif value == "0" * 64:
        error(errors, path, "must not be the all-zero sha256 digest")


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_relative_file(
    errors: list[str],
    root: Path,
    path: str,
    value: Any,
    check_files: bool,
    expected_sha256: str | None = None,
    allow_empty: bool = False,
) -> Path | None:
    check_string(errors, path, value)
    if not isinstance(value, str):
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return None
    actual = root / rel
    if check_files and (not actual.is_file() or (actual.stat().st_size <= 0 and not allow_empty)):
        error(errors, path, f"referenced file is missing or empty: {value}")
        return actual
    if check_files and expected_sha256 is not None and actual.is_file():
        actual_sha256 = sha256_file(actual)
        if actual_sha256 != expected_sha256:
            error(errors, path, f"referenced file sha256 mismatch: expected {expected_sha256}, got {actual_sha256}")
    return actual


def check_semantic_log(
    errors: list[str],
    path: Path | None,
    facts: dict[str, Any],
    check_files: bool,
) -> None:
    if not check_files or path is None:
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(errors, "$.logs[qemu-semantic].path", f"cannot read semantic QEMU JSON: {exc}")
        return
    if not isinstance(payload, dict):
        error(errors, "$.logs[qemu-semantic].path", "semantic QEMU JSON must be an object")
        return
    if payload.get("schema_version") != "suderra.qemu-semantic.v1":
        error(errors, "$.logs[qemu-semantic].schema_version", "must be suderra.qemu-semantic.v1")
    for field in SEMANTIC_FACT_FIELDS:
        if field not in payload:
            error(errors, f"$.logs[qemu-semantic].{field}", "must be present in semantic QEMU JSON")
        if field not in facts:
            continue
        if payload.get(field) != facts.get(field):
            error(errors, f"$.guest_facts.{field}", "must match qemu-semantic log payload")


def expected_from_qemu_path(path: Path) -> tuple[str | None, str | None]:
    parts = path.as_posix().split("/")
    if path.name != "qemu.json" or "release-lab-input" not in parts:
        return None, None
    index = len(parts) - 1 - parts[::-1].index("release-lab-input")
    if len(parts) <= index + 2:
        return None, None
    return parts[index + 1], parts[index + 2]


def check_binding(
    errors: list[str],
    payload: dict[str, Any],
    expected_version: str | None,
    expected_target: str | None,
    expected_source_sha: str | None,
    expected_artifact_sha256: str | None,
) -> None:
    if expected_version is not None and payload.get("version") != expected_version:
        error(errors, "$.version", f"must match QEMU evidence path version {expected_version}")
    if expected_target is not None and payload.get("target") != expected_target:
        error(errors, "$.target", f"must match QEMU evidence path target {expected_target}")
    if expected_source_sha is not None:
        source_sha = payload.get("source_sha")
        if source_sha != expected_source_sha:
            error(errors, "$.source_sha", f"must match bound source sha {expected_source_sha}")
    source_sha = payload.get("source_sha")
    if source_sha is not None and (not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha)):
        error(errors, "$.source_sha", "must be a lowercase git commit sha")
    if expected_artifact_sha256 is not None and payload.get("image_sha256") != expected_artifact_sha256:
        error(errors, "$.image_sha256", f"must match bound artifact sha256 {expected_artifact_sha256}")


def validate_termination(errors: list[str], payload: dict[str, Any], require_pass: bool, profile: str) -> None:
    termination = payload.get("termination")
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        if profile in STRICT_PROFILES:
            error(errors, "$.schema_version", f"strict QEMU profile requires {SCHEMA_VERSION}")
        return
    if not isinstance(termination, dict):
        error(errors, "$.termination", "must be an object")
        return
    for field in ("mode", "reason"):
        check_string(errors, f"$.termination.{field}", termination.get(field))
    for field in ("killed", "timeout", "qmp_quit_sent", "qmp_quit_ack", "acceptable"):
        if not isinstance(termination.get(field), bool):
            error(errors, f"$.termination.{field}", "must be a boolean")
    exit_status = termination.get("exit_status")
    if exit_status is not None and not isinstance(exit_status, int):
        error(errors, "$.termination.exit_status", "must be an integer or null")
    sig = termination.get("signal")
    if sig is not None and (not isinstance(sig, int) or sig <= 0):
        error(errors, "$.termination.signal", "must be a positive integer or null")
    if require_pass or payload.get("status") == "passed":
        if termination.get("acceptable") is not True:
            error(errors, "$.termination.acceptable", "must be true for passed QEMU evidence")
        if termination.get("killed") is not False:
            error(errors, "$.termination.killed", "must be false for passed QEMU evidence")
        if termination.get("timeout") is not False:
            error(errors, "$.termination.timeout", "must be false for passed QEMU evidence")
        if exit_status != 0:
            error(errors, "$.termination.exit_status", "must be 0 for passed QEMU evidence")
        if payload.get("qemu_exit_status") != 0:
            error(errors, "$.qemu_exit_status", "must be 0 for passed QEMU evidence")


def validate_production_facts(errors: list[str], facts: dict[str, Any], checks: dict[str, Any]) -> None:
    os_release = facts.get("os_release")
    variant = os_release.get("VARIANT") if isinstance(os_release, dict) else None
    if variant != "prod":
        error(errors, "$.guest_facts.os_release.VARIANT", "must be prod for production-runtime QEMU input")
    rootfs = facts.get("rootfs")
    root_source = rootfs.get("mount_source") if isinstance(rootfs, dict) else None
    cmdline_root = rootfs.get("cmdline_root") if isinstance(rootfs, dict) else None
    if not any(isinstance(value, str) and ("dm-" in value or "verity" in value.lower()) for value in (root_source, cmdline_root)):
        error(errors, "$.guest_facts.rootfs", "must show dm-verity-backed rootfs for production-runtime")
    lockdown = facts.get("lockdown")
    lockdown_status = lockdown.get("status") if isinstance(lockdown, dict) else None
    if lockdown_status not in {"integrity", "confidentiality", "locked", "enforced"}:
        error(errors, "$.guest_facts.lockdown.status", "must be an enforced lockdown state for production-runtime")
    listeners = facts.get("listeners")
    if not isinstance(listeners, list):
        error(errors, "$.guest_facts.listeners", "must be a list for production-runtime")
    elif listeners:
        error(errors, "$.guest_facts.listeners", "must be empty for production-runtime")
    firewall = facts.get("firewall")
    if not isinstance(firewall, dict) or firewall.get("loaded") is not True:
        error(errors, "$.guest_facts.firewall.loaded", "must be true for production-runtime")
    for field in PRODUCTION_FACT_FIELDS:
        if field not in facts:
            error(errors, f"$.guest_facts.{field}", "must be collected for production-runtime")
    secure_boot = facts.get("secure_boot")
    if not isinstance(secure_boot, dict) or secure_boot.get("enabled") is not True:
        error(errors, "$.guest_facts.secure_boot.enabled", "must be true for production-runtime")
    dm_verity = facts.get("dm_verity")
    if not isinstance(dm_verity, dict) or dm_verity.get("active") is not True:
        error(errors, "$.guest_facts.dm_verity.active", "must be true for production-runtime")
    rauc = facts.get("rauc")
    if not isinstance(rauc, dict) or rauc.get("available") is not True:
        error(errors, "$.guest_facts.rauc.available", "must be true for production-runtime")
    data_encryption = facts.get("data_encryption")
    if not isinstance(data_encryption, dict) or data_encryption.get("encrypted") is not True:
        error(errors, "$.guest_facts.data_encryption.encrypted", "must be true for production-runtime")
    anti_rollback = facts.get("anti_rollback")
    rollback_floor = anti_rollback.get("rollback_floor") if isinstance(anti_rollback, dict) else None
    if not isinstance(rollback_floor, str) or not rollback_floor.strip() or rollback_floor in PLACEHOLDER_VALUES:
        error(errors, "$.guest_facts.anti_rollback.rollback_floor", "must be collected for production-runtime")
    for name in ("rootfs", "lockdown-transition", "listeners", "firewall", *sorted(PRODUCTION_RUNTIME_CHECKS)):
        result = checks.get(name)
        if not isinstance(result, dict) or result.get("status") != "passed":
            error(errors, f"$.checks.{name}.status", "must be passed for production-runtime")


def validate(
    path: Path,
    check_files: bool,
    require_pass: bool,
    profile: str,
    expected_version: str | None = None,
    expected_target: str | None = None,
    expected_source_sha: str | None = None,
    expected_artifact_sha256: str | None = None,
) -> list[str]:
    root = path.parent
    errors: list[str] = []
    inferred_version, inferred_target = expected_from_qemu_path(path)
    expected_version = expected_version or inferred_version
    expected_target = expected_target or inferred_target
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{path}: cannot read QEMU evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        if profile in STRICT_PROFILES or schema_version not in LEGACY_SCHEMA_VERSIONS:
            error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
    failure_class = payload.get("failure_class")
    if schema_version == SCHEMA_VERSION:
        if failure_class not in FAILURE_CLASSES:
            error(errors, "$.failure_class", f"must be one of: {', '.join(sorted(FAILURE_CLASSES))}")
        if payload.get("status") == "passed" and failure_class != "none":
            error(errors, "$.failure_class", "must be none when status is passed")
    for field in ("version", "target", "generated_at", "image", "qemu_version", "firmware"):
        check_string(errors, f"$.{field}", payload.get(field))
        if profile in STRICT_PROFILES and payload.get("status") == "passed":
            check_non_placeholder(errors, f"$.{field}", payload.get(field))
    check_sha256(errors, "$.image_sha256", payload.get("image_sha256"))
    check_sha256(errors, "$.firmware_sha256", payload.get("firmware_sha256"))
    check_binding(errors, payload, expected_version, expected_target, expected_source_sha, expected_artifact_sha256)
    status = payload.get("status")
    if status not in STATUS_VALUES:
        error(errors, "$.status", f"must be one of: {', '.join(sorted(STATUS_VALUES))}")
    if require_pass and status != "passed":
        error(errors, "$.status", "must be passed for release QEMU input")
    validate_termination(errors, payload, require_pass, profile)
    logs = payload.get("logs")
    log_roles: set[str] = set()
    semantic_log_path: Path | None = None
    if not isinstance(logs, list) or not logs:
        error(errors, "$.logs", "must be a non-empty list")
    else:
        for idx, item in enumerate(logs):
            if not isinstance(item, dict):
                error(errors, f"$.logs[{idx}]", "must be an object")
                continue
            check_string(errors, f"$.logs[{idx}].role", item.get("role"))
            if isinstance(item.get("role"), str):
                log_roles.add(item["role"])
            check_sha256(errors, f"$.logs[{idx}].sha256", item.get("sha256"))
            expected_sha = item.get("sha256") if isinstance(item.get("sha256"), str) else None
            allow_empty = item.get("role") == "qemu-stderr"
            actual_log = check_relative_file(
                errors,
                root,
                f"$.logs[{idx}].path",
                item.get("path"),
                check_files,
                expected_sha,
                allow_empty,
            )
            if item.get("role") == "qemu-semantic":
                semantic_log_path = actual_log
    if profile in STRICT_PROFILES:
        missing_roles = sorted(REQUIRED_STRICT_LOG_ROLES - log_roles)
        if missing_roles:
            error(errors, "$.logs", f"missing required log roles: {', '.join(missing_roles)}")
    checks = payload.get("checks")
    if not isinstance(checks, dict):
        error(errors, "$.checks", "must be an object")
        checks = {}
    missing = sorted(REQUIRED_CHECKS - set(checks))
    if missing:
        error(errors, "$.checks", f"missing required checks: {', '.join(missing)}")
    if profile in PRODUCTION_PROFILES:
        missing_production = sorted(PRODUCTION_RUNTIME_CHECKS - set(checks))
        if missing_production:
            error(errors, "$.checks", f"missing production-runtime checks: {', '.join(missing_production)}")
    for name, result in checks.items():
        if not isinstance(result, dict):
            error(errors, f"$.checks.{name}", "must be an object")
            continue
        if result.get("status") not in {"passed", "failed", "not_applicable"}:
            error(errors, f"$.checks.{name}.status", "must be passed, failed, or not_applicable")
        if require_pass and result.get("status") != "passed":
            error(errors, f"$.checks.{name}.status", "must be passed for release QEMU input")
        if profile in STRICT_PROFILES and name in SEMANTIC_CHECKS:
            if not isinstance(result.get("evidence"), str) or not result.get("evidence", "").strip():
                error(errors, f"$.checks.{name}.evidence", "must describe machine-collected evidence")
            else:
                check_non_placeholder(errors, f"$.checks.{name}.evidence", result.get("evidence"))
            if not isinstance(result.get("source"), str) or not result.get("source", "").strip():
                error(errors, f"$.checks.{name}.source", "must name the guest command or log source")
            else:
                check_non_placeholder(errors, f"$.checks.{name}.source", result.get("source"))
    facts = payload.get("guest_facts")
    if not isinstance(facts, dict):
        error(errors, "$.guest_facts", "must be an object")
    elif profile in STRICT_PROFILES:
        for field in SEMANTIC_FACT_FIELDS:
            if field not in facts:
                error(errors, f"$.guest_facts.{field}", "must be collected for release-candidate QEMU input")
            elif field != "listeners":
                value = facts[field]
                if isinstance(value, str):
                    if not value.strip():
                        error(errors, f"$.guest_facts.{field}", "must not be empty")
                    check_non_placeholder(errors, f"$.guest_facts.{field}", value)
                elif isinstance(value, dict) and not value:
                    error(errors, f"$.guest_facts.{field}", "must not be an empty object")
                elif value is None:
                    error(errors, f"$.guest_facts.{field}", "must not be null")
        listeners = facts.get("listeners")
        if "listeners" in facts and not isinstance(listeners, list):
            error(errors, "$.guest_facts.listeners", "must be a list")
        check_semantic_log(errors, semantic_log_path, facts, check_files)
        if profile in PRODUCTION_PROFILES:
            validate_production_facts(errors, facts, checks)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument(
        "--profile",
        choices=("smoke", "technical-dry-run", "release-candidate", "production-candidate", "production-runtime"),
        default="release-candidate",
    )
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-target")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-artifact-sha256")
    args = parser.parse_args()
    errors = validate(
        args.input,
        args.check_files,
        args.require_pass,
        args.profile,
        args.expected_version,
        args.expected_target,
        args.expected_source_sha,
        args.expected_artifact_sha256,
    )
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated QEMU input: {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
