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


SCHEMA_VERSION = "suderra.qemu-production-runtime-suite.v1"
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


def validate(
    path: Path,
    *,
    check_files: bool,
    require_pass: bool,
    expected_version: str | None = None,
    expected_target: str | None = None,
    expected_source_sha: str | None = None,
    expected_artifact_sha256: str | None = None,
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

    if payload.get("schema_version") != SCHEMA_VERSION:
        error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
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
            for log_idx, log in enumerate(logs):
                log_path = f"{scenario_path}.logs[{log_idx}]"
                if not isinstance(log, dict):
                    error(errors, log_path, "must be an object")
                    continue
                role = log.get("role")
                check_string(errors, f"{log_path}.role", role)
                if isinstance(role, str):
                    roles.add(role)
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
    args = parser.parse_args()
    errors = validate(
        args.input,
        check_files=args.check_files,
        require_pass=args.require_pass,
        expected_version=args.expected_version,
        expected_target=args.expected_target,
        expected_source_sha=args.expected_source_sha,
        expected_artifact_sha256=args.expected_artifact_sha256,
    )
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated production-runtime QEMU suite: {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
