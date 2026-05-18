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


SCHEMA_VERSION = "suderra.qemu-acceptance.v2"
STATUS_VALUES = {"passed", "failed", "infra-error", "timeout", "not-applicable"}
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


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def check_string(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        error(errors, path, "must be a non-empty string")


def check_sha256(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        error(errors, path, "must be a lowercase sha256 hex digest")


def check_relative_file(errors: list[str], root: Path, path: str, value: Any, check_files: bool) -> None:
    check_string(errors, path, value)
    if not isinstance(value, str):
        return
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return
    actual = root / rel
    if check_files and (not actual.is_file() or actual.stat().st_size <= 0):
        error(errors, path, f"referenced file is missing or empty: {value}")


def validate(path: Path, check_files: bool, require_pass: bool) -> list[str]:
    root = path.parent
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{path}: cannot read QEMU evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at", "image", "qemu_version", "firmware"):
        check_string(errors, f"$.{field}", payload.get(field))
    check_sha256(errors, "$.image_sha256", payload.get("image_sha256"))
    check_sha256(errors, "$.firmware_sha256", payload.get("firmware_sha256"))
    status = payload.get("status")
    if status not in STATUS_VALUES:
        error(errors, "$.status", f"must be one of: {', '.join(sorted(STATUS_VALUES))}")
    if require_pass and status != "passed":
        error(errors, "$.status", "must be passed for release QEMU input")
    logs = payload.get("logs")
    if not isinstance(logs, list) or not logs:
        error(errors, "$.logs", "must be a non-empty list")
    else:
        for idx, item in enumerate(logs):
            if not isinstance(item, dict):
                error(errors, f"$.logs[{idx}]", "must be an object")
                continue
            check_string(errors, f"$.logs[{idx}].role", item.get("role"))
            check_relative_file(errors, root, f"$.logs[{idx}].path", item.get("path"), check_files)
            check_sha256(errors, f"$.logs[{idx}].sha256", item.get("sha256"))
    checks = payload.get("checks")
    if not isinstance(checks, dict):
        error(errors, "$.checks", "must be an object")
        checks = {}
    missing = sorted(REQUIRED_CHECKS - set(checks))
    if missing:
        error(errors, "$.checks", f"missing required checks: {', '.join(missing)}")
    for name, result in checks.items():
        if not isinstance(result, dict):
            error(errors, f"$.checks.{name}", "must be an object")
            continue
        if result.get("status") not in {"passed", "failed", "not_applicable"}:
            error(errors, f"$.checks.{name}.status", "must be passed, failed, or not_applicable")
        if require_pass and result.get("status") != "passed":
            error(errors, f"$.checks.{name}.status", "must be passed for release QEMU input")
    facts = payload.get("guest_facts")
    if not isinstance(facts, dict):
        error(errors, "$.guest_facts", "must be an object")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()
    errors = validate(args.input, args.check_files, args.require_pass)
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated QEMU input: {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
