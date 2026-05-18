#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate pre-release Suderra hardware lab input.

This is intentionally separate from final release evidence. Lab input is
collected before a tag exists, then the release workflow binds it to the
actual staged, signed, and attested release bytes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.lab-evidence.v2"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
STATUS_VALUES = {"passed", "failed", "not_run", "not_applicable", "not_collected"}
REQUIRED_DEVICE_FIELDS = (
    "board",
    "serial",
    "sku",
    "storage_serial",
    "uart_adapter",
    "power_supply",
    "boot_firmware",
    "operator",
    "tested_at",
)
REQUIRED_LAB_CHECKS = (
    "board-identity",
    "artifact-hash",
    "flash-transcript",
    "full-readback-hash",
    "serial-boot-log",
    "post-install-boot",
    "partitions",
    "root-data-mounts",
    "network",
    "listeners",
    "failed-units",
    "thermal",
    "watchdog",
)
REQUIRED_USB_NEGATIVE_TESTS = (
    "no-target-disk",
    "ambiguous-targets",
    "usb-target-without-override",
    "tampered-payload",
    "bad-signature",
    "expired-manifest",
    "wrong-board",
    "small-target",
    "rollback-floor-violation",
)
REQUIRED_BOARDS_BY_TARGET = {
    "rpi4": ("raspberry-pi-4-model-b", "cm4-lite-sd", "cm4-emmc-io-board"),
    "pi-cm4-revpi-usb-installer": (
        "raspberry-pi-4-model-b",
        "cm4-lite-sd",
        "cm4-emmc-io-board",
        "revpi-connect-4",
    ),
    "revpi4": ("revpi-connect-4",),
}


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def is_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_string(errors: list[str], path: str, value: Any) -> None:
    if not is_string(value):
        error(errors, path, "must be a non-empty string")


def check_status(errors: list[str], path: str, value: Any) -> None:
    if value not in STATUS_VALUES:
        error(errors, path, f"must be one of: {', '.join(sorted(STATUS_VALUES))}")


def check_relative_file(
    errors: list[str],
    root: Path,
    path: str,
    value: Any,
    check_files: bool,
) -> None:
    if not is_string(value):
        error(errors, path, "must be a relative file path")
        return
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return
    actual = root / rel
    if check_files and (not actual.is_file() or actual.stat().st_size <= 0):
        error(errors, path, f"referenced file is missing or empty: {value}")


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line.rstrip()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def parse_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"expected key/value entry: {text!r}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def load_matrix(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"defconfigs": [], "variants": [], "security_scans": []}
    section: str | None = None
    current: dict[str, Any] | None = None
    pending_key: str | None = None
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            data.setdefault(section, [])
            current = None
            pending_key = None
            continue
        if section in {"defconfigs", "variants"}:
            if indent == 2 and text.startswith("- "):
                current = {}
                data[section].append(current)
                rest = text[2:].strip()
                if rest:
                    key, value = parse_key_value(rest)
                    current[key] = parse_scalar(value)
                pending_key = None
                continue
            if indent == 4 and current is not None:
                key, value = parse_key_value(text)
                if value:
                    current[key] = parse_scalar(value)
                    pending_key = None
                else:
                    current[key] = []
                    pending_key = key
                continue
            if indent == 6 and text.startswith("- ") and current is not None and pending_key:
                current[pending_key].append(parse_scalar(text[2:].strip()))
                continue
        if section == "security_scans" and indent == 2 and text.startswith("- "):
            data[section].append(parse_scalar(text[2:].strip()))
            continue
        raise ValueError(f"unsupported YAML subset at {path}:{lineno}: {raw}")
    return data


def release_targets_requiring_hardware(matrix: dict[str, Any]) -> list[str]:
    targets = []
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        target = str(row.get("target", ""))
        acceptance = str(row.get("acceptance", ""))
        if row.get("production_required") or "hardware" in acceptance:
            targets.append(target)
    return targets


def expected_from_lab_path(path: Path) -> tuple[str | None, str | None]:
    parts = path.as_posix().split("/")
    if path.name != "lab.json" or "release-lab-input" not in parts:
        return None, None
    index = len(parts) - 1 - parts[::-1].index("release-lab-input")
    if len(parts) <= index + 3:
        return None, None
    return parts[index + 1], parts[index + 2]


def validate_lab(
    path: Path,
    check_files: bool,
    require_pass: bool,
    expected_version: str | None = None,
    expected_target: str | None = None,
) -> list[str]:
    root = path.parent
    errors: list[str] = []
    inferred_version, inferred_target = expected_from_lab_path(path)
    expected_version = expected_version or inferred_version
    expected_target = expected_target or inferred_target
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{path}: cannot read lab evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at", "lab_id", "operator"):
        check_string(errors, f"$.{field}", payload.get(field))
    for field in ("version", "target"):
        value = payload.get(field)
        if isinstance(value, str) and not SAFE_ID_RE.fullmatch(value):
            error(errors, f"$.{field}", "must be a safe path identifier")
    if expected_version is not None and payload.get("version") != expected_version:
        error(errors, "$.version", f"must match lab evidence path version {expected_version}")
    if expected_target is not None and payload.get("target") != expected_target:
        error(errors, "$.target", f"must match lab evidence path target {expected_target}")
    devices = payload.get("devices")
    if not isinstance(devices, list) or not devices:
        error(errors, "$.devices", "must be a non-empty list")
        devices = []
    for idx, device in enumerate(devices):
        device_path = f"$.devices[{idx}]"
        if not isinstance(device, dict):
            error(errors, device_path, "must be an object")
            continue
        for field in REQUIRED_DEVICE_FIELDS:
            check_string(errors, f"{device_path}.{field}", device.get(field))
        check_status(errors, f"{device_path}.status", device.get("status"))
        if require_pass and device.get("status") != "passed":
            error(errors, f"{device_path}.status", "must be passed for release lab input")
        logs = device.get("logs")
        if not isinstance(logs, list) or not logs:
            error(errors, f"{device_path}.logs", "must be a non-empty list")
        else:
            for log_idx, log in enumerate(logs):
                check_relative_file(errors, root, f"{device_path}.logs[{log_idx}]", log, check_files)
        checks = device.get("checks")
        if not isinstance(checks, dict):
            error(errors, f"{device_path}.checks", "must be an object")
            checks = {}
        missing_checks = sorted(set(REQUIRED_LAB_CHECKS) - set(checks))
        if missing_checks:
            error(errors, f"{device_path}.checks", f"missing required checks: {', '.join(missing_checks)}")
        if device.get("board") == "revpi-connect-4" and "revpi-io" not in checks:
            error(errors, f"{device_path}.checks", "revpi-connect-4 requires revpi-io check")
        for check_name, check in checks.items():
            check_path = f"{device_path}.checks.{check_name}"
            if not isinstance(check, dict):
                error(errors, check_path, "must be an object")
                continue
            check_status(errors, f"{check_path}.status", check.get("status"))
            check_relative_file(errors, root, f"{check_path}.evidence", check.get("evidence"), check_files)
            if require_pass and check.get("status") != "passed":
                error(errors, f"{check_path}.status", "must be passed for release lab input")
    target = str(payload.get("target", ""))
    required_boards = REQUIRED_BOARDS_BY_TARGET.get(target, ())
    if required_boards:
        seen = {
            device.get("board")
            for device in devices
            if isinstance(device, dict) and isinstance(device.get("board"), str)
        }
        missing = sorted(set(required_boards) - seen)
        if missing:
            error(errors, "$.devices", f"missing required board evidence: {', '.join(missing)}")
    negative_tests = payload.get("negative_tests")
    if not isinstance(negative_tests, list):
        error(errors, "$.negative_tests", "must be a list")
        negative_tests = []
    if target == "pi-cm4-revpi-usb-installer":
        names = {
            item.get("name")
            for item in negative_tests
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        missing = sorted(set(REQUIRED_USB_NEGATIVE_TESTS) - names)
        if missing:
            error(errors, "$.negative_tests", f"missing required negative tests: {', '.join(missing)}")
    for idx, item in enumerate(negative_tests):
        item_path = f"$.negative_tests[{idx}]"
        if not isinstance(item, dict):
            error(errors, item_path, "must be an object")
            continue
        check_string(errors, f"{item_path}.name", item.get("name"))
        check_string(errors, f"{item_path}.failure_code", item.get("failure_code"))
        check_status(errors, f"{item_path}.status", item.get("status"))
        check_relative_file(errors, root, f"{item_path}.evidence", item.get("evidence"), check_files)
        if require_pass and item.get("status") != "passed":
            error(errors, f"{item_path}.status", "must be passed for release lab input")
    return errors


def validate_command(args: argparse.Namespace) -> int:
    errors = validate_lab(
        args.input,
        args.check_files,
        args.require_pass,
        args.expected_version,
        args.expected_target,
    )
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated lab evidence: {args.input}")
    return 0


def validate_matrix_command(args: argparse.Namespace) -> int:
    matrix = load_matrix(args.matrix)
    failures: list[str] = []
    for target in release_targets_requiring_hardware(matrix):
        evidence = args.root / args.version / target / "lab.json"
        failures.extend(
            validate_lab(
                evidence,
                args.check_files,
                args.require_pass,
                args.version,
                target,
            )
        )
    if failures:
        for item in failures:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated release lab input for {args.version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--require-pass", action="store_true")
    validate.add_argument("--check-files", action="store_true")
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-target")
    validate.set_defaults(func=validate_command)
    validate_matrix = subparsers.add_parser("validate-matrix")
    validate_matrix.add_argument("--version", required=True)
    validate_matrix.add_argument("--root", type=Path, default=Path("release-lab-input"))
    validate_matrix.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate_matrix.add_argument("--require-pass", action="store_true")
    validate_matrix.add_argument("--check-files", action="store_true")
    validate_matrix.set_defaults(func=validate_matrix_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
