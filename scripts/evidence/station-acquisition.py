#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Run station adapter commands and emit acquisition evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = "suderra.station-acquisition.v1"
REQUIRED_ADAPTER_ROLES = {
    "flash",
    "readback",
    "uart",
    "power",
    "storage",
    "tpm",
    "secure-boot",
    "rauc",
    "tamper",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_string(payload: dict[str, Any], field: str, path: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}.{field} must be a non-empty string")
    return value


def command_from_event(event: dict[str, Any], path: str) -> list[str]:
    command = event.get("command")
    if isinstance(command, list) and all(isinstance(part, str) and part for part in command):
        return command
    if isinstance(command, str) and command.strip():
        return shlex.split(command)
    raise ValueError(f"{path}.command must be a command array or shell-like command string")


def run_event(event: dict[str, Any], index: int, output_root: Path) -> dict[str, Any]:
    role = require_string(event, "role", f"events[{index}]")
    adapter_id = require_string(event, "adapter_id", f"events[{index}]")
    event_dir = output_root / f"{index:02d}-{role}"
    event_dir.mkdir(parents=True, exist_ok=True)
    stdout = event_dir / "stdout.log"
    stderr = event_dir / "stderr.log"
    command = command_from_event(event, f"events[{index}]")
    started_at = now_utc()
    result = subprocess.run(
        command,
        stdout=stdout.open("wb"),
        stderr=stderr.open("wb"),
        check=False,
    )
    completed_at = now_utc()
    expected_exit = int(event.get("expected_exit_code", 0))
    status = "passed" if result.returncode == expected_exit else "failed"
    measured = event.get("measured")
    if not isinstance(measured, dict):
        measured = {}
    return {
        "role": role,
        "adapter_id": adapter_id,
        "adapter_version": require_string(event, "adapter_version", f"events[{index}]"),
        "adapter_binary_sha256": require_string(event, "adapter_binary_sha256", f"events[{index}]"),
        "argv": command,
        "started_at": started_at,
        "completed_at": completed_at,
        "exit_code": result.returncode,
        "expected_exit_code": expected_exit,
        "status": status,
        "stdout": {
            "path": stdout.relative_to(output_root).as_posix(),
            "sha256": sha256_file(stdout),
            "bytes": stdout.stat().st_size,
        },
        "stderr": {
            "path": stderr.relative_to(output_root).as_posix(),
            "sha256": sha256_file(stderr),
            "bytes": stderr.stat().st_size,
        },
        "measured": measured,
    }


def create_command(args: argparse.Namespace) -> int:
    plan = read_json(args.plan)
    if not isinstance(plan, dict):
        raise ValueError("station acquisition plan must be a JSON object")
    events_spec = plan.get("events")
    if not isinstance(events_spec, list) or not events_spec:
        raise ValueError("plan.events must be a non-empty list")
    event_root = args.output.parent / "station-acquisition-events"
    event_root.mkdir(parents=True, exist_ok=True)
    events = [
        run_event(event, index, event_root)
        for index, event in enumerate(events_spec)
        if isinstance(event, dict)
    ]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "version": require_string(plan, "version", "plan"),
        "target": require_string(plan, "target", "plan"),
        "source_sha": require_string(plan, "source_sha", "plan"),
        "source_run_id": require_string(plan, "source_run_id", "plan"),
        "generated_at": now_utc(),
        "station_id": require_string(plan, "station_id", "plan"),
        "registry_sha256": require_string(plan, "registry_sha256", "plan"),
        "artifact_sha256": require_string(plan, "artifact_sha256", "plan"),
        "artifact_bytes": int(plan.get("artifact_bytes", 0)),
        "events_root": event_root.relative_to(args.output.parent).as_posix(),
        "events": events,
    }
    write_json(args.output, payload)
    failures = validate_payload(payload, args.output.parent, True)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote station acquisition evidence: {args.output}")
    return 0


def validate_payload(payload: dict[str, Any], root: Path, check_files: bool) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        errors.append("events must be a non-empty list")
        return errors
    roles = set()
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"events[{idx}] must be an object")
            continue
        roles.add(event.get("role"))
        if event.get("status") != "passed":
            errors.append(f"events[{idx}].status must be passed")
        measured = event.get("measured")
        if not isinstance(measured, dict):
            errors.append(f"events[{idx}].measured must be an object")
            measured = {}
        role = event.get("role")
        if role == "readback":
            expected = payload.get("artifact_sha256")
            actual = measured.get("sha256") or measured.get("actual_sha256") or measured.get("readback_sha256")
            if actual != expected:
                errors.append(f"events[{idx}].measured.sha256 must match artifact_sha256")
            if not isinstance(measured.get("bytes_read"), int) or measured.get("bytes_read", 0) != payload.get("artifact_bytes"):
                errors.append(f"events[{idx}].measured.bytes_read must match artifact_bytes")
        if role == "power":
            if measured.get("cycled") is not True:
                errors.append(f"events[{idx}].measured.cycled must be true")
            transcript = measured.get("transcript_sha256")
            if not isinstance(transcript, str) or not SHA256_RE.fullmatch(transcript) or transcript == "0" * 64:
                errors.append(f"events[{idx}].measured.transcript_sha256 must be a non-zero sha256")
        if role == "tpm" and measured.get("present") is not True:
            errors.append(f"events[{idx}].measured.present must be true")
        if role == "secure-boot":
            if measured.get("enabled") is not True:
                errors.append(f"events[{idx}].measured.enabled must be true")
            if measured.get("enforced") is not True:
                errors.append(f"events[{idx}].measured.enforced must be true")
        if role == "rauc":
            if measured.get("rollback_verified") is not True:
                errors.append(f"events[{idx}].measured.rollback_verified must be true")
            if measured.get("mark_good_verified") is not True:
                errors.append(f"events[{idx}].measured.mark_good_verified must be true")
        if role == "tamper":
            if measured.get("dm_verity_rejected") is not True:
                errors.append(f"events[{idx}].measured.dm_verity_rejected must be true")
            if measured.get("boot_tamper_rejected") is not True:
                errors.append(f"events[{idx}].measured.boot_tamper_rejected must be true")
        adapter_sha = event.get("adapter_binary_sha256")
        if not isinstance(adapter_sha, str) or not SHA256_RE.fullmatch(adapter_sha) or adapter_sha == "0" * 64:
            errors.append(f"events[{idx}].adapter_binary_sha256 must be a non-zero sha256")
        for log_field in ("stdout", "stderr"):
            ref = event.get(log_field)
            if not isinstance(ref, dict):
                errors.append(f"events[{idx}].{log_field} must be an object")
                continue
            rel = Path(str(ref.get("path", "")))
            if rel.is_absolute() or ".." in rel.parts:
                errors.append(f"events[{idx}].{log_field}.path must be relative")
                continue
            if check_files:
                actual = root / str(payload.get("events_root", "")) / rel
                if not actual.is_file():
                    errors.append(f"events[{idx}].{log_field}.path missing: {actual}")
                elif sha256_file(actual) != ref.get("sha256"):
                    errors.append(f"events[{idx}].{log_field}.sha256 mismatch")
    missing = sorted(REQUIRED_ADAPTER_ROLES - {role for role in roles if isinstance(role, str)})
    if missing:
        errors.append(f"events missing required adapter roles: {', '.join(missing)}")
    return errors


def validate_command(args: argparse.Namespace) -> int:
    payload = read_json(args.input)
    if not isinstance(payload, dict):
        print("ERROR: station acquisition must be a JSON object", file=sys.stderr)
        return 1
    failures = validate_payload(payload, args.input.parent, args.check_files)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated station acquisition evidence: {args.input}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--plan", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)
    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--check-files", action="store_true")
    validate.set_defaults(func=validate_command)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
