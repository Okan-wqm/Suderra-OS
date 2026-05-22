#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate Buildroot and payload package performance budgets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_budget(path: Path) -> dict[str, Any]:
    payload: dict[str, Any] = {"default": {}, "targets": {}}
    current: dict[str, Any] | None = None
    current_key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line == "default:":
            current = payload["default"]
            current_key = None
            continue
        if line == "targets:":
            current = None
            current_key = "targets"
            continue
        if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            if current_key != "targets":
                raise ValueError(f"unsupported budget section: {raw}")
            name = line.strip()[:-1]
            payload["targets"].setdefault(name, {})
            current = payload["targets"][name]
            continue
        if line.startswith("  ") and current is not None:
            key, value = line.strip().split(":", 1)
            value = value.strip()
            if value in {"true", "false"}:
                current[key] = value == "true"
            elif value:
                current[key] = int(value)
            continue
        if line.startswith("    ") and current is not None:
            key, value = line.strip().split(":", 1)
            value = value.strip()
            current[key] = int(value) if value else value
            continue
        raise ValueError(f"unsupported budget YAML subset: {raw}")
    return payload


def budget_for(config: dict[str, Any], defconfig: str) -> dict[str, Any]:
    result = dict(config.get("default", {}))
    result.update(config.get("targets", {}).get(defconfig, {}))
    return result


def validate_buildroot(args: argparse.Namespace) -> int:
    budget = budget_for(load_budget(args.budget), args.defconfig)
    payload = read_json(args.performance)
    failures: list[str] = []
    if payload.get("schema_version") != "suderra.buildroot-build-performance.v1":
        failures.append("performance evidence schema mismatch")
    build_time = payload.get("build_time_log")
    if not isinstance(build_time, dict) or build_time.get("present") is not True:
        failures.append("build-time.log evidence is missing")
    timing = payload.get("timing")
    if not isinstance(timing, dict):
        failures.append("timing evidence is missing")
    else:
        if timing.get("status") != "collected":
            failures.append("timing.status must be collected")
        completed_step_count = timing.get("completed_step_count")
        if not isinstance(completed_step_count, int) or completed_step_count <= 0:
            failures.append("timing.completed_step_count must be positive")
        max_seconds = budget.get("buildroot_timing_budget_seconds")
        total_seconds = timing.get("total_seconds")
        if not isinstance(total_seconds, (int, float)):
            failures.append("timing.total_seconds must be numeric")
        elif isinstance(max_seconds, int) and float(total_seconds) > max_seconds:
            failures.append(f"Buildroot timing exceeds budget: {total_seconds} > {max_seconds}")
    ccache = payload.get("ccache")
    if not isinstance(ccache, dict):
        failures.append("ccache evidence is missing")
    elif budget.get("require_cache_evidence", True) and ccache.get("present") is not True:
        failures.append("ccache evidence must be present")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    return 0


def validate_payload(args: argparse.Namespace) -> int:
    budget = budget_for(load_budget(args.budget), args.defconfig)
    payload = read_json(args.evidence)
    failures: list[str] = []
    if payload.get("schema_version") != "suderra.usb-installer-payload-package.v1":
        failures.append("payload package evidence schema mismatch")
    max_seconds = budget.get("payload_package_budget_seconds", 600)
    duration = payload.get("duration_seconds")
    if not isinstance(duration, (int, float)):
        failures.append("payload package duration_seconds is required")
    elif float(duration) > max_seconds:
        failures.append(f"payload packaging exceeds budget: {duration} > {max_seconds}")
    for field in ("base_manifest_sha256", "payload_inputs_sha256"):
        if not isinstance(payload.get(field), str) or not SHA256_RE.fullmatch(payload[field]):
            failures.append(f"{field} must be a sha256")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    buildroot = subparsers.add_parser("validate-buildroot")
    buildroot.add_argument("--budget", type=Path, required=True)
    buildroot.add_argument("--defconfig", required=True)
    buildroot.add_argument("--performance", type=Path, required=True)
    buildroot.set_defaults(func=validate_buildroot)
    payload = subparsers.add_parser("validate-payload")
    payload.add_argument("--budget", type=Path, required=True)
    payload.add_argument("--defconfig", required=True)
    payload.add_argument("--evidence", type=Path, required=True)
    payload.set_defaults(func=validate_payload)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
