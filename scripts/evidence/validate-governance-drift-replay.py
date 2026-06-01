#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Select and replay signed governance drift evidence for release gates."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


SCHEMA_VERSION = "suderra.governance-drift-run-manifest.v1"
VALIDATION_SCHEMA_VERSION = "suderra.github-governance-validation.v2"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def select_run(args: argparse.Namespace) -> int:
    policy = read_json(args.policy)
    payload = read_json(args.runs_json)
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        print("ERROR: workflow runs JSON must contain workflow_runs", file=sys.stderr)
        return 1
    max_age = timedelta(days=int(policy.get("audit_log_lookback_days", 30)))
    now = datetime.now(timezone.utc)
    for run in runs:
        if not isinstance(run, dict):
            continue
        if run.get("conclusion") != "success" or run.get("status") not in {None, "completed"}:
            continue
        if run.get("head_branch") != args.expected_branch:
            continue
        created_at = parse_utc(run.get("created_at"))
        if created_at is None or now - created_at > max_age:
            continue
        args.output.write_text(str(run["id"]) + "\n", encoding="utf-8")
        print(f"selected governance drift run: {run['id']}")
        return 0
    print("ERROR: no fresh successful governance drift run found", file=sys.stderr)
    return 1


def validate_replay(args: argparse.Namespace) -> int:
    failures: list[str] = []
    root = args.artifact_root
    validation_path = root / "governance-policy-validation.json"
    manifest_path = root / "drift-run-manifest.json"
    selected_run = read_json(args.selected_run_json)
    validation = read_json(validation_path)
    manifest = read_json(manifest_path)
    if selected_run.get("conclusion") != "success" or selected_run.get("status") not in {None, "completed"}:
        failures.append("selected governance drift run must be fresh completed success API payload")
    if validation.get("schema_version") != VALIDATION_SCHEMA_VERSION:
        failures.append("governance drift evidence schema mismatch")
    if validation.get("status") != "passed":
        failures.append("governance drift evidence did not pass")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append("governance drift run manifest schema mismatch")
    if str(manifest.get("run_id")) != str(selected_run.get("id")):
        failures.append("governance drift run manifest run_id mismatch")
    if str(manifest.get("run_attempt")) != str(selected_run.get("run_attempt", 1)):
        failures.append("governance drift run manifest run_attempt mismatch")
    if manifest.get("workflow_path") != args.expected_workflow_path:
        failures.append("governance drift run manifest workflow path mismatch")
    if manifest.get("branch") != args.expected_branch or selected_run.get("head_branch") != args.expected_branch:
        failures.append("governance drift evidence must bind to the expected branch")
    if manifest.get("head_sha") != selected_run.get("head_sha"):
        failures.append("governance drift run manifest head_sha mismatch")
    checks = {
        "policy_sha256": args.policy,
        "snapshot_manifest_sha256": root / "snapshot-manifest.json",
        "governance_validation_sha256": validation_path,
    }
    for field, path in checks.items():
        if not path.is_file() or path.stat().st_size <= 0:
            failures.append(f"governance drift replay missing file for {field}: {path}")
            continue
        if manifest.get(field) != sha256_file(path):
            failures.append(f"governance drift run manifest {field} mismatch")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated governance drift replay: {manifest.get('run_id')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    select = subparsers.add_parser("select-run")
    select.add_argument("--runs-json", type=Path, required=True)
    select.add_argument("--policy", type=Path, required=True)
    select.add_argument("--expected-branch", default="main")
    select.add_argument("--output", type=Path, required=True)
    select.set_defaults(func=select_run)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--selected-run-json", type=Path, required=True)
    validate.add_argument("--artifact-root", type=Path, required=True)
    validate.add_argument("--policy", type=Path, required=True)
    validate.add_argument("--expected-workflow-path", default=".github/workflows/governance-drift.yml")
    validate.add_argument("--expected-branch", default="main")
    validate.set_defaults(func=validate_replay)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
