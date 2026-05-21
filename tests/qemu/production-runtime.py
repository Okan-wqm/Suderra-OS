#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Execute production-runtime QEMU scenario plans.

The runner intentionally executes commands from a reviewed scenario plan instead
of accepting hand-written pass/fail JSON. Each command is expected to perform the
real scenario setup and QEMU run, then leave raw logs under the scenario work
directory. The runner records hashes and validates the final suite contract.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "evidence" / "validate-production-runtime-suite.py"


def load_validator() -> Any:
    spec = importlib.util.spec_from_file_location("validate_production_runtime_suite", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return "0" * 64
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(rel)
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
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


def command_from_spec(item: dict[str, Any], path: str) -> list[str]:
    command = item.get("command")
    if isinstance(command, list) and all(isinstance(part, str) and part for part in command):
        return command
    if isinstance(command, str) and command.strip():
        return shlex.split(command)
    raise ValueError(f"{path}.command must be a command array or shell-like command string")


def log_entries(base: Path, scenario_dir: Path) -> list[dict[str, Any]]:
    output = []
    for path in sorted(scenario_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        role = path.stem
        if path.name.endswith(".serial.log"):
            role = "serial"
        elif path.name.endswith(".qmp.json"):
            role = "qmp-events"
        elif path.name.endswith(".stderr.log"):
            role = "qemu-stderr"
        elif path.name.endswith(".stdout.log"):
            role = "qemu-stdout"
        output.append(
            {
                "role": role,
                "path": rel,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return output


def execute_scenario(
    plan: dict[str, Any],
    item: dict[str, Any],
    idx: int,
    work_root: Path,
) -> dict[str, Any]:
    name = require_string(item, "name", f"scenarios[{idx}]")
    scenario_dir = work_root / name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = scenario_dir / "runner.stdout.log"
    stderr_path = scenario_dir / "runner.stderr.log"
    before_root = scenario_dir / "mutation-before"
    after_root = scenario_dir / "mutation-after"
    before_digest = sha256_tree(before_root)
    started_at = now_utc()
    command = command_from_spec(item, f"scenarios[{idx}]")
    env = {
        **{key: str(value) for key, value in plan.get("environment", {}).items() if isinstance(key, str)},
        "SUDERRA_PRODUCTION_SCENARIO": name,
        "SUDERRA_SCENARIO_DIR": str(scenario_dir),
        "SUDERRA_IMAGE": str(plan["image"]),
        "SUDERRA_OVMF_CODE": str(plan["ovmf_code"]),
        "SUDERRA_OVMF_VARS": str(plan["ovmf_vars"]),
        "SUDERRA_SWTPM_STATE": str(plan["swtpm_state"]),
    }
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, **env},
        stdout=stdout_path.open("wb"),
        stderr=stderr_path.open("wb"),
        check=False,
    )
    completed_at = now_utc()
    after_digest = sha256_tree(after_root)
    expected_exit_code = item.get("expected_exit_code", 0)
    status = "passed" if result.returncode == expected_exit_code else "failed"
    observed_outcome = str(item.get("expected_outcome")) if status == "passed" else "userspace-rejected"
    mutation_type = str(item.get("mutation_type", "none" if name == "signed-boot" else "external-command"))
    mutation_target = str(item.get("mutation_target", scenario_dir))
    if name != "signed-boot" and before_digest == after_digest:
        # External scenario commands that mutate outside mutation-before/after
        # must write explicit digest files to avoid passing on no-op evidence.
        before_file = scenario_dir / "mutation.before.sha256"
        after_file = scenario_dir / "mutation.after.sha256"
        if before_file.is_file() and after_file.is_file():
            before_digest = before_file.read_text(encoding="utf-8").strip()
            after_digest = after_file.read_text(encoding="utf-8").strip()
    return {
        "name": name,
        "status": status,
        "expected_outcome": require_string(item, "expected_outcome", f"scenarios[{idx}]"),
        "observed_outcome": observed_outcome,
        "command": " ".join(shlex.quote(part) for part in command),
        "started_at": started_at,
        "completed_at": completed_at,
        "termination_class": "exit-code",
        "failure_class": "none" if status == "passed" else "security_failure",
        "exit_code": result.returncode,
        "expected_exit_code": expected_exit_code,
        "mutation": {
            "type": mutation_type,
            "target": mutation_target,
            "before_sha256": before_digest,
            "after_sha256": after_digest,
        },
        "logs": log_entries(work_root, scenario_dir),
    }


def create_command(args: argparse.Namespace) -> int:
    plan = read_json(args.plan)
    if not isinstance(plan, dict):
        raise ValueError("scenario plan must be a JSON object")
    for field in ("version", "target", "source_sha", "image", "ovmf_code", "ovmf_vars", "swtpm_state"):
        require_string(plan, field, "plan")
    image = Path(plan["image"])
    ovmf_code = Path(plan["ovmf_code"])
    ovmf_vars = Path(plan["ovmf_vars"])
    swtpm_state = Path(plan["swtpm_state"])
    for path in (image, ovmf_code, ovmf_vars):
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"required input file is missing or empty: {path}")
    if not swtpm_state.exists():
        raise ValueError(f"swtpm state path is missing: {swtpm_state}")
    scenarios_spec = plan.get("scenarios")
    if not isinstance(scenarios_spec, list) or not scenarios_spec:
        raise ValueError("plan.scenarios must be a non-empty list")
    work_root = args.output.parent / "production-runtime-logs"
    work_root.mkdir(parents=True, exist_ok=True)
    plan = dict(plan)
    plan["image"] = image
    plan["ovmf_code"] = ovmf_code
    plan["ovmf_vars"] = ovmf_vars
    plan["swtpm_state"] = swtpm_state
    suite = {
        "schema_version": load_validator().SCHEMA_VERSION,
        "version": plan["version"],
        "target": plan["target"],
        "source_sha": plan["source_sha"],
        "generated_at": now_utc(),
        "image": str(image),
        "image_sha256": sha256_file(image),
        "ovmf_code": str(ovmf_code),
        "ovmf_code_sha256": sha256_file(ovmf_code),
        "ovmf_vars": str(ovmf_vars),
        "ovmf_vars_sha256": sha256_file(ovmf_vars),
        "swtpm_state": str(swtpm_state),
        "swtpm_state_sha256": sha256_tree(swtpm_state),
        "scenarios": [
            execute_scenario(plan, item, idx, work_root)
            for idx, item in enumerate(scenarios_spec)
            if isinstance(item, dict)
        ],
    }
    write_json(args.output, suite)
    failures = load_validator().validate(
        args.output,
        check_files=True,
        require_pass=True,
        expected_version=str(plan["version"]),
        expected_target=str(plan["target"]),
        expected_source_sha=str(plan["source_sha"]),
        expected_artifact_sha256=sha256_file(image),
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote production-runtime QEMU suite: {args.output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--plan", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
