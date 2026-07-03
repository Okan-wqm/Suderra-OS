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
RUNTIME_MUTATIONS_PATH = Path(__file__).resolve().parent / "runtime_mutations.py"
SCENARIO_RESULT = "scenario-result.json"

# Producer input keys that must be coerced to filesystem paths / ints.
_MUTATION_PATH_KEYS = frozenset({
    "stub", "kernel", "osrel", "initrd", "cmdline_tampered", "sign_key",
    "sign_cert", "signed_uki", "image", "swtpm_state", "bundle_tool", "before_source",
})
_MUTATION_INT_KEYS = frozenset({"offset", "length"})


def load_validator() -> Any:
    spec = importlib.util.spec_from_file_location("validate_production_runtime_suite", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_mutations() -> Any:
    spec = importlib.util.spec_from_file_location("runtime_mutations", RUNTIME_MUTATIONS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {RUNTIME_MUTATIONS_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resolve_mutation_inputs(raw: dict[str, Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for key, value in raw.items():
        if key in _MUTATION_PATH_KEYS:
            resolved[key] = Path(str(value))
        elif key in _MUTATION_INT_KEYS:
            resolved[key] = int(value)
        else:
            resolved[key] = value
    return resolved


def produce_scenario_mutation(plan: dict[str, Any], name: str, scenario_dir: Path) -> dict[str, str]:
    """Produce the real mutation artifact for a negative scenario and return the
    env the scenario runner consumes (SUDERRA_MUTATION_ARTIFACT/_ROLE/
    _BEFORE_SHA256). Returns {} for the positive scenario or when the plan
    carries no mutation_inputs — a negative scenario without a mutation is left
    to fail as operator-error in the runner, never silently passed."""
    mutations = load_mutations()
    if name in mutations.NO_MUTATION:
        return {}
    inputs_map = plan.get("mutation_inputs")
    if not isinstance(inputs_map, dict):
        return {}
    raw = inputs_map.get(name)
    if not isinstance(raw, dict):
        return {}
    result = mutations.produce(
        name,
        work_dir=scenario_dir / "mutation",
        inputs=_resolve_mutation_inputs(raw),
    )
    if result is None:
        return {}
    return {
        "SUDERRA_MUTATION_ARTIFACT": str(result["artifact"]),
        "SUDERRA_MUTATION_ROLE": str(result["role"]),
        "SUDERRA_MUTATION_BEFORE_SHA256": str(result["before_sha256"]),
    }


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


def qemu_version_from_result(result: dict[str, Any]) -> str:
    value = result.get("qemu_version")
    if isinstance(value, str) and value.strip():
        return value
    return "not_collected"


def list_from_result(result: dict[str, Any], field: str) -> list[str]:
    value = result.get(field)
    if isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        return value
    return []


def object_from_result(result: dict[str, Any], field: str) -> dict[str, Any]:
    value = result.get(field)
    return value if isinstance(value, dict) else {}


def scenario_logs_by_role(logs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(item["role"]): item
        for item in logs
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    }


def raw_evidence_from_logs(logs: list[dict[str, Any]]) -> dict[str, str]:
    by_role = scenario_logs_by_role(logs)
    return {
        "serial_sha256": str(by_role.get("serial", {}).get("sha256", "")),
        "qmp_events_sha256": str(by_role.get("qmp-events", {}).get("sha256", "")),
    }


def read_scenario_result(path: Path) -> dict[str, Any]:
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def mutation_artifact_from_result(
    measured: dict[str, Any],
    scenario_dir: Path,
    suite_root: Path,
    fallback: dict[str, Any],
) -> dict[str, Any]:
    artifact = object_from_result(measured, "mutation_artifact")
    if not artifact:
        return fallback
    artifact = dict(artifact)
    path = artifact.get("path")
    if isinstance(path, str) and path.strip():
        rel = Path(path)
        if not rel.is_absolute() and ".." not in rel.parts:
            actual = scenario_dir / rel
            if actual.exists():
                artifact["path"] = actual.relative_to(suite_root).as_posix()
    return artifact


def execute_scenario(
    plan: dict[str, Any],
    item: dict[str, Any],
    idx: int,
    work_root: Path,
) -> dict[str, Any]:
    suite_root = work_root.parent
    name = require_string(item, "name", f"scenarios[{idx}]")
    scenario_dir = work_root / name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = scenario_dir / "runner.stdout.log"
    stderr_path = scenario_dir / "runner.stderr.log"
    before_root = scenario_dir / "mutation-before"
    after_root = scenario_dir / "mutation-after"
    before_digest = sha256_tree(before_root)
    swtpm_before_digest = sha256_tree(Path(plan["swtpm_state"]))
    started_at = now_utc()
    command = command_from_spec(item, f"scenarios[{idx}]")
    # Produce the REAL mutation artifact for negative scenarios and export it to
    # the scenario runner, which applies it to the boot disk / attaches it as a
    # guest payload. signed-boot produces nothing.
    mutation_env = produce_scenario_mutation(plan, name, scenario_dir)
    env = {
        **{key: str(value) for key, value in plan.get("environment", {}).items() if isinstance(key, str)},
        "SUDERRA_PRODUCTION_SCENARIO": name,
        "SUDERRA_SCENARIO_DIR": str(scenario_dir),
        "SUDERRA_IMAGE": str(plan["image"]),
        "SUDERRA_OVMF_CODE": str(plan["ovmf_code"]),
        "SUDERRA_OVMF_VARS": str(plan["ovmf_vars"]),
        "SUDERRA_SWTPM_STATE": str(plan["swtpm_state"]),
        "SUDERRA_EXPECTED_OUTCOME": str(item.get("expected_outcome", "")),
        "SUDERRA_SCENARIO_RESULT": str(scenario_dir / SCENARIO_RESULT),
        **mutation_env,
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
    measured = read_scenario_result(scenario_dir / SCENARIO_RESULT)
    measured_status = measured.get("status")
    observed_outcome = measured.get("observed_outcome")
    observation = object_from_result(measured, "observation")
    if not isinstance(observed_outcome, str) or not observed_outcome.strip():
        observed_outcome = "not-collected"
    observation_outcome = observation.get("observed_outcome") if observation else None
    has_typed_observation = isinstance(observation_outcome, str) and observation_outcome == observed_outcome
    status = (
        "passed"
        if result.returncode == expected_exit_code and measured_status == "passed" and has_typed_observation
        else "failed"
    )
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
        "observation": observation,
        "command": " ".join(shlex.quote(part) for part in command),
        "started_at": started_at,
        "completed_at": completed_at,
        "termination_class": "exit-code",
        "failure_class": "none" if status == "passed" else "security_failure",
        "exit_code": result.returncode,
        "expected_exit_code": expected_exit_code,
        "qemu_version": qemu_version_from_result(measured),
        "qemu_argv": list_from_result(measured, "qemu_argv"),
        "termination": {
            **object_from_result(measured, "termination"),
            "class": str(object_from_result(measured, "termination").get("class", "measured")),
            "reason": str(object_from_result(measured, "termination").get("reason", "scenario result")),
        },
        "raw_evidence": object_from_result(measured, "raw_evidence") or raw_evidence_from_logs(log_entries(suite_root, scenario_dir)),
        "guest_facts": object_from_result(measured, "guest_facts"),
        "swtpm_state": {
            "path": str(plan["swtpm_state"]),
            "before_sha256": str(measured.get("swtpm_state_before_sha256", swtpm_before_digest)),
            "after_sha256": str(measured.get("swtpm_state_after_sha256", sha256_tree(plan["swtpm_state"]))),
        },
        "mutation": {
            "type": mutation_type,
            "target": mutation_target,
            "before_sha256": before_digest,
            "after_sha256": after_digest,
            "artifact": mutation_artifact_from_result(measured, scenario_dir, suite_root, {
                "role": mutation_type,
                "path": str(Path("production-runtime-logs") / name / SCENARIO_RESULT),
                "before_sha256": before_digest,
                "after_sha256": after_digest,
            }),
        },
        "logs": log_entries(suite_root, scenario_dir),
    }


def create_command(args: argparse.Namespace) -> int:
    plan = read_json(args.plan)
    if not isinstance(plan, dict):
        raise ValueError("scenario plan must be a JSON object")
    for field in (
        "version",
        "target",
        "source_sha",
        "source_run_id",
        "source_run_attempt",
        "subject_id",
        "defconfig",
        "image",
        "raw_image_sha256",
        "compressed_artifact_sha256",
        "release_artifact",
        "ovmf_code",
        "ovmf_vars",
        "swtpm_state",
    ):
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
    swtpm_state_before_sha256 = sha256_tree(swtpm_state)
    scenarios = [
        execute_scenario(plan, item, idx, work_root)
        for idx, item in enumerate(scenarios_spec)
        if isinstance(item, dict)
    ]
    first_qemu_argv = next(
        (scenario.get("qemu_argv") for scenario in scenarios if isinstance(scenario.get("qemu_argv"), list) and scenario["qemu_argv"]),
        [],
    )
    first_qemu_version = next(
        (
            str(scenario.get("qemu_version"))
            for scenario in scenarios
            if isinstance(scenario.get("qemu_version"), str) and scenario.get("qemu_version") != "not_collected"
        ),
        "not_collected",
    )
    suite = {
        "schema_version": load_validator().SCHEMA_VERSION,
        "version": plan["version"],
        "target": plan["target"],
        "source_sha": plan["source_sha"],
        "source_run_id": plan["source_run_id"],
        "source_run_attempt": plan["source_run_attempt"],
        "subject_id": plan["subject_id"],
        "defconfig": plan["defconfig"],
        "raw_image_sha256": plan["raw_image_sha256"],
        "compressed_artifact_sha256": plan["compressed_artifact_sha256"],
        "release_artifact": plan["release_artifact"],
        "generated_at": now_utc(),
        "image": str(image),
        "image_sha256": sha256_file(image),
        "ovmf_code": str(ovmf_code),
        "ovmf_code_sha256": sha256_file(ovmf_code),
        "ovmf_vars": str(ovmf_vars),
        "ovmf_vars_sha256": sha256_file(ovmf_vars),
        "ovmf_enrollment": {
            # Enrollment kanıtı plandan GELMELİ — enroll edilmemiş OVMF_VARS'ın
            # hash'ini "enrolled" gibi göstermek (eski fallback) Secure Boot
            # ölçümünü sahteler. Alan yoksa fail-closed.
            "mode": require_string(plan, "ovmf_enrollment_mode", "plan"),
            "enrolled_vars_sha256": require_string(plan, "ovmf_enrolled_vars_sha256", "plan"),
            "secure_boot_db_sha256": require_string(plan, "secure_boot_db_sha256", "plan"),
        },
        "qemu_version": first_qemu_version,
        "qemu_argv": first_qemu_argv,
        "swtpm_state": str(swtpm_state),
        "swtpm_state_sha256": sha256_tree(swtpm_state),
        "swtpm_state_before_sha256": swtpm_state_before_sha256,
        "swtpm_state_after_sha256": sha256_tree(swtpm_state),
        "scenarios": scenarios,
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
        profile="production-runtime",
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
