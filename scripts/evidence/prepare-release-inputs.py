#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Prepare and bind release-candidate input evidence.

The output manifest is intentionally stricter than the final release evidence:
it binds pre-tag/pre-publish evidence to one successful Build run and one exact
source commit before any tag workflow is allowed to publish.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.release-input-binding.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def load_matrix(path: Path) -> tuple[dict[str, Any], Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_matrix(path), module


def release_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix.get("defconfigs", []) if row.get("release")]


def artifact_entries(
    matrix: dict[str, Any],
    matrix_module: Any,
    artifact_root: Path | None,
    require_artifacts: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    for row in release_rows(matrix):
        defconfig = str(row["name"])
        target = str(row["target"])
        artifact_dir = artifact_root / f"{defconfig}-image" if artifact_root is not None else None
        for artifact in matrix_module.expected_artifacts(row):
            path = artifact_dir / artifact if artifact_dir is not None else None
            if path is None or not path.is_file():
                if require_artifacts:
                    errors.append(f"missing Build artifact for {defconfig}: {artifact}")
                continue
            entries.append(
                {
                    "defconfig": defconfig,
                    "target": target,
                    "artifact": artifact,
                    "path": path.relative_to(artifact_root).as_posix() if artifact_root else str(path),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return entries, errors


def binding_payload(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not SEMVER_RE.fullmatch(args.version):
        errors.append(f"version is not SemVer tag format: {args.version}")
    if args.profile == "release-candidate" and "-" not in args.version:
        errors.append("release-candidate profile requires a prerelease SemVer tag")
    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        errors.append("source_sha must be a lowercase git commit sha")
    matrix_path = args.matrix if args.matrix.is_absolute() else ROOT / args.matrix
    matrix, matrix_module = load_matrix(matrix_path)
    artifact_root = args.artifact_root.resolve() if args.artifact_root is not None else None
    artifacts, artifact_errors = artifact_entries(
        matrix,
        matrix_module,
        artifact_root,
        args.require_artifacts,
    )
    errors.extend(artifact_errors)
    try:
        buildroot_index_sha = run_git(["ls-tree", args.source_sha, "buildroot"]).split()[2]
    except Exception as exc:
        errors.append(f"cannot resolve buildroot index sha for {args.source_sha}: {exc}")
        buildroot_index_sha = ""
    matrix_sha256 = read_text_sha256(matrix_path)
    try:
        matrix_display = str(matrix_path.relative_to(ROOT))
    except ValueError:
        matrix_display = str(matrix_path)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "profile": args.profile,
        "version": args.version,
        "source_sha": args.source_sha,
        "source_run_id": str(args.source_run_id),
        "source_run_attempt": str(args.source_run_attempt),
        "build_workflow_name": args.build_workflow_name,
        "matrix_path": matrix_display,
        "matrix_sha256": matrix_sha256,
        "buildroot_index_sha": buildroot_index_sha,
        "artifact_root": str(artifact_root) if artifact_root else None,
        "artifacts": sorted(artifacts, key=lambda item: (item["defconfig"], item["artifact"])),
        "release_targets": [
            {
                "defconfig": str(row["name"]),
                "target": str(row["target"]),
                "release_artifact": str(row["release_artifact"]),
                "production_required": bool(row.get("production_required")),
                "production_ready": bool(row.get("production_ready")),
                "blocker": str(row.get("blocker", "")),
            }
            for row in release_rows(matrix)
        ],
        "generated_at": now_utc(),
    }
    return payload, errors


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def plan_command(args: argparse.Namespace) -> int:
    payload, errors = binding_payload(args)
    write_json(args.output, payload)
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"wrote release input binding: {args.output}")
    return 0


def skeleton_qemu(version: str, target: str, source_sha: str) -> dict[str, Any]:
    return {
        "schema_version": "suderra.qemu-acceptance.v3",
        "version": version,
        "target": target,
        "source_sha": source_sha,
        "generated_at": now_utc(),
        "image": "TO_BE_COLLECTED",
        "image_sha256": "0" * 64,
        "qemu_version": "TO_BE_COLLECTED",
        "firmware": "TO_BE_COLLECTED",
        "firmware_sha256": "0" * 64,
        "status": "failed",
        "logs": [],
        "checks": {},
        "guest_facts": {},
    }


def skeleton_lab(version: str, target: str, source_sha: str) -> dict[str, Any]:
    return {
        "schema_version": "suderra.lab-evidence.v3",
        "version": version,
        "target": target,
        "generated_at": now_utc(),
        "lab_id": "TO_BE_COLLECTED",
        "operator": "TO_BE_COLLECTED",
        "station": {
            "station_id": "TO_BE_COLLECTED",
            "fixture_id": "TO_BE_COLLECTED",
            "operator_id": "TO_BE_COLLECTED",
            "trusted_key_fingerprint": "TO_BE_COLLECTED",
            "clock": "TO_BE_COLLECTED",
            "tool_versions": {},
        },
        "artifact_binding": {
            "version": version,
            "source_sha": source_sha,
            "source_run_id": "TO_BE_COLLECTED",
            "release_assets_sha256": "0" * 64,
        },
        "devices": [],
        "negative_tests": [],
    }


def init_command(args: argparse.Namespace) -> int:
    matrix_path = args.matrix if args.matrix.is_absolute() else ROOT / args.matrix
    matrix, _matrix_module = load_matrix(matrix_path)
    binding_output = args.output_root / "release-inputs" / args.version / "release-candidate.json"
    plan_args = argparse.Namespace(**vars(args))
    plan_args.output = binding_output
    plan_args.require_artifacts = args.artifact_root is not None
    payload, errors = binding_payload(plan_args)
    write_json(binding_output, payload)

    for row in release_rows(matrix):
        target = str(row["target"])
        if row.get("qemu_test"):
            write_json(
                args.output_root / "release-lab-input" / args.version / target / "qemu.json",
                skeleton_qemu(args.version, target, args.source_sha),
            )
        if row.get("production_required") or "hardware" in str(row.get("acceptance", "")):
            write_json(
                args.output_root / "release-lab-input" / args.version / target / "lab.json",
                skeleton_lab(args.version, target, args.source_sha),
            )
        write_json(
            args.output_root / "release-approvals" / args.version / f"{target}.json",
            {
                "schema_version": "suderra.release-approval.v1",
                "version": args.version,
                "target": target,
                "source_sha": args.source_sha,
                "status": "pending",
                "approver": "TO_BE_COLLECTED",
                "approved_at": "TO_BE_COLLECTED",
                "decision": "TO_BE_COLLECTED",
            },
        )
        repro = args.output_root / "release-reproducibility" / args.version / f"{target}.log"
        repro.parent.mkdir(parents=True, exist_ok=True)
        repro.write_text("TO_BE_COLLECTED: reproducibility comparison has not run\n", encoding="utf-8")

    for scan in matrix.get("security_scans", []):
        write_json(
            args.output_root / "release-security" / args.version / f"{scan}.json",
            {
                "schema_version": "suderra.release-security-report.v1",
                "version": args.version,
                "source_sha": args.source_sha,
                "source_run_id": str(args.source_run_id),
                "scan": scan,
                "status": "not_run",
                "generated_at": "TO_BE_COLLECTED",
                "tool": "TO_BE_COLLECTED",
                "tool_version": "TO_BE_COLLECTED",
                "evidence_type": "TO_BE_COLLECTED",
                "evidence_sha256": "0" * 64,
            },
        )
    if errors:
        for item in errors:
            print(f"WARNING: {item}", file=sys.stderr)
    print(f"initialized release input skeletons under {args.output_root}")
    return 0


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-run-attempt", default="1")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--build-workflow-name", default="Build")
    parser.add_argument("--profile", choices=("technical-dry-run", "release-candidate"), default="release-candidate")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--artifact-root", type=Path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    add_common(plan)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--require-artifacts", action="store_true")
    plan.set_defaults(func=plan_command)

    init = subparsers.add_parser("init")
    add_common(init)
    init.add_argument("--output-root", type=Path, required=True)
    init.set_defaults(func=init_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
