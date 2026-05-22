#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate the release-bound Image Build contract."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "suderra.image-build-contract.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_matrix_module() -> Any:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(path: Path, rel: Path, role: str, **extra: Any) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise FileNotFoundError(path)
    return {
        "role": role,
        "path": rel.as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        **extra,
    }


def existing_artifact_path(base: Path, logical_artifact: str) -> Path:
    candidates = [base / logical_artifact, base / Path(logical_artifact).name]
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])


def create(args: argparse.Namespace) -> None:
    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        raise SystemExit("--source-sha must be a lowercase git SHA")
    matrix_module = load_matrix_module()
    matrix = matrix_module.load_matrix(args.matrix)
    artifact_root = args.artifact_root
    files: list[dict[str, Any]] = []
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        defconfig = str(row["name"])
        target = str(row["target"])
        image_dir = artifact_root / f"{defconfig}-image"
        for artifact in matrix_module.expected_artifacts(row):
            path = image_dir / artifact
            if path.is_file():
                files.append(
                    record(
                        path,
                        path.relative_to(artifact_root),
                        "image-artifact",
                        defconfig=defconfig,
                        target=target,
                        artifact=artifact,
                        release_artifact=str(row["release_artifact"]),
                    )
                )
        logs_dir = artifact_root / f"{defconfig}-build-logs"
        evidence_roles = (
            ("build-log", f"build-logs/{defconfig}.log"),
            ("warning-classifier-evidence", f"build-logs/{defconfig}.warnings.json"),
            ("buildroot-source-identity", f"build-logs/{defconfig}.source-identity.json"),
            ("build-time-log", f"build-logs/{defconfig}.build-time.log"),
            ("build-performance", f"build-logs/{defconfig}.build-performance.json"),
            ("payload-inputs", f"build-logs/{defconfig}.payload-inputs.json"),
            ("payload-package", f"build-logs/{defconfig}.payload-package.json"),
            ("usb-installer-base", f"build-logs/{defconfig}.usb-installer-base.json"),
        )
        for role, artifact in evidence_roles:
            path = existing_artifact_path(logs_dir, artifact)
            if path.is_file():
                files.append(
                    record(
                        path,
                        path.relative_to(artifact_root),
                        role,
                        defconfig=defconfig,
                        target=target,
                        artifact=artifact,
                    )
                )
    for arch in ("x86_64", "aarch64"):
        installer_dir = artifact_root / f"installer-{arch}"
        for artifact, role in ((f"suderra-installer-{arch}", "installer"), (f"suderra-installer-{arch}.sha256", "checksum")):
            path = installer_dir / artifact
            if path.is_file():
                files.append(record(path, path.relative_to(artifact_root), role, arch=arch, artifact=artifact))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "workflow": {
            "name": args.workflow_name,
            "path": args.workflow_path,
            "ref": args.workflow_ref,
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
        },
        "source_sha": args.source_sha,
        "matrix_path": args.matrix.as_posix(),
        "matrix_sha256": sha256_file(args.matrix),
        "artifact_root": str(artifact_root),
        "files": sorted(files, key=lambda item: (item.get("defconfig", ""), item.get("path", ""))),
        "generated_at": utc_now(),
    }
    payload["contract_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def expected_contract_keys(matrix_path: Path) -> set[tuple[str, str, str]]:
    matrix_module = load_matrix_module()
    matrix = matrix_module.load_matrix(matrix_path)
    expected: set[tuple[str, str, str]] = set()
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        defconfig = str(row["name"])
        target = str(row["target"])
        for artifact in matrix_module.expected_artifacts(row):
            expected.add((defconfig, target, artifact))
        evidence = [
            f"build-logs/{defconfig}.log",
            f"build-logs/{defconfig}.warnings.json",
            f"build-logs/{defconfig}.source-identity.json",
            f"build-logs/{defconfig}.build-time.log",
            f"build-logs/{defconfig}.build-performance.json",
        ]
        if row.get("prebuild_defconfigs"):
            evidence.extend(
                [
                    f"build-logs/{defconfig}.payload-inputs.json",
                    f"build-logs/{defconfig}.payload-package.json",
                    f"build-logs/{defconfig}.usb-installer-base.json",
                ]
            )
        for artifact in evidence:
            expected.add((defconfig, target, artifact))
    for arch in ("x86_64", "aarch64"):
        expected.add((f"installer-{arch}", arch, f"suderra-installer-{arch}"))
        expected.add((f"installer-{arch}", arch, f"suderra-installer-{arch}.sha256"))
    return expected


def validate(args: argparse.Namespace) -> None:
    try:
        payload = json.loads(args.contract.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid image build contract JSON: {exc}") from exc
    failures: list[str] = []
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    workflow = payload.get("workflow")
    if not isinstance(workflow, dict):
        failures.append("workflow must be an object")
    else:
        if args.workflow_path and workflow.get("path") != args.workflow_path:
            failures.append("workflow.path mismatch")
        if args.source_run_id and str(workflow.get("run_id")) != str(args.source_run_id):
            failures.append("workflow.run_id mismatch")
        if args.source_run_attempt and str(workflow.get("run_attempt")) != str(args.source_run_attempt):
            failures.append("workflow.run_attempt mismatch")
    if args.source_sha and payload.get("source_sha") != args.source_sha:
        failures.append("source_sha mismatch")
    files = payload.get("files")
    seen_paths: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    if not isinstance(files, list) or not files:
        failures.append("files must be a non-empty list")
    else:
        artifact_root = args.artifact_root
        for item in files:
            if not isinstance(item, dict):
                failures.append("file entries must be objects")
                continue
            digest = item.get("sha256")
            rel = item.get("path")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                failures.append(f"invalid file sha256 for {rel}")
            if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts:
                failures.append(f"invalid file path: {rel}")
                continue
            seen_paths.add(rel)
            defconfig_or_arch = item.get("defconfig") or f"installer-{item.get('arch')}"
            target_or_arch = item.get("target") or item.get("arch")
            artifact = item.get("artifact")
            if isinstance(defconfig_or_arch, str) and isinstance(target_or_arch, str) and isinstance(artifact, str):
                seen_keys.add((defconfig_or_arch, target_or_arch, artifact))
            if artifact_root is not None:
                path = artifact_root / rel
                if not path.is_file():
                    failures.append(f"contract file missing: {path}")
                elif isinstance(digest, str) and sha256_file(path) != digest:
                    failures.append(f"contract file sha mismatch: {path}")
    try:
        required_keys = expected_contract_keys(args.matrix)
    except Exception as exc:
        failures.append(f"cannot load expected image build contract paths: {exc}")
        required_keys = set()
    missing = sorted(required_keys - seen_keys)
    if missing:
        failures.append(
            "contract missing required files: "
            + ", ".join(f"{defconfig}:{target}:{artifact}" for defconfig, target, artifact in missing)
        )
    if failures:
        raise SystemExit("\n".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--source-sha", required=True)
    create_parser.add_argument("--workflow-name", default="Image Build")
    create_parser.add_argument("--workflow-path", default=".github/workflows/image-build.yml")
    create_parser.add_argument("--workflow-ref", required=True)
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument("--run-attempt", required=True)
    create_parser.add_argument("--matrix", type=Path, default=Path("ci/build-matrix.yml"))
    create_parser.add_argument("--artifact-root", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.set_defaults(func=create)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("contract", type=Path)
    validate_parser.add_argument("--artifact-root", type=Path)
    validate_parser.add_argument("--workflow-path")
    validate_parser.add_argument("--source-sha")
    validate_parser.add_argument("--source-run-id")
    validate_parser.add_argument("--source-run-attempt")
    validate_parser.add_argument("--matrix", type=Path, default=Path("ci/build-matrix.yml"))
    validate_parser.set_defaults(func=validate)
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
