#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate staged release bytes against the preflight Image Build artifact binding."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
BINDING_SCHEMA_VERSION = "suderra.release-input-binding.v2"
IMAGE_BUILD_WORKFLOW_NAME = "Image Build"
IMAGE_BUILD_WORKFLOW_PATH = ".github/workflows/image-build.yml"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_matrix_module() -> Any:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def binding_index(binding: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    artifacts = binding.get("artifacts")
    if not isinstance(artifacts, list):
        return {}
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        defconfig = item.get("defconfig")
        artifact = item.get("artifact")
        if isinstance(defconfig, str) and isinstance(artifact, str):
            index[(defconfig, artifact)] = item
    return index


def installer_index(binding: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    installers = binding.get("installers")
    if not isinstance(installers, list):
        return {}
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in installers:
        if not isinstance(item, dict):
            continue
        arch = item.get("arch")
        artifact = item.get("artifact")
        if isinstance(arch, str) and isinstance(artifact, str):
            index[(arch, artifact)] = item
    return index


def staged_name_for_artifact(row: dict[str, Any], artifact: str, matrix_module: Any) -> str | None:
    release_artifact = str(row["release_artifact"])
    source_artifact = str(row["artifact"])
    if artifact == f"{source_artifact}.xz":
        return release_artifact
    if artifact == "MANIFEST.txt":
        return f"{matrix_module.release_rename_base(release_artifact)}.manifest.txt"
    if artifact == "manifest.json":
        return f"{matrix_module.payload_manifest_base(release_artifact)}.payload-manifest.json"
    if artifact == "manifest.sig":
        return f"{matrix_module.payload_manifest_base(release_artifact)}.payload-manifest.sig"
    return None


def validate(binding_path: Path, release_dir: Path, matrix_path: Path) -> list[str]:
    failures: list[str] = []
    binding = read_json(binding_path)
    if not isinstance(binding, dict):
        return [f"binding manifest must be a JSON object: {binding_path}"]
    if binding.get("schema_version") != BINDING_SCHEMA_VERSION:
        failures.append(f"binding schema_version must be {BINDING_SCHEMA_VERSION}")
    if binding.get("build_workflow_name") != IMAGE_BUILD_WORKFLOW_NAME:
        failures.append(f"binding build_workflow_name must be {IMAGE_BUILD_WORKFLOW_NAME}")
    if binding.get("build_workflow_path") != IMAGE_BUILD_WORKFLOW_PATH:
        failures.append(f"binding build_workflow_path must be {IMAGE_BUILD_WORKFLOW_PATH}")
    image_contract = binding.get("image_build_contract")
    if not isinstance(image_contract, dict):
        failures.append("binding image_build_contract must be an object")
    else:
        digest = image_contract.get("sha256")
        rel = image_contract.get("path")
        if image_contract.get("role") != "image-build-contract":
            failures.append("binding image_build_contract role must be image-build-contract")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
            failures.append("binding image_build_contract must have a non-zero sha256")
        if not isinstance(image_contract.get("bytes"), int) or image_contract.get("bytes", 0) <= 0:
            failures.append("binding image_build_contract must have positive byte size")
        if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts:
            failures.append("binding image_build_contract path must be relative")
    artifacts = binding_index(binding)
    installers = installer_index(binding)
    matrix_module = load_matrix_module()
    matrix = matrix_module.load_matrix(matrix_path)
    tracked_names: set[str] = set()
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        defconfig = str(row["name"])
        for artifact in matrix_module.expected_artifacts(row):
            staged_name = staged_name_for_artifact(row, artifact, matrix_module)
            if staged_name is None:
                continue
            tracked_names.add(staged_name)
            bound = artifacts.get((defconfig, artifact))
            if bound is None:
                failures.append(f"binding missing staged source artifact: {defconfig}:{artifact}")
                continue
            expected_sha = bound.get("sha256")
            if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha) or expected_sha == "0" * 64:
                failures.append(f"binding artifact has invalid sha256: {defconfig}:{artifact}")
                continue
            staged = release_dir / staged_name
            if not staged.is_file() or staged.stat().st_size <= 0:
                failures.append(f"staged release file missing or empty: {staged_name}")
                continue
            actual_sha = sha256_file(staged)
            if actual_sha != expected_sha:
                failures.append(
                    f"staged release file sha mismatch for {staged_name}: "
                    f"expected bound {expected_sha}, got {actual_sha}"
                )
    for staged in release_dir.iterdir() if release_dir.is_dir() else []:
        if not staged.is_file():
            continue
        name = staged.name
        if name.endswith((".img.xz", ".manifest.txt", ".payload-manifest.json", ".payload-manifest.sig")):
            if name.startswith("suderra-") and name not in tracked_names:
                failures.append(f"unexpected staged release image contract file: {name}")
    version = binding.get("version")
    if isinstance(version, str):
        for arch in ("x86_64", "aarch64"):
            source_name = f"suderra-installer-{arch}"
            release_name = f"suderra-installer-{version}-{arch}"
            bound = installers.get((arch, source_name))
            if bound is None:
                failures.append(f"binding missing installer artifact: {arch}:{source_name}")
                continue
            expected_sha = bound.get("sha256")
            if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha) or expected_sha == "0" * 64:
                failures.append(f"binding installer has invalid sha256: {arch}:{source_name}")
                continue
            staged = release_dir / release_name
            if not staged.is_file() or staged.stat().st_size <= 0:
                failures.append(f"staged installer file missing or empty: {release_name}")
                continue
            actual_sha = sha256_file(staged)
            if actual_sha != expected_sha:
                failures.append(
                    f"staged installer sha mismatch for {release_name}: "
                    f"expected bound {expected_sha}, got {actual_sha}"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding-manifest", type=Path, required=True)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    args = parser.parse_args()
    failures = validate(args.binding_manifest, args.release_dir, args.matrix)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated staged release artifact binding: {args.release_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
