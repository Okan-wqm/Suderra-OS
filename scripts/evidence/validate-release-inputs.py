#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Pre-tag/pre-publish release input readiness gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_approval import validate_approval_payload  # noqa: E402

DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
BINDING_SCHEMA_VERSION = "suderra.release-input-binding.v2"
BUILDROOT_IDENTITY_SCHEMA_FIELD = "buildroot_source_identity_schema_version"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_VALUES = {"TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING"}
MAX_RAW_SECURITY_EVIDENCE_BYTES = 10 * 1024 * 1024


def run(args: list[str]) -> list[str]:
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode == 0:
        return []
    return [line for line in result.stderr.splitlines() if line.strip()] or [result.stdout.strip()]


def read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_matrix_module() -> Any:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_matrix(path: Path) -> dict[str, Any]:
    return load_matrix_module().load_matrix(path)


def load_matrix_with_module(path: Path) -> tuple[dict[str, Any], Any]:
    module = load_matrix_module()
    return module.load_matrix(path), module


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.strip() in PLACEHOLDER_VALUES


def git_output(args: list[str]) -> str:
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


def load_binding(path: Path | None, failures: list[str]) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = read_json(path)
    if not isinstance(payload, dict):
        failures.append(f"binding manifest missing or invalid JSON: {path}")
        return None
    if payload.get("schema_version") != BINDING_SCHEMA_VERSION:
        failures.append(f"binding manifest schema_version must be {BINDING_SCHEMA_VERSION}: {path}")
    return payload


def load_buildroot_identity_module() -> Any:
    script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
    spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def buildroot_identity_payload_from_binding(binding: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if BUILDROOT_IDENTITY_SCHEMA_FIELD in binding:
        payload["schema_version"] = binding.get(BUILDROOT_IDENTITY_SCHEMA_FIELD)
    for field in (
        "buildroot_index_sha",
        "buildroot_upstream_ref",
        "buildroot_source_mode",
        "buildroot_patchset_sha256",
        "buildroot_patch_files",
        "buildroot_effective_source_id",
        "buildroot_expected_patched",
        "buildroot_rust_version",
        "buildroot_rust_bin_version",
        "buildroot_expected_diff_sha256",
        "buildroot_staged_diff_sha256",
        "buildroot_applied_diff_sha256",
        "buildroot_worktree_diff_sha256",
        "suderra_source_sha",
        "suderra_external_tree_sha256",
        "suderra_external_dirty_paths",
        "suderra_release_source_id",
    ):
        if field in binding:
            payload[field] = binding.get(field)
    return payload


def compare_buildroot_identity_to_binding(
    failures: list[str],
    payload: dict[str, Any],
    binding: dict[str, Any],
    prefix: str,
) -> None:
    field_pairs = [
        ("schema_version", BUILDROOT_IDENTITY_SCHEMA_FIELD),
        ("buildroot_index_sha", "buildroot_index_sha"),
        ("buildroot_upstream_ref", "buildroot_upstream_ref"),
        ("buildroot_source_mode", "buildroot_source_mode"),
        ("buildroot_patchset_sha256", "buildroot_patchset_sha256"),
        ("buildroot_patch_files", "buildroot_patch_files"),
        ("buildroot_effective_source_id", "buildroot_effective_source_id"),
        ("buildroot_expected_patched", "buildroot_expected_patched"),
        ("buildroot_rust_version", "buildroot_rust_version"),
        ("buildroot_rust_bin_version", "buildroot_rust_bin_version"),
        ("buildroot_expected_diff_sha256", "buildroot_expected_diff_sha256"),
        ("buildroot_staged_diff_sha256", "buildroot_staged_diff_sha256"),
        ("buildroot_applied_diff_sha256", "buildroot_applied_diff_sha256"),
        ("buildroot_worktree_diff_sha256", "buildroot_worktree_diff_sha256"),
        ("suderra_source_sha", "suderra_source_sha"),
        ("suderra_external_tree_sha256", "suderra_external_tree_sha256"),
        ("suderra_external_dirty_paths", "suderra_external_dirty_paths"),
        ("suderra_release_source_id", "suderra_release_source_id"),
    ]
    for identity_field, binding_field in field_pairs:
        if payload.get(identity_field) != binding.get(binding_field):
            failures.append(f"{prefix}: {identity_field} must match release input binding")


def validate_binding(
    binding: dict[str, Any] | None,
    args: argparse.Namespace,
    matrix_path: Path,
) -> list[str]:
    if binding is None:
        if args.profile in {"release-candidate", "production-candidate"}:
            return [f"{args.profile} profile requires --binding-manifest"]
        return []
    failures: list[str] = []
    if binding.get("version") != args.version:
        failures.append("binding version must match requested version")
    if binding.get("profile") != args.profile:
        failures.append("binding profile must match requested profile")
    if args.source_sha is not None and binding.get("source_sha") != args.source_sha:
        failures.append("binding source_sha must match --source-sha")
    if args.source_run_id is not None and str(binding.get("source_run_id")) != str(args.source_run_id):
        failures.append("binding source_run_id must match --source-run-id")
    source_run_attempt = binding.get("source_run_attempt")
    try:
        valid_attempt = int(str(source_run_attempt))
    except (TypeError, ValueError):
        valid_attempt = 0
    if valid_attempt <= 0:
        failures.append("binding source_run_attempt must be a positive run attempt")
    if args.source_run_attempt is not None and str(source_run_attempt) != str(args.source_run_attempt):
        failures.append("binding source_run_attempt must match --source-run-attempt")
    if binding.get("build_workflow_name") != args.build_workflow_name:
        failures.append(f"binding build_workflow_name must be {args.build_workflow_name}")
    if binding.get("build_workflow_path") != args.build_workflow_path:
        failures.append(f"binding build_workflow_path must be {args.build_workflow_path}")
    source_sha = binding.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("binding source_sha must be a lowercase git commit sha")
    matrix_sha256 = binding.get("matrix_sha256")
    if not isinstance(matrix_sha256, str) or not SHA256_RE.fullmatch(matrix_sha256):
        failures.append("binding matrix_sha256 must be a lowercase sha256")
    elif matrix_path.is_file() and sha256_file(matrix_path) != matrix_sha256:
        failures.append("binding matrix_sha256 does not match current ci/build-matrix.yml")
    buildroot_index_sha = binding.get("buildroot_index_sha")
    if isinstance(source_sha, str) and SOURCE_SHA_RE.fullmatch(source_sha):
        try:
            expected_buildroot = git_output(["ls-tree", source_sha, "buildroot"]).split()[2]
        except Exception as exc:
            failures.append(f"cannot resolve Buildroot submodule for binding source_sha: {exc}")
            expected_buildroot = None
        if expected_buildroot is not None and buildroot_index_sha != expected_buildroot:
            failures.append("binding buildroot_index_sha does not match source_sha tree")
    try:
        buildroot_module = load_buildroot_identity_module()
        identity_payload = buildroot_identity_payload_from_binding(binding)
        for failure in buildroot_module.validate_metadata_payload(identity_payload):
            failures.append(f"binding Buildroot source identity: {failure}")
    except Exception as exc:
        failures.append(f"cannot validate binding Buildroot source identity: {exc}")
    for field in ("userspace_cargo_lock_sha256", "userspace_rust_toolchain_sha256"):
        value = binding.get(field)
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
            failures.append(f"binding {field} must be a non-zero sha256")
    try:
        matrix, matrix_module = load_matrix_with_module(matrix_path)
        expected_rows = [row for row in matrix.get("defconfigs", []) if row.get("release")]
        expected_artifacts: dict[tuple[str, str], dict[str, Any]] = {
            (str(row["name"]), artifact): row
            for row in expected_rows
            for artifact in matrix_module.expected_artifacts(row)
        }
    except Exception as exc:
        failures.append(f"cannot load expected release artifact contract: {exc}")
        expected_artifacts = {}

    artifacts = binding.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        failures.append("binding artifacts must be a non-empty list")
    else:
        seen: set[tuple[str, str]] = set()
        artifact_root = args.artifact_root
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                failures.append(f"binding artifacts[{index}] must be an object")
                continue
            key = (str(artifact.get("defconfig")), str(artifact.get("artifact")))
            expected_row = expected_artifacts.get(key)
            if expected_artifacts and expected_row is None:
                failures.append(f"unexpected binding artifact: {key[0]} {key[1]}")
            elif expected_row is not None and artifact.get("target") != expected_row.get("target"):
                failures.append(f"binding artifact {key[0]} {key[1]} target must be {expected_row.get('target')}")
            if key in seen:
                failures.append(f"duplicate binding artifact: {key[0]} {key[1]}")
            seen.add(key)
            digest = artifact.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                failures.append(f"binding artifact {key[0]} {key[1]} has invalid sha256")
            elif digest == "0" * 64:
                failures.append(f"binding artifact {key[0]} {key[1]} must not use all-zero sha256")
            if not isinstance(artifact.get("bytes"), int) or artifact.get("bytes", 0) <= 0:
                failures.append(f"binding artifact {key[0]} {key[1]} must have positive byte size")
            rel = artifact.get("path")
            if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts or is_placeholder(rel):
                failures.append(f"binding artifact {key[0]} {key[1]} path must be a relative non-placeholder path")
            if artifact_root is not None and isinstance(rel, str):
                path = artifact_root / rel
                if not path.is_file():
                    failures.append(f"binding artifact file missing: {path}")
                elif isinstance(digest, str) and sha256_file(path) != digest:
                    failures.append(f"binding artifact sha mismatch: {path}")
        if expected_artifacts:
            missing = sorted(set(expected_artifacts) - seen)
            if missing:
                failures.append(
                    "binding artifacts missing matrix-required files: "
                    + ", ".join(f"{defconfig}:{artifact}" for defconfig, artifact in missing)
                )
    expected_build_evidence: set[tuple[str, str]] = set()
    if "expected_rows" in locals():
        for row in expected_rows:
            defconfig = str(row["name"])
            expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.log"))
            expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.warnings.json"))
            expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.source-identity.json"))
            expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.build-time.log"))
            expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.build-performance.json"))
            if row.get("prebuild_defconfigs"):
                expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.payload-inputs.json"))
                expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.payload-package.json"))
                expected_build_evidence.add((defconfig, f"build-logs/{defconfig}.usb-installer-base.json"))
    build_evidence = binding.get("build_evidence")
    if not isinstance(build_evidence, list) or not build_evidence:
        failures.append("binding build_evidence must be a non-empty list")
    else:
        seen_evidence: set[tuple[str, str]] = set()
        artifact_root = args.artifact_root
        for index, evidence in enumerate(build_evidence):
            if not isinstance(evidence, dict):
                failures.append(f"binding build_evidence[{index}] must be an object")
                continue
            key = (str(evidence.get("defconfig")), str(evidence.get("artifact")))
            if expected_build_evidence and key not in expected_build_evidence:
                failures.append(f"unexpected binding build evidence: {key[0]} {key[1]}")
            if key in seen_evidence:
                failures.append(f"duplicate binding build evidence: {key[0]} {key[1]}")
            seen_evidence.add(key)
            role = evidence.get("role")
            if role not in {
                "build-log",
                "warning-classifier-evidence",
                "buildroot-source-identity",
                "build-time-log",
                "build-performance",
                "payload-inputs",
                "payload-package",
                "usb-installer-base",
            }:
                failures.append(f"binding build evidence {key[0]} {key[1]} has invalid role")
            digest = evidence.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                failures.append(f"binding build evidence {key[0]} {key[1]} has invalid sha256")
            elif digest == "0" * 64:
                failures.append(f"binding build evidence {key[0]} {key[1]} must not use all-zero sha256")
            if not isinstance(evidence.get("bytes"), int) or evidence.get("bytes", 0) <= 0:
                failures.append(f"binding build evidence {key[0]} {key[1]} must have positive byte size")
            rel = evidence.get("path")
            if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts or is_placeholder(rel):
                failures.append(f"binding build evidence {key[0]} {key[1]} path must be a relative non-placeholder path")
            if artifact_root is not None and isinstance(rel, str):
                path = artifact_root / rel
                if not path.is_file():
                    failures.append(f"binding build evidence file missing: {path}")
                elif isinstance(digest, str) and sha256_file(path) != digest:
                    failures.append(f"binding build evidence sha mismatch: {path}")
                elif role == "warning-classifier-evidence":
                    payload = read_json(path)
                    if not isinstance(payload, dict):
                        failures.append(f"warning evidence must be JSON: {path}")
                    else:
                        summary = payload.get("summary")
                        if not isinstance(summary, dict):
                            failures.append(f"warning evidence summary must be an object: {path}")
                        else:
                            if summary.get("owned") != 0:
                                failures.append(f"warning evidence owned count must be 0: {path}")
                            if summary.get("third-party") != 0:
                                failures.append(f"warning evidence third-party count must be 0: {path}")
                        for field in ("failing", "policy_errors"):
                            value = payload.get(field)
                            if value != []:
                                failures.append(f"warning evidence {field} must be empty: {path}")
                elif role == "buildroot-source-identity":
                    payload = read_json(path)
                    if not isinstance(payload, dict):
                        failures.append(f"Buildroot source identity must be JSON: {path}")
                    else:
                        try:
                            module = load_buildroot_identity_module()
                            for failure in module.validate_metadata_payload(payload):
                                failures.append(f"{path}: {failure}")
                            compare_buildroot_identity_to_binding(failures, payload, binding, str(path))
                        except Exception as exc:
                            failures.append(f"cannot validate Buildroot source identity {path}: {exc}")
                elif role == "build-performance":
                    payload = read_json(path)
                    if not isinstance(payload, dict) or payload.get("schema_version") != "suderra.buildroot-build-performance.v1":
                        failures.append(f"build performance evidence must be v1 JSON: {path}")
                    else:
                        timing = payload.get("timing")
                        if not isinstance(timing, dict) or timing.get("status") != "collected":
                            failures.append(f"build performance timing must be collected: {path}")
                elif role == "payload-package":
                    payload = read_json(path)
                    if not isinstance(payload, dict) or payload.get("schema_version") != "suderra.usb-installer-payload-package.v1":
                        failures.append(f"payload package evidence must be v1 JSON: {path}")
                    else:
                        for field in ("base_manifest_sha256", "payload_inputs_sha256"):
                            value = payload.get(field)
                            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                                failures.append(f"payload package evidence {field} must be sha256: {path}")
                elif role == "payload-inputs":
                    payload = read_json(path)
                    if not isinstance(payload, dict) or payload.get("schema_version") != "suderra.payload-inputs.v1":
                        failures.append(f"payload inputs evidence must be v1 JSON: {path}")
                elif role == "usb-installer-base":
                    payload = read_json(path)
                    if not isinstance(payload, dict) or payload.get("schema_version") != "suderra.usb-installer-base.v1":
                        failures.append(f"USB installer base evidence must be v1 JSON: {path}")
        if expected_build_evidence:
            missing = sorted(expected_build_evidence - seen_evidence)
            if missing:
                failures.append(
                    "binding build_evidence missing matrix-required files: "
                    + ", ".join(f"{defconfig}:{artifact}" for defconfig, artifact in missing)
                )
    expected_installers = {
        ("x86_64", "suderra-installer-x86_64"),
        ("x86_64", "suderra-installer-x86_64.sha256"),
        ("aarch64", "suderra-installer-aarch64"),
        ("aarch64", "suderra-installer-aarch64.sha256"),
    }
    installers = binding.get("installers")
    if not isinstance(installers, list) or not installers:
        failures.append("binding installers must be a non-empty list")
    else:
        seen_installers: set[tuple[str, str]] = set()
        artifact_root = args.artifact_root
        for index, installer in enumerate(installers):
            if not isinstance(installer, dict):
                failures.append(f"binding installers[{index}] must be an object")
                continue
            key = (str(installer.get("arch")), str(installer.get("artifact")))
            if key not in expected_installers:
                failures.append(f"unexpected binding installer artifact: {key[0]} {key[1]}")
            if key in seen_installers:
                failures.append(f"duplicate binding installer artifact: {key[0]} {key[1]}")
            seen_installers.add(key)
            if installer.get("role") not in {"installer", "checksum"}:
                failures.append(f"binding installer {key[0]} {key[1]} has invalid role")
            digest = installer.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
                failures.append(f"binding installer {key[0]} {key[1]} must have a non-zero sha256")
            if not isinstance(installer.get("bytes"), int) or installer.get("bytes", 0) <= 0:
                failures.append(f"binding installer {key[0]} {key[1]} must have positive byte size")
            rel = installer.get("path")
            if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts or is_placeholder(rel):
                failures.append(f"binding installer {key[0]} {key[1]} path must be a relative non-placeholder path")
            if artifact_root is not None and isinstance(rel, str):
                path = artifact_root / rel
                if not path.is_file():
                    failures.append(f"binding installer file missing: {path}")
                elif isinstance(digest, str) and sha256_file(path) != digest:
                    failures.append(f"binding installer sha mismatch: {path}")
        missing = sorted(expected_installers - seen_installers)
        if missing:
            failures.append(
                "binding installers missing required files: "
                + ", ".join(f"{arch}:{artifact}" for arch, artifact in missing)
            )
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
        if not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts or is_placeholder(rel):
            failures.append("binding image_build_contract path must be relative and non-placeholder")
        if args.artifact_root is not None and isinstance(rel, str):
            contract_path = args.artifact_root / rel
            if not contract_path.is_file():
                failures.append(f"image build contract file missing: {contract_path}")
            elif isinstance(digest, str) and sha256_file(contract_path) != digest:
                failures.append(f"image build contract sha mismatch: {contract_path}")
    return failures


def binding_artifact_sha256(binding: dict[str, Any] | None, target: str, artifact_name: str) -> str | None:
    if not isinstance(binding, dict):
        return None
    artifacts = binding.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    matches = [
        item.get("sha256")
        for item in artifacts
        if isinstance(item, dict)
        and item.get("target") == target
        and item.get("artifact") == artifact_name
        and isinstance(item.get("sha256"), str)
    ]
    return matches[0] if len(matches) == 1 else None


def validate_approval(path: Path, version: str, target: str, source_sha: str | None) -> list[str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"missing or invalid approval input: {path}"]
    return [
        f"{path}: {failure}"
        for failure in validate_approval_payload(payload, version, target, source_sha, require_pass=True)
    ]


def validate_repro(
    path: Path,
    version: str | None = None,
    target: str | None = None,
    source_sha: str | None = None,
    source_run_id: str | None = None,
    check_files: bool = False,
) -> list[str]:
    if not path.is_file() or path.stat().st_size <= 0:
        return [f"missing reproducibility input: {path}"]
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"reproducibility input must be suderra.reproducibility.v1 JSON: {path}"]
    failures = []
    if payload.get("schema_version") != "suderra.reproducibility.v1":
        failures.append(f"reproducibility schema_version mismatch: {path}")
    if version is not None and payload.get("version") != version:
        failures.append(f"reproducibility version mismatch: {path}")
    if target is not None and payload.get("target") != target:
        failures.append(f"reproducibility target mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"reproducibility source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"reproducibility source_run_id mismatch: {path}")
    if payload.get("status") != "passed":
        failures.append(f"reproducibility status must be passed: {path}")
    comparison = payload.get("comparison")
    if not isinstance(comparison, str) or not comparison.strip() or is_placeholder(comparison):
        failures.append(f"reproducibility comparison is required: {path}")
    generated_at = payload.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at.strip() or is_placeholder(generated_at):
        failures.append(f"reproducibility generated_at is required: {path}")
    comparisons = payload.get("artifact_comparisons")
    if not isinstance(comparisons, list) or not comparisons:
        failures.append(f"reproducibility artifact_comparisons must be a non-empty list: {path}")
    else:
        for idx, item in enumerate(comparisons):
            if not isinstance(item, dict):
                failures.append(f"reproducibility artifact_comparisons[{idx}] must be an object: {path}")
                continue
            if item.get("status") != "matched":
                failures.append(f"reproducibility artifact_comparisons[{idx}].status must be matched: {path}")
            artifact = item.get("artifact")
            if not isinstance(artifact, str) or not artifact.strip() or is_placeholder(artifact):
                failures.append(f"reproducibility artifact_comparisons[{idx}].artifact is required: {path}")
            for field in ("reference_sha256", "rebuild_sha256"):
                value = item.get(field)
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                    failures.append(
                        f"reproducibility artifact_comparisons[{idx}].{field} must be a non-zero sha256: {path}"
                    )
            if (
                isinstance(item.get("reference_sha256"), str)
                and isinstance(item.get("rebuild_sha256"), str)
                and item["reference_sha256"] != item["rebuild_sha256"]
            ):
                failures.append(f"reproducibility artifact_comparisons[{idx}] digest mismatch: {path}")
    logs = payload.get("logs", [])
    if not isinstance(logs, list):
        failures.append(f"reproducibility logs must be a list: {path}")
    else:
        base = path.parent
        for idx, item in enumerate(logs):
            if not isinstance(item, dict):
                failures.append(f"reproducibility logs[{idx}] must be an object: {path}")
                continue
            rel = item.get("path")
            digest = item.get("sha256")
            if not isinstance(rel, str) or not rel.strip() or is_placeholder(rel):
                failures.append(f"reproducibility logs[{idx}].path is required: {path}")
                continue
            rel_path = Path(rel)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                failures.append(f"reproducibility logs[{idx}].path must be relative and contained: {path}")
                continue
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
                failures.append(f"reproducibility logs[{idx}].sha256 must be a non-zero sha256: {path}")
                continue
            if check_files:
                log_path = base / rel_path
                if not log_path.is_file() or log_path.stat().st_size <= 0:
                    failures.append(f"reproducibility log missing or empty: {log_path}")
                elif sha256_file(log_path) != digest:
                    failures.append(f"reproducibility log sha mismatch: {log_path}")
    return failures


def validate_security_report(
    path: Path,
    scan: str,
    version: str,
    source_sha: str | None,
    source_run_id: str | None,
    check_files: bool = False,
) -> list[str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"missing or invalid release security report: {path}"]
    failures = []
    schema_version = payload.get("schema_version")
    if schema_version not in {"suderra.release-security-report.v1", "suderra.release-security-report.v2"}:
        failures.append(f"security report schema_version mismatch: {path}")
    if payload.get("version") != version:
        failures.append(f"security report version mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"security report source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"security report source_run_id mismatch: {path}")
    if payload.get("scan", scan) != scan:
        failures.append(f"security report scan mismatch: {path}")
    if payload.get("status") != "passed":
        failures.append(f"security report status must be passed: {path}")
    if schema_version == "suderra.release-security-report.v2":
        try:
            spec = importlib.util.spec_from_file_location(
                "security_raw_replay",
                ROOT / "scripts" / "evidence" / "security-raw-replay.py",
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot import security-raw-replay.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            failures.extend(module.validate_report(path, check_files=check_files))
        except Exception as exc:
            failures.append(f"cannot replay scanner raw evidence: {exc}")
        return failures
    for field in ("generated_at", "tool", "tool_version", "evidence_type", "evidence_sha256", "evidence_path"):
        value = payload.get(field)
        if field == "evidence_sha256":
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                failures.append(f"security report evidence_sha256 must be a non-zero sha256: {path}")
        elif field == "evidence_path":
            if not isinstance(value, str) or not value.strip() or is_placeholder(value):
                failures.append(f"security report missing evidence_path: {path}")
            else:
                rel = Path(value)
                if rel.is_absolute() or ".." in rel.parts:
                    failures.append(f"security report evidence_path must be relative and confined: {path}")
        elif not isinstance(value, str) or not value.strip() or is_placeholder(value):
            failures.append(f"security report missing {field}: {path}")
    evidence_bytes = payload.get("evidence_bytes")
    if not isinstance(evidence_bytes, int) or evidence_bytes <= 0:
        failures.append(f"security report evidence_bytes must be positive: {path}")
    elif evidence_bytes > MAX_RAW_SECURITY_EVIDENCE_BYTES:
        failures.append(f"security report raw evidence exceeds size cap: {path}")
    evidence_path = payload.get("evidence_path")
    evidence_sha = payload.get("evidence_sha256")
    if check_files and isinstance(evidence_path, str) and not Path(evidence_path).is_absolute() and ".." not in Path(evidence_path).parts:
        raw_root = path.parent.parent
        raw_path = raw_root / evidence_path
        if not raw_path.is_file():
            failures.append(f"security report raw evidence missing: {raw_path}")
        else:
            if raw_path.stat().st_size != evidence_bytes:
                failures.append(f"security report raw evidence size mismatch: {raw_path}")
            if isinstance(evidence_sha, str) and SHA256_RE.fullmatch(evidence_sha) and sha256_file(raw_path) != evidence_sha:
                failures.append(f"security report raw evidence sha256 mismatch: {raw_path}")
    counts = payload.get("severity_counts")
    if isinstance(counts, dict):
        for severity in ("critical", "high"):
            value = counts.get(severity, 0)
            if isinstance(value, int) and value > 0:
                failures.append(f"security report has {severity} findings: {path}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-tier", choices=("alpha", "production"), required=True)
    parser.add_argument(
        "--profile",
        choices=("technical-dry-run", "release-candidate", "production-candidate"),
        default="release-candidate",
    )
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--binding-manifest", type=Path)
    parser.add_argument("--ingress-manifest", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--source-run-id")
    parser.add_argument("--source-run-attempt")
    parser.add_argument("--station-registry", type=Path)
    parser.add_argument("--build-workflow-name", default="Image Build")
    parser.add_argument("--build-workflow-path", default=".github/workflows/image-build.yml")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--require-ingress-signature", action="store_true")
    parser.add_argument("--ingress-certificate-identity")
    parser.add_argument("--ingress-certificate-oidc-issuer")
    args = parser.parse_args()

    failures: list[str] = []
    inferred_tier = "alpha" if "-" in args.version else "production"
    if args.release_tier != inferred_tier:
        failures.append(f"release tier must be {inferred_tier} for version {args.version}")
    binding = load_binding(args.binding_manifest, failures)
    failures.extend(validate_binding(binding, args, args.matrix))
    if args.profile in {"release-candidate", "production-candidate"}:
        if args.ingress_manifest is None:
            failures.append(f"{args.profile} profile requires --ingress-manifest")
        else:
            ingress_args = [
                sys.executable,
                "scripts/evidence/release-ingress.py",
                "validate",
                str(args.ingress_manifest),
                "--expected-version",
                args.version,
            ]
            if args.binding_manifest is not None:
                ingress_args.extend(["--binding-manifest", str(args.binding_manifest)])
            if args.artifact_root is not None:
                ingress_args.extend(["--artifact-root", str(args.artifact_root)])
            if args.source_sha is not None:
                ingress_args.extend(["--expected-source-sha", args.source_sha])
            if args.require_ingress_signature:
                ingress_args.append("--require-signature")
                if args.ingress_certificate_identity:
                    ingress_args.extend(["--certificate-identity", args.ingress_certificate_identity])
                if args.ingress_certificate_oidc_issuer:
                    ingress_args.extend(["--certificate-oidc-issuer", args.ingress_certificate_oidc_issuer])
            failures.extend(run(ingress_args))
    bound_source_sha = args.source_sha
    if bound_source_sha is None and isinstance(binding, dict) and isinstance(binding.get("source_sha"), str):
        bound_source_sha = binding["source_sha"]
    bound_source_run_id = args.source_run_id
    if bound_source_run_id is None and isinstance(binding, dict) and binding.get("source_run_id") is not None:
        bound_source_run_id = str(binding["source_run_id"])
    if args.profile == "technical-dry-run":
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print(f"validated technical dry-run release inputs for {args.version}")
        return 0
    governance_report = args.root / "release-governance" / args.version / "governance-policy-validation.json"
    governance = read_json(governance_report)
    if not isinstance(governance, dict) or governance.get("status") != "passed":
        failures.append(f"governance policy validation missing or failed: {governance_report}")

    lab_args = [
        sys.executable,
        "scripts/evidence/validate-lab-input.py",
        "validate-matrix",
        "--version",
        args.version,
        "--root",
        str(args.root / "release-lab-input"),
        "--require-pass",
        "--profile",
        args.profile,
    ]
    if bound_source_sha:
        lab_args.extend(["--expected-source-sha", bound_source_sha])
    if bound_source_run_id:
        lab_args.extend(["--expected-source-run-id", bound_source_run_id])
    station_registry = args.station_registry or args.root / "release-governance" / args.version / "station-registry.json"
    try:
        registry_rel = station_registry.resolve().relative_to((args.root / "release-lab-input").resolve())
    except ValueError:
        registry_rel = None
    if registry_rel is not None and args.profile != "technical-dry-run":
        failures.append("station registry must be a protected governance input, not release-lab-input")
    lab_args.extend(["--station-registry", str(station_registry)])
    if args.check_files:
        lab_args.append("--check-files")
    failures.extend(run(lab_args))
    if args.profile == "production-candidate":
        acquisition_root = args.root / "release-lab-input" / args.version
        acquisition_count = 0
        for target_dir in sorted(acquisition_root.iterdir()) if acquisition_root.is_dir() else []:
            if not target_dir.is_dir():
                continue
            acquisition = target_dir / "station-acquisition.json"
            acquisition_count += 1
            acquisition_args = [
                sys.executable,
                "scripts/evidence/station-acquisition.py",
                "validate",
                str(acquisition),
            ]
            if args.check_files:
                acquisition_args.append("--check-files")
            failures.extend(run(acquisition_args))
        if acquisition_count == 0:
            failures.append("production-candidate profile requires station-acquisition adapter evidence")

    matrix = load_matrix(args.matrix)
    if args.profile == "production-candidate":
        signing_root = args.root / "release-signing" / args.version
        signing_sessions = sorted(signing_root.glob("*/*.json")) if signing_root.is_dir() else []
        if not signing_sessions:
            failures.append("production-candidate profile requires release-signing HSM session evidence")
        for session in signing_sessions:
            payload = read_json(session)
            if not isinstance(payload, dict):
                failures.append(f"HSM signing session missing or invalid JSON: {session}")
                continue
            if payload.get("schema_version") != "suderra.hsm-signing-session.v2":
                failures.append(f"HSM signing session must be suderra.hsm-signing-session.v2: {session}")
            if payload.get("mode") != "production":
                failures.append(f"HSM signing session mode must be production: {session}")
            if not isinstance(payload.get("challenge"), dict) or not isinstance(payload.get("artifacts"), list):
                failures.append(f"HSM signing session must bind challenge and artifacts: {session}")
    for row in matrix.get("defconfigs", []):
        if row.get("release") and row.get("qemu_test"):
            qemu = args.root / "release-lab-input" / args.version / str(row["target"]) / "qemu.json"
            qemu_args = [
                sys.executable,
                "scripts/evidence/validate-qemu-input.py",
                str(qemu),
                "--require-pass",
                "--profile",
                args.profile,
            ]
            if bound_source_sha:
                qemu_args.extend(["--expected-source-sha", bound_source_sha])
            expected_qemu_sha = binding_artifact_sha256(binding, str(row["target"]), str(row["artifact"]))
            if expected_qemu_sha:
                qemu_args.extend(["--expected-artifact-sha256", expected_qemu_sha])
            if args.check_files:
                qemu_args.append("--check-files")
            failures.extend(run(qemu_args))
        if row.get("release"):
            target = str(row["target"])
            approval = args.root / "release-approvals" / args.version / f"{target}.json"
            repro = args.root / "release-reproducibility" / args.version / f"{target}.json"
            failures.extend(validate_approval(approval, args.version, target, bound_source_sha))
            failures.extend(validate_repro(repro, args.version, target, bound_source_sha, bound_source_run_id, args.check_files))
        if args.profile == "production-candidate" and row.get("profile") == "production-runtime":
            runtime = args.root / "release-runtime" / args.version / str(row["target"]) / "production-runtime.json"
            runtime_args = [
                sys.executable,
                "scripts/evidence/validate-production-runtime-suite.py",
                str(runtime),
                "--require-pass",
                "--expected-version",
                args.version,
                "--expected-target",
                str(row["target"]),
            ]
            if bound_source_sha:
                runtime_args.extend(["--expected-source-sha", bound_source_sha])
            if args.check_files:
                runtime_args.append("--check-files")
            failures.extend(run(runtime_args))
    for scan in matrix.get("security_scans", []):
        report = args.root / "release-security" / args.version / f"{scan}.json"
        if args.profile == "production-candidate":
            report_payload = read_json(report)
            if not isinstance(report_payload, dict) or report_payload.get("schema_version") != "suderra.release-security-report.v2":
                failures.append(f"production-candidate requires scanner-native v2 security report for {scan}: {report}")
        failures.extend(validate_security_report(report, str(scan), args.version, bound_source_sha, bound_source_run_id, args.check_files))

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated release inputs for {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
