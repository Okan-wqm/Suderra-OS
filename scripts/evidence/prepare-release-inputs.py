#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Prepare and bind release-candidate input evidence.

The output manifest is intentionally stricter than the final release evidence:
it binds pre-tag/pre-publish evidence to one successful Image Build run and one
exact source commit before any tag workflow is allowed to publish.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.release-input-binding.v2"
BUILDROOT_IDENTITY_SCHEMA_FIELD = "buildroot_source_identity_schema_version"
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


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def buildroot_source_metadata(source_sha: str) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
    spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = module.metadata(source_sha)
    failures = module.validate_metadata_payload(payload)
    if failures:
        raise RuntimeError("; ".join(failures))
    return payload


def buildroot_metadata_for_binding(identity: dict[str, Any]) -> dict[str, Any]:
    """Map a Buildroot source-identity payload into release binding fields."""
    output = {
        BUILDROOT_IDENTITY_SCHEMA_FIELD: identity.get("schema_version"),
    }
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
        if field in identity:
            output[field] = identity.get(field)
    return output


def buildroot_source_metadata_from_evidence(
    build_evidence: list[dict[str, Any]],
    artifact_root: Path | None,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    if artifact_root is None:
        return None, []
    identities: list[tuple[str, dict[str, Any]]] = []
    script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
    spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
    if spec is None or spec.loader is None:
        return None, [f"cannot import {script}"]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for evidence in build_evidence:
        if evidence.get("role") != "buildroot-source-identity":
            continue
        rel = evidence.get("path")
        if not isinstance(rel, str):
            errors.append("Buildroot source identity evidence path must be a string")
            continue
        path = artifact_root / rel
        try:
            payload = read_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot read Buildroot source identity {path}: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"Buildroot source identity must be a JSON object: {path}")
            continue
        for failure in module.validate_metadata_payload(payload):
            errors.append(f"{path}: {failure}")
        identities.append((str(evidence.get("defconfig")), payload))
    if not identities:
        return None, errors
    identity_fields = [
        "schema_version",
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
    ]
    first_defconfig, first = identities[0]
    for defconfig, payload in identities[1:]:
        for field in identity_fields:
            if payload.get(field) != first.get(field):
                errors.append(
                    f"Buildroot source identity mismatch for {defconfig}: {field} differs from {first_defconfig}"
                )
    return buildroot_metadata_for_binding(first), errors


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
                    errors.append(f"missing Image Build artifact for {defconfig}: {artifact}")
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


def build_evidence_entries(
    matrix: dict[str, Any],
    artifact_root: Path | None,
    require_artifacts: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    for row in release_rows(matrix):
        defconfig = str(row["name"])
        target = str(row["target"])
        artifact_dir = artifact_root / f"{defconfig}-build-logs" if artifact_root is not None else None
        roles = [
            ("build-log", f"build-logs/{defconfig}.log"),
            ("warning-classifier-evidence", f"build-logs/{defconfig}.warnings.json"),
            ("buildroot-source-identity", f"build-logs/{defconfig}.source-identity.json"),
            ("build-time-log", f"build-logs/{defconfig}.build-time.log"),
            ("build-performance", f"build-logs/{defconfig}.build-performance.json"),
        ]
        if row.get("prebuild_defconfigs"):
            roles.extend(
                [
                    ("payload-inputs", f"build-logs/{defconfig}.payload-inputs.json"),
                    ("payload-package", f"build-logs/{defconfig}.payload-package.json"),
                    ("usb-installer-base", f"build-logs/{defconfig}.usb-installer-base.json"),
                ]
            )
        for role, artifact in roles:
            path = None
            if artifact_dir is not None:
                candidates = [artifact_dir / artifact, artifact_dir / Path(artifact).name]
                path = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
            if path is None or not path.is_file():
                if require_artifacts:
                    errors.append(f"missing Image Build evidence for {defconfig}: {artifact}")
                continue
            entries.append(
                {
                    "role": role,
                    "defconfig": defconfig,
                    "target": target,
                    "artifact": artifact,
                    "path": path.relative_to(artifact_root).as_posix() if artifact_root else str(path),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return entries, errors


def installer_entries(
    artifact_root: Path | None,
    require_artifacts: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    for arch in ("x86_64", "aarch64"):
        artifact_dir = artifact_root / f"installer-{arch}" if artifact_root is not None else None
        for role, artifact in (
            ("installer", f"suderra-installer-{arch}"),
            ("checksum", f"suderra-installer-{arch}.sha256"),
        ):
            path = artifact_dir / artifact if artifact_dir is not None else None
            if path is None or not path.is_file():
                if require_artifacts:
                    errors.append(f"missing installer artifact for {arch}: {artifact}")
                continue
            entries.append(
                {
                    "role": role,
                    "arch": arch,
                    "artifact": artifact,
                    "path": path.relative_to(artifact_root).as_posix() if artifact_root else str(path),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return entries, errors


def image_build_contract_entry(
    contract: Path | None,
    artifact_root: Path | None,
    require_artifacts: bool,
) -> tuple[dict[str, Any] | None, list[str]]:
    if contract is None:
        if require_artifacts:
            return None, ["missing image build contract"]
        return None, []
    errors: list[str] = []
    if not contract.is_file() or contract.stat().st_size <= 0:
        return None, [f"image build contract missing or empty: {contract}"]
    try:
        payload = read_json(contract)
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"image build contract invalid JSON: {exc}"]
    if not isinstance(payload, dict) or payload.get("schema_version") != "suderra.image-build-contract.v1":
        errors.append("image build contract schema_version must be suderra.image-build-contract.v1")
    workflow = payload.get("workflow")
    if not isinstance(workflow, dict) or workflow.get("path") != ".github/workflows/image-build.yml":
        errors.append("image build contract must be produced by image-build.yml")
    if artifact_root is not None:
        try:
            rel = contract.relative_to(artifact_root)
        except ValueError:
            errors.append("image build contract must live under artifact root")
            rel_path = str(contract)
        else:
            rel_path = rel.as_posix()
    else:
        rel_path = str(contract)
    return (
        {
            "role": "image-build-contract",
            "path": rel_path,
            "bytes": contract.stat().st_size,
            "sha256": sha256_file(contract),
        },
        errors,
    )


def binding_payload(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not SEMVER_RE.fullmatch(args.version):
        errors.append(f"version is not SemVer tag format: {args.version}")
    if args.profile in {"rc-evidence-dry-run", "release-candidate"} and "-" not in args.version:
        errors.append(f"{args.profile} profile requires a prerelease SemVer tag")
    if args.profile == "production-candidate" and "-" in args.version:
        errors.append("production-candidate profile requires a GA SemVer tag")
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
    build_evidence, build_evidence_errors = build_evidence_entries(
        matrix,
        artifact_root,
        args.require_artifacts,
    )
    errors.extend(build_evidence_errors)
    buildroot_metadata, buildroot_errors = buildroot_source_metadata_from_evidence(build_evidence, artifact_root)
    errors.extend(buildroot_errors)
    if buildroot_metadata is None:
        try:
            buildroot_metadata = buildroot_source_metadata(args.source_sha)
        except Exception as exc:
            errors.append(f"cannot resolve Buildroot source identity for {args.source_sha}: {exc}")
            buildroot_metadata = {
                BUILDROOT_IDENTITY_SCHEMA_FIELD: "",
                "buildroot_index_sha": "",
                "buildroot_upstream_ref": "",
                "buildroot_source_mode": "",
                "buildroot_patchset_sha256": "",
                "buildroot_patch_files": [],
                "buildroot_effective_source_id": "",
                "buildroot_expected_patched": False,
            }
        else:
            buildroot_metadata = buildroot_metadata_for_binding(buildroot_metadata)
    installers, installer_errors = installer_entries(artifact_root, args.require_artifacts)
    errors.extend(installer_errors)
    image_contract, image_contract_errors = image_build_contract_entry(
        args.image_build_contract,
        artifact_root,
        args.require_artifacts,
    )
    errors.extend(image_contract_errors)
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
        "build_workflow_path": args.build_workflow_path,
        "matrix_path": matrix_display,
        "matrix_sha256": matrix_sha256,
        **buildroot_metadata,
        "artifact_root": str(artifact_root) if artifact_root else None,
        "artifacts": sorted(artifacts, key=lambda item: (item["defconfig"], item["artifact"])),
        "build_evidence": sorted(build_evidence, key=lambda item: (item["defconfig"], item["artifact"])),
        "installers": sorted(installers, key=lambda item: (item["arch"], item["artifact"])),
        "image_build_contract": image_contract,
        "userspace_cargo_lock_sha256": read_text_sha256(ROOT / "userspace" / "Cargo.lock"),
        "userspace_rust_toolchain_sha256": read_text_sha256(ROOT / "userspace" / "rust-toolchain.toml"),
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


def artifact_ref(binding: dict[str, Any], target: str, artifact: str) -> dict[str, Any] | None:
    artifacts = binding.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        if item.get("target") == target and item.get("artifact") == artifact:
            return item
    return None


def artifact_ref_any(binding: dict[str, Any], target: str, artifacts: list[str]) -> dict[str, Any] | None:
    for artifact in artifacts:
        ref = artifact_ref(binding, target, artifact)
        if ref is not None:
            return ref
    return None


def relative_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def file_measurement(input_root: Path | None, rel_path: str) -> dict[str, Any]:
    measurement: dict[str, Any] = {"path": rel_path}
    if input_root is None:
        return measurement
    path = input_root / rel_path
    if path.is_file():
        measurement["sha256"] = sha256_file(path)
        measurement["bytes"] = path.stat().st_size
    return measurement


def artifact_measurement(ref: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(ref, dict):
        return {}
    measurement: dict[str, Any] = {}
    rel_path = relative_path(ref.get("path"))
    if rel_path is not None:
        measurement["path"] = rel_path
    if isinstance(ref.get("sha256"), str):
        measurement["sha256"] = ref["sha256"]
    if isinstance(ref.get("bytes"), int):
        measurement["bytes"] = ref["bytes"]
    return measurement


def node_id_for(subject_id: str, role: str, path: str) -> str:
    digest = sha256_bytes(f"{subject_id}|{role}|{path}".encode("utf-8"))[:24]
    return f"evidence-node:{digest}"


def append_evidence_node(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    subject_id: str,
    target: str,
    role: str,
    path: str,
    schema_role: str,
    schema_version: str,
    required: bool,
    measurement: dict[str, Any] | None = None,
    producer: str = "ci/evidence-contract.yml",
) -> str:
    payload = {
        "node_id": node_id_for(subject_id, role, path),
        "subject_id": subject_id,
        "target": target,
        "role": role,
        "path": path,
        "schema_role": schema_role,
        "schema_version": schema_version,
        "required": bool(required),
        "producer": producer,
    }
    if measurement:
        for field in ("sha256", "bytes"):
            if field in measurement:
                payload[field] = measurement[field]
    nodes.append(payload)
    edges.append(
        {
            "from": subject_id,
            "to": payload["node_id"],
            "relationship": "requires" if required else "observes",
            "role": role,
        }
    )
    return str(payload["node_id"])


def subject_graph_payload(
    binding: dict[str, Any],
    matrix: dict[str, Any],
    *,
    input_root: Path | None = None,
) -> dict[str, Any]:
    contract = evidence_contract.load_contract()
    version = str(binding.get("version"))
    profile = str(binding.get("profile"))
    source_sha = str(binding.get("source_sha"))
    source_run_id = str(binding.get("source_run_id"))
    profile_policy = evidence_contract.profile_policy(profile, contract)
    strict_artifact_binding = bool(profile_policy.get("strict_artifact_binding"))
    production_candidate = bool(profile_policy.get("production_candidate"))
    subjects: list[dict[str, Any]] = []
    evidence_nodes: list[dict[str, Any]] = []
    evidence_edges: list[dict[str, Any]] = []
    scans = [str(item) for item in matrix.get("security_scans", []) if isinstance(item, str)]
    for row in matrix.get("defconfigs", []):
        if not isinstance(row, dict) or not isinstance(row.get("target"), str):
            continue
        target = str(row["target"])
        policy = evidence_contract.target_policy(target, contract)
        if not policy or not (policy.get("production_gate") or policy.get("release_public")):
            continue
        production_candidate = profile == "production-candidate"
        raw_ref = artifact_ref(binding, target, str(row.get("artifact")))
        compressed_ref = artifact_ref_any(
            binding,
            target,
            [
                str(row.get("release_artifact")),
                f"{row.get('artifact')}.xz",
            ],
        )
        if (
            strict_artifact_binding
            and not production_candidate
            and row.get("release") is not True
            and (not isinstance(raw_ref, dict) or not isinstance(compressed_ref, dict))
        ):
            continue
        subject_id = evidence_contract.release_subject_id(
            version=version,
            target=target,
            source_sha=source_sha,
            source_run_id=source_run_id,
            contract=contract,
        )
        required_evidence: list[str] = []
        binding_path = f"release-inputs/{version}/{profile}.json"
        required_evidence.append(
            append_evidence_node(
                evidence_nodes,
                evidence_edges,
                subject_id=subject_id,
                target=target,
                role="release-input-binding",
                path=binding_path,
                schema_role="binding_manifest",
                schema_version=SCHEMA_VERSION,
                required=True,
                measurement=file_measurement(input_root, binding_path),
                producer="prepare-release-inputs.py",
            )
        )
        for role, artifact in (
            ("raw-image", raw_ref),
            ("compressed-release-artifact", compressed_ref),
        ):
            measurement = artifact_measurement(artifact)
            rel_path = measurement.get("path")
            if isinstance(rel_path, str):
                required_evidence.append(
                    append_evidence_node(
                        evidence_nodes,
                        evidence_edges,
                        subject_id=subject_id,
                        target=target,
                        role=role,
                        path=rel_path,
                        schema_role="build_artifact",
                        schema_version="sha256-digest",
                        required=profile == "production-candidate",
                        measurement=measurement,
                        producer="ci/build-matrix.yml",
                    )
                )
        for runtime_target in evidence_contract.runtime_suite_targets_for(target, contract):
            runtime_path = f"release-runtime/{version}/{runtime_target}/production-runtime.json"
            required_evidence.append(
                append_evidence_node(
                    evidence_nodes,
                    evidence_edges,
                    subject_id=subject_id,
                    target=target,
                    role="runtime-suite",
                    path=runtime_path,
                    schema_role="production_runtime_suite",
                    schema_version=evidence_contract.schema_version("production_runtime_suite", contract),
                    required=production_candidate and bool(policy.get("runtime_required")),
                    measurement=file_measurement(input_root, runtime_path),
                )
            )
        if policy.get("signing_required") is True:
            signing_path = f"release-signing/{version}/{target}/signing-manifest.json"
            required_evidence.append(
                append_evidence_node(
                    evidence_nodes,
                    evidence_edges,
                    subject_id=subject_id,
                    target=target,
                    role="signing-manifest",
                    path=signing_path,
                    schema_role="signing_manifest",
                    schema_version=evidence_contract.schema_version("signing_manifest", contract),
                    required=production_candidate,
                    measurement=file_measurement(input_root, signing_path),
                )
            )
        if policy.get("hardware_required") is True:
            hardware_path = f"release-lab-input/{version}/{target}/hardware-subject.json"
            required_evidence.append(
                append_evidence_node(
                    evidence_nodes,
                    evidence_edges,
                    subject_id=subject_id,
                    target=target,
                    role="hardware-subject",
                    path=hardware_path,
                    schema_role="hardware_subject",
                    schema_version=evidence_contract.schema_version("hardware_subject", contract),
                    required=production_candidate,
                    measurement=file_measurement(input_root, hardware_path),
                )
            )
            registry_path = f"release-governance/{version}/station-registry.json"
            required_evidence.append(
                append_evidence_node(
                    evidence_nodes,
                    evidence_edges,
                    subject_id=subject_id,
                    target=target,
                    role="station-registry",
                    path=registry_path,
                    schema_role="lab_station_registry",
                    schema_version="suderra.lab-station-registry.v1",
                    required=production_candidate,
                    measurement=file_measurement(input_root, registry_path),
                )
            )
        if policy.get("release_image_scan_required") is True:
            for scan in scans:
                scan_path = f"release-security/{version}/{scan}.json"
                required_evidence.append(
                    append_evidence_node(
                        evidence_nodes,
                        evidence_edges,
                        subject_id=subject_id,
                        target=target,
                        role="scanner-native-report",
                        path=scan_path,
                        schema_role="release_security_report",
                        schema_version=evidence_contract.schema_version("release_security_report", contract),
                        required=production_candidate,
                        measurement=file_measurement(input_root, scan_path),
                        )
                    )
        if policy.get("ota_capable") is True:
            ota_path = f"release-ota/{version}/{target}/ota-artifacts.json"
            required_evidence.append(
                append_evidence_node(
                    evidence_nodes,
                    evidence_edges,
                    subject_id=subject_id,
                    target=target,
                    role="ota-artifacts",
                    path=ota_path,
                    schema_role="ota_artifacts",
                    schema_version=evidence_contract.schema_version("ota_artifacts", contract),
                    required=production_candidate,
                    measurement=file_measurement(input_root, ota_path),
                )
            )
        if policy.get("production_gate") is True:
            for role, rel_path, schema_role, schema_version in (
                (
                    "governance-role-bindings",
                    f"release-governance/{version}/role-bindings.json",
                    "governance_role_bindings",
                    evidence_contract.schema_version("governance_role_bindings", contract),
                ),
                (
                    "governance-snapshot",
                    f"release-governance/{version}/governance-policy-validation.json",
                    "github_governance_validation",
                    "suderra.github-governance-validation.v2",
                ),
                (
                    "reproducibility",
                    f"release-reproducibility/{version}/{target}.json",
                    "reproducibility",
                    "suderra.reproducibility.v1",
                ),
            ):
                required_evidence.append(
                    append_evidence_node(
                        evidence_nodes,
                        evidence_edges,
                        subject_id=subject_id,
                        target=target,
                        role=role,
                        path=rel_path,
                        schema_role=schema_role,
                        schema_version=schema_version,
                        required=production_candidate or role == "reproducibility",
                        measurement=file_measurement(input_root, rel_path),
                    )
                )
            if profile == "production-candidate":
                retention_path = f"release-retention/{version}/retention-manifest.json"
                required_evidence.append(
                    append_evidence_node(
                        evidence_nodes,
                        evidence_edges,
                        subject_id=subject_id,
                        target=target,
                        role="retention-manifest",
                        path=retention_path,
                        schema_role="retention_manifest",
                        schema_version=evidence_contract.schema_version("retention_manifest", contract),
                        required=True,
                        measurement=file_measurement(input_root, retention_path),
                    )
                )
        subject = {
            "subject_id": subject_id,
            "version": version,
            "profile": profile,
            "target": target,
            "defconfig": row.get("name"),
            "source_sha": source_sha,
            "source_run_id": source_run_id,
            "source_run_attempt": str(binding.get("source_run_attempt")),
            "raw_image_sha256": raw_ref.get("sha256") if isinstance(raw_ref, dict) else None,
            "raw_image_bytes": raw_ref.get("bytes") if isinstance(raw_ref, dict) else None,
            "compressed_artifact_sha256": compressed_ref.get("sha256") if isinstance(compressed_ref, dict) else None,
            "compressed_artifact_bytes": compressed_ref.get("bytes") if isinstance(compressed_ref, dict) else None,
            "artifacts": {
                "raw_image": {
                    "name": row.get("artifact"),
                    "sha256": raw_ref.get("sha256") if isinstance(raw_ref, dict) else None,
                    "bytes": raw_ref.get("bytes") if isinstance(raw_ref, dict) else None,
                },
                "compressed_release_artifact": {
                    "name": row.get("release_artifact"),
                    "sha256": compressed_ref.get("sha256") if isinstance(compressed_ref, dict) else None,
                    "bytes": compressed_ref.get("bytes") if isinstance(compressed_ref, dict) else None,
                },
            },
            "target_policy": policy,
            "runtime_suite_targets": evidence_contract.runtime_suite_targets_for(target, contract),
            "required_evidence_nodes": sorted(required_evidence),
        }
        subjects.append(subject)
    return {
        "schema_version": evidence_contract.schema_version("release_subject_graph", contract),
        "version": version,
        "profile": profile,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "source_run_attempt": str(binding.get("source_run_attempt")),
        "producer": {
            "name": "prepare-release-inputs.py subject-graph",
            "source": "ci/evidence-contract.yml",
        },
        "subjects": sorted(subjects, key=lambda item: str(item.get("target"))),
        "evidence_nodes": sorted(evidence_nodes, key=lambda item: (str(item.get("target")), str(item.get("role")), str(item.get("path")))),
        "evidence_edges": sorted(evidence_edges, key=lambda item: (str(item.get("from")), str(item.get("role")), str(item.get("to")))),
        "required_paths": sorted(
            {
                str(item["path"])
                for item in evidence_nodes
                if item.get("required") is True and isinstance(item.get("path"), str)
            }
        ),
        "retention_closure": {
            "policy_id": evidence_contract.retention_policy(contract)["policy_id"],
            "required_exports": evidence_contract.retention_required_exports(contract),
        },
    }


def subject_graph_command(args: argparse.Namespace) -> int:
    binding = read_json(args.binding_manifest)
    if not isinstance(binding, dict):
        print(f"ERROR: binding manifest must be a JSON object: {args.binding_manifest}", file=sys.stderr)
        return 1
    matrix_path = args.matrix if args.matrix.is_absolute() else ROOT / args.matrix
    matrix, _matrix_module = load_matrix(matrix_path)
    input_root = args.input_root if args.input_root is None or args.input_root.is_absolute() else ROOT / args.input_root
    payload = subject_graph_payload(binding, matrix, input_root=input_root)
    write_json(args.output, payload)
    print(f"wrote release subject graph: {args.output}")
    return 0


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
        "schema_version": "suderra.qemu-acceptance.v4",
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
        "profile": "release-candidate",
        "failure_class": "operator_error",
        "qemu_exit_status": None,
        "termination": {
            "mode": "not_started",
            "exit_status": None,
            "signal": None,
            "killed": False,
            "timeout": False,
            "qmp_quit_sent": False,
            "qmp_quit_ack": False,
            "reason": "skeleton placeholder; QEMU has not been collected",
            "acceptable": False,
        },
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
            "build_artifact_sha256": "0" * 64,
            "build_artifact_bytes": 0,
        },
        "devices": [],
        "negative_tests": [],
    }


def init_command(args: argparse.Namespace) -> int:
    matrix_path = args.matrix if args.matrix.is_absolute() else ROOT / args.matrix
    matrix, _matrix_module = load_matrix(matrix_path)
    binding_output = args.output_root / "release-inputs" / args.version / f"{args.profile}.json"
    plan_args = argparse.Namespace(**vars(args))
    plan_args.output = binding_output
    plan_args.require_artifacts = args.artifact_root is not None
    payload, errors = binding_payload(plan_args)
    write_json(binding_output, payload)
    write_json(
        args.output_root / "release-subject-graph" / args.version / "release-subject-graph.json",
        subject_graph_payload(payload, matrix, input_root=args.output_root),
    )

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
                "schema_version": "suderra.release-approval.v2",
                "version": args.version,
                "target": target,
                "source_sha": args.source_sha,
                "approvals": [],
                "residual_risk": {
                    "status": "none",
                    "items": [],
                },
                "release_decision": {
                    "status": "blocked",
                    "decided_by": "TO_BE_COLLECTED",
                    "decided_at": "TO_BE_COLLECTED",
                    "rationale": "TO_BE_COLLECTED",
                },
            },
        )
        write_json(
            args.output_root / "release-reproducibility" / args.version / f"{target}.json",
            {
                "schema_version": "suderra.reproducibility.v1",
                "version": args.version,
                "target": target,
                "source_sha": args.source_sha,
                "source_run_id": str(args.source_run_id),
                "status": "not_run",
                "generated_at": "TO_BE_COLLECTED",
                "comparison": "TO_BE_COLLECTED",
                "artifact_comparisons": [],
                "logs": [],
            },
        )

    for scan in matrix.get("security_scans", []):
        write_json(
            args.output_root / "release-security" / args.version / f"{scan}.json",
            {
                "schema_version": "suderra.release-security-report.v2",
                "version": args.version,
                "source_sha": args.source_sha,
                "source_run_id": str(args.source_run_id),
                "scan": scan,
                "status": "not_run",
                "generated_at": "TO_BE_COLLECTED",
                "tool": scan,
                "tool_version": "TO_BE_COLLECTED",
                "scanner_db": {
                    "type": "TO_BE_COLLECTED",
                    "version": "TO_BE_COLLECTED",
                    "created_at": "TO_BE_COLLECTED",
                    "digest": "TO_BE_COLLECTED",
                    "auto_update_disabled": False,
                },
                "subjects": [],
                "raw": {
                    "path": "TO_BE_COLLECTED",
                    "sha256": "0" * 64,
                    "bytes": 0,
                },
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
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
    parser.add_argument("--build-workflow-name", default="Image Build")
    parser.add_argument("--build-workflow-path", default=".github/workflows/image-build.yml")
    parser.add_argument(
        "--profile",
        choices=("technical-dry-run", "rc-evidence-dry-run", "release-candidate", "production-candidate"),
        default="release-candidate",
    )
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--image-build-contract", type=Path)


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

    subject_graph = subparsers.add_parser("subject-graph")
    subject_graph.add_argument("--binding-manifest", type=Path, required=True)
    subject_graph.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    subject_graph.add_argument("--input-root", type=Path)
    subject_graph.add_argument("--output", type=Path, required=True)
    subject_graph.set_defaults(func=subject_graph_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
