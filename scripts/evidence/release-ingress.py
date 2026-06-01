#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate release ingress manifests.

The ingress manifest records the exact Image Build workflow artifact bytes that
a release preflight accepted. The tag workflow promotes those bytes instead of
rebuilding images.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402

EVIDENCE_CONTRACT = evidence_contract.load_contract()
SCHEMA_VERSION = "suderra.release-ingress.v1"
BINDING_SCHEMA_VERSION = "suderra.release-input-binding.v2"
BUILDROOT_IDENTITY_SCHEMA_FIELD = "buildroot_source_identity_schema_version"
IMAGE_BUILD_WORKFLOW_NAME = "Image Build"
IMAGE_BUILD_WORKFLOW_PATH = ".github/workflows/image-build.yml"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {"TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING", ""}
SCHEMA_ROLES = {
    "evidence_ingress": "suderra.operator-evidence-ingress.v2",
    "binding_manifest": BINDING_SCHEMA_VERSION,
    "approval": "suderra.release-approval.v2",
    "governance_role_bindings": evidence_contract.schema_version("governance_role_bindings", EVIDENCE_CONTRACT),
    "hardware_subject": evidence_contract.schema_version("hardware_subject", EVIDENCE_CONTRACT),
    "qemu_input": "suderra.qemu-acceptance.v4",
    "lab_input": evidence_contract.schema_version("lab_evidence", EVIDENCE_CONTRACT),
    "production_runtime_suite": evidence_contract.schema_version("production_runtime_suite", EVIDENCE_CONTRACT),
    "hsm_signing_session": evidence_contract.schema_version("hsm_signing_session", EVIDENCE_CONTRACT),
    "release_subject_graph": evidence_contract.schema_version("release_subject_graph", EVIDENCE_CONTRACT),
    "retention_manifest": evidence_contract.schema_version("retention_manifest", EVIDENCE_CONTRACT),
    "release_security_report": evidence_contract.schema_version("release_security_report", EVIDENCE_CONTRACT),
    "signing_manifest": evidence_contract.schema_version("signing_manifest", EVIDENCE_CONTRACT),
    "station_acquisition": evidence_contract.schema_version("station_acquisition", EVIDENCE_CONTRACT),
    "ota_artifacts": evidence_contract.schema_version("ota_artifacts", EVIDENCE_CONTRACT),
    "release_evidence": evidence_contract.schema_version("release_evidence", EVIDENCE_CONTRACT),
}
OPTIONAL_EMPTY_INPUT_ROLES = {"qemu-stderr"}
PREFLIGHT_INPUT_DIRS = tuple(evidence_contract.output_tree_roots(contract=EVIDENCE_CONTRACT))
VALID_PREFLIGHT_PROFILES = set(evidence_contract.all_profiles(EVIDENCE_CONTRACT))
STRICT_PREFLIGHT_PROFILES = set(evidence_contract.operator_ingress_required_profiles(EVIDENCE_CONTRACT))
EVIDENCE_INGRESS_MANIFEST = "evidence-ingress-manifest.json"
EVIDENCE_INGRESS_SIGNATURE_SIDECARS = (
    "evidence-ingress-manifest.json.sig",
    "evidence-ingress-manifest.json.cert",
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_utc(value: Any, path: str, failures: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        failures.append(f"{path}: must be an ISO-8601 UTC timestamp ending in Z")
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        failures.append(f"{path}: must be an ISO-8601 UTC timestamp")
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_buildroot_identity_module() -> Any:
    script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
    spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_operator_evidence_ingress_module() -> Any:
    script = ROOT / "scripts" / "evidence" / "operator-evidence-ingress.py"
    spec = importlib.util.spec_from_file_location("operator_evidence_ingress", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_validate_release_inputs_module() -> Any:
    script = ROOT / "scripts" / "evidence" / "validate-release-inputs.py"
    spec = importlib.util.spec_from_file_location("validate_release_inputs", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def buildroot_identity_payload_from_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    identity: dict[str, Any] = {}
    if BUILDROOT_IDENTITY_SCHEMA_FIELD in payload:
        identity["schema_version"] = payload.get(BUILDROOT_IDENTITY_SCHEMA_FIELD)
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
        if field in payload:
            identity[field] = payload.get(field)
    return identity


def validate_buildroot_identity(failures: list[str], path: str, payload: dict[str, Any]) -> None:
    try:
        module = load_buildroot_identity_module()
    except Exception as exc:
        failures.append(f"{path}: cannot load Buildroot source identity validator: {exc}")
        return
    identity = buildroot_identity_payload_from_mapping(payload)
    for failure in module.validate_metadata_payload(identity):
        failures.append(f"{path}: {failure}")


def check_string(failures: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip() or value.strip() in PLACEHOLDERS:
        failures.append(f"{path}: must be a non-placeholder string")


def check_sha256(failures: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        failures.append(f"{path}: must be a lowercase sha256 digest")
    elif value == "0" * 64:
        failures.append(f"{path}: must not be the all-zero sha256 digest")


def check_relative_path(failures: list[str], path: str, value: Any) -> Path | None:
    check_string(failures, path, value)
    if not isinstance(value, str):
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        failures.append(f"{path}: must be relative and must not contain '..'")
        return None
    return rel


def role_for_artifact(artifact: str) -> str:
    if artifact.endswith(".log"):
        return "build-log"
    if artifact.endswith(".warnings.json"):
        return "warning-classifier-evidence"
    if artifact.endswith(".img.xz") or artifact.endswith(".img"):
        return "release-image"
    if artifact == "MANIFEST.txt" or artifact.endswith(".manifest.txt"):
        return "checksum"
    if artifact == "manifest.json" or artifact.endswith(".payload-manifest.json"):
        return "payload-manifest"
    if artifact == "manifest.sig" or artifact.endswith(".payload-manifest.sig"):
        return "payload-signature"
    return "build-artifact"


def append_file_record(
    files: list[dict[str, Any]],
    *,
    source: str,
    role: str,
    path: Path,
    rel_path: Path,
    defconfig: str = "release-input",
    target: str = "release-input",
    artifact: str | None = None,
) -> None:
    files.append(
        {
            "source": source,
            "role": role,
            "defconfig": defconfig,
            "target": target,
            "artifact": artifact or rel_path.name,
            "path": rel_path.as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    )


def input_role_for_path(rel_path: Path) -> str:
    return evidence_contract.preflight_input_role_for_path(rel_path, contract=EVIDENCE_CONTRACT)


def create_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    binding = read_json(args.binding_manifest)
    if not isinstance(binding, dict):
        return {}, [f"binding manifest must be a JSON object: {args.binding_manifest}"]
    if binding.get("schema_version") != BINDING_SCHEMA_VERSION:
        failures.append(f"binding schema_version must be {BINDING_SCHEMA_VERSION}")
    if binding.get("build_workflow_name") != IMAGE_BUILD_WORKFLOW_NAME:
        failures.append(f"binding build_workflow_name must be {IMAGE_BUILD_WORKFLOW_NAME}")
    if binding.get("build_workflow_path") != IMAGE_BUILD_WORKFLOW_PATH:
        failures.append(f"binding build_workflow_path must be {IMAGE_BUILD_WORKFLOW_PATH}")
    if not isinstance(binding.get("image_build_contract"), dict):
        failures.append("binding image_build_contract must be an object")
    validate_buildroot_identity(failures, "binding Buildroot source identity", binding)
    generated_at = now_utc()
    expires_at = generated_at + timedelta(days=args.expires_days)
    producer = {
        "provider": "github-actions",
        "repository": args.repository,
        "workflow": args.workflow,
        "run_id": str(args.run_id),
        "run_attempt": str(args.run_attempt),
        "actor": args.actor,
    }
    files: list[dict[str, Any]] = []
    artifact_root = args.artifact_root
    for collection, default_source in (
        (binding.get("artifacts", []), "build-artifact"),
        (binding.get("build_evidence", []), "build-evidence"),
        (binding.get("installers", []), "installer-artifact"),
        ([binding.get("image_build_contract")] if binding.get("image_build_contract") else [], "image-build-contract"),
    ):
        if not isinstance(collection, list):
            failures.append(f"binding {default_source} collection must be a list")
            continue
        for idx, artifact in enumerate(collection):
            if not isinstance(artifact, dict):
                failures.append(f"binding {default_source}[{idx}] must be an object")
                continue
            rel = artifact.get("path")
            rel_path = check_relative_path(failures, f"binding {default_source}[{idx}].path", rel)
            if rel_path is None:
                continue
            path = artifact_root / rel_path
            if not path.is_file() or path.stat().st_size <= 0:
                failures.append(f"ingress artifact missing or empty: {rel}")
                continue
            digest = sha256_file(path)
            bound_digest = artifact.get("sha256")
            if digest != bound_digest:
                failures.append(f"ingress artifact sha mismatch for {rel}: binding {bound_digest}, got {digest}")
            if default_source == "image-build-contract":
                record_defconfig = "image-build-contract"
                record_target = "image-build-contract"
                record_artifact = artifact.get("artifact") or rel_path.name
            else:
                record_defconfig = artifact.get("defconfig") or f"installer-{artifact.get('arch')}"
                record_target = artifact.get("target") or artifact.get("arch")
                record_artifact = artifact.get("artifact")
            append_file_record(
                files,
                source=default_source,
                role=artifact.get("role") or role_for_artifact(str(artifact.get("artifact", ""))),
                defconfig=record_defconfig,
                target=record_target,
                artifact=record_artifact,
                path=path,
                rel_path=rel_path,
            )
    if args.input_root is not None:
        input_root = args.input_root
        profile = str(binding.get("profile", ""))
        allowed_input_dirs = set(evidence_contract.preflight_input_roots(profile, contract=EVIDENCE_CONTRACT))
        for dirname in evidence_contract.output_tree_roots(contract=EVIDENCE_CONTRACT):
            if dirname == "build-artifacts":
                continue
            if dirname not in allowed_input_dirs and (input_root / dirname).exists():
                failures.append(f"{dirname}: must not be present for preflight profile {profile}")
        for dirname in sorted(allowed_input_dirs):
            root = input_root / dirname
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                rel_path = path.relative_to(input_root)
                role = input_role_for_path(rel_path)
                if path.stat().st_size <= 0 and role not in OPTIONAL_EMPTY_INPUT_ROLES:
                    failures.append(f"preflight input is empty and not allowlisted: {rel_path.as_posix()}")
                    continue
                append_file_record(
                    files,
                    source="preflight-input",
                    role=role,
                    path=path,
                    rel_path=rel_path,
                    defconfig=rel_path.parts[2] if len(rel_path.parts) > 3 and rel_path.parts[0] == "release-lab-input" else "release-input",
                    target=rel_path.parts[2] if len(rel_path.parts) > 3 and rel_path.parts[0] == "release-lab-input" else "release-input",
                )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": binding.get("version"),
        "profile": binding.get("profile"),
        "source_sha": binding.get("source_sha"),
        "source_run_id": str(binding.get("source_run_id")),
        "source_run_attempt": str(binding.get("source_run_attempt")),
        "build_workflow_name": binding.get("build_workflow_name"),
        "build_workflow_path": binding.get("build_workflow_path"),
        "matrix_sha256": binding.get("matrix_sha256"),
        "buildroot_source_identity_schema_version": binding.get("buildroot_source_identity_schema_version"),
        "buildroot_index_sha": binding.get("buildroot_index_sha"),
        "buildroot_upstream_ref": binding.get("buildroot_upstream_ref"),
        "buildroot_source_mode": binding.get("buildroot_source_mode"),
        "buildroot_patchset_sha256": binding.get("buildroot_patchset_sha256"),
        "buildroot_patch_files": binding.get("buildroot_patch_files"),
        "buildroot_effective_source_id": binding.get("buildroot_effective_source_id"),
        "buildroot_expected_patched": binding.get("buildroot_expected_patched"),
        "buildroot_rust_version": binding.get("buildroot_rust_version"),
        "buildroot_rust_bin_version": binding.get("buildroot_rust_bin_version"),
        "producer": producer,
        "generated_at": format_utc(generated_at),
        "expires_at": format_utc(expires_at),
        "schema_roles": SCHEMA_ROLES,
        "files": sorted(files, key=lambda item: (str(item["defconfig"]), str(item["artifact"]))),
    }
    for field in (
        "buildroot_applied_diff_sha256",
        "buildroot_expected_diff_sha256",
        "buildroot_staged_diff_sha256",
        "buildroot_worktree_diff_sha256",
        "suderra_source_sha",
        "suderra_external_tree_sha256",
        "suderra_external_dirty_paths",
        "suderra_release_source_id",
    ):
        if binding.get(field) is not None:
            manifest[field] = binding.get(field)
    return manifest, failures


def verify_manifest_signature(
    manifest_path: Path,
    certificate_identity: str | None,
    certificate_oidc_issuer: str | None,
) -> list[str]:
    signature = manifest_path.with_name(f"{manifest_path.name}.sig")
    certificate = manifest_path.with_name(f"{manifest_path.name}.cert")
    failures = []
    for sidecar in (signature, certificate):
        if not sidecar.is_file() or sidecar.stat().st_size <= 0:
            failures.append(f"{sidecar}: missing ingress manifest signature sidecar")
    if failures:
        return failures
    if not certificate_identity or not certificate_oidc_issuer:
        failures.append("ingress signature verification requires certificate identity and OIDC issuer")
        return failures
    result = subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--certificate",
            str(certificate),
            "--certificate-identity",
            certificate_identity,
            "--certificate-oidc-issuer",
            certificate_oidc_issuer,
            "--signature",
            str(signature),
            str(manifest_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        failures.append(result.stderr.strip() or result.stdout.strip() or "cosign ingress signature verification failed")
    return failures


def validate_operator_evidence_ingress(
    *,
    manifest: dict[str, Any],
    input_root: Path,
    require_signature: bool,
    certificate_identity: str | None,
    certificate_oidc_issuer: str | None,
) -> list[str]:
    version = str(manifest.get("version", ""))
    operator_manifest = input_root / "release-ingress" / version / EVIDENCE_INGRESS_MANIFEST
    try:
        module = load_operator_evidence_ingress_module()
    except Exception as exc:
        return [f"operator evidence ingress: cannot load validator: {exc}"]
    args = argparse.Namespace(
        manifest=operator_manifest,
        input_root=input_root,
        matrix=ROOT / "ci" / "build-matrix.yml",
        expected_version=version,
        expected_source_sha=str(manifest.get("source_sha", "")),
        expected_source_image_build_run_id=str(manifest.get("source_run_id", "")),
        expected_source_image_build_run_attempt=str(manifest.get("source_run_attempt", "")),
        require_signature=require_signature,
        certificate_identity=certificate_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
        allow_preflight_context=True,
    )
    return [f"operator evidence ingress: {failure}" for failure in module.validate_manifest(args)]


def validate_manifest(
    manifest_path: Path,
    artifact_root: Path | None,
    input_root: Path | None = None,
    binding_manifest: Path | None = None,
    expected_version: str | None = None,
    expected_source_sha: str | None = None,
    require_signature: bool = False,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
    require_evidence_ingress_signature: bool = False,
    evidence_ingress_certificate_identity: str | None = None,
    evidence_ingress_certificate_oidc_issuer: str | None = None,
) -> list[str]:
    failures: list[str] = []
    try:
        manifest = read_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{manifest_path}: cannot read ingress manifest: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{manifest_path}: ingress manifest must be a JSON object"]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"$.schema_version: must be {SCHEMA_VERSION}")
    for field in (
        "version",
        "profile",
        "source_sha",
        "source_run_id",
        "source_run_attempt",
        "build_workflow_name",
        "build_workflow_path",
        "matrix_sha256",
        "buildroot_source_identity_schema_version",
        "buildroot_index_sha",
        "buildroot_upstream_ref",
        "buildroot_source_mode",
        "buildroot_patchset_sha256",
        "buildroot_effective_source_id",
        "buildroot_rust_version",
        "buildroot_rust_bin_version",
    ):
        check_string(failures, f"$.{field}", manifest.get(field))
    if manifest.get("build_workflow_name") != IMAGE_BUILD_WORKFLOW_NAME:
        failures.append(f"$.build_workflow_name: must be {IMAGE_BUILD_WORKFLOW_NAME}")
    if manifest.get("build_workflow_path") != IMAGE_BUILD_WORKFLOW_PATH:
        failures.append(f"$.build_workflow_path: must be {IMAGE_BUILD_WORKFLOW_PATH}")
    if manifest.get("profile") not in VALID_PREFLIGHT_PROFILES:
        failures.append(
            "$.profile: must be technical-dry-run, rc-evidence-dry-run, "
            "release-candidate, or production-candidate"
        )
    if expected_version is not None and manifest.get("version") != expected_version:
        failures.append(f"$.version: must match {expected_version}")
    binding = None
    if binding_manifest is not None:
        try:
            binding = read_json(binding_manifest)
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{binding_manifest}: cannot read binding manifest: {exc}")
            binding = None
        if isinstance(binding, dict):
            for field in (
                "version",
                "profile",
                "source_sha",
                "source_run_id",
                "source_run_attempt",
                "build_workflow_name",
                "build_workflow_path",
                "matrix_sha256",
                "buildroot_source_identity_schema_version",
                "buildroot_index_sha",
                "buildroot_upstream_ref",
                "buildroot_source_mode",
                "buildroot_patchset_sha256",
                "buildroot_patch_files",
                "buildroot_effective_source_id",
                "buildroot_applied_diff_sha256",
                "buildroot_expected_patched",
                "buildroot_rust_version",
                "buildroot_rust_bin_version",
                "buildroot_expected_diff_sha256",
                "buildroot_staged_diff_sha256",
                "buildroot_worktree_diff_sha256",
                "suderra_source_sha",
                "suderra_external_tree_sha256",
                "suderra_external_dirty_paths",
                "suderra_release_source_id",
            ):
                if field in binding or field in manifest:
                    if str(manifest.get(field)) != str(binding.get(field)):
                        failures.append(f"$.{field}: must match binding manifest")
    source_sha = manifest.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("$.source_sha: must be a lowercase git commit sha")
    elif expected_source_sha is not None and source_sha != expected_source_sha:
        failures.append(f"$.source_sha: must match {expected_source_sha}")
    check_sha256(failures, "$.matrix_sha256", manifest.get("matrix_sha256"))
    buildroot_index_sha = manifest.get("buildroot_index_sha")
    if not isinstance(buildroot_index_sha, str) or not SOURCE_SHA_RE.fullmatch(buildroot_index_sha):
        failures.append("$.buildroot_index_sha: must be a lowercase git commit sha")
    check_sha256(failures, "$.buildroot_patchset_sha256", manifest.get("buildroot_patchset_sha256"))
    check_sha256(failures, "$.buildroot_effective_source_id", manifest.get("buildroot_effective_source_id"))
    if "suderra_source_sha" in manifest:
        value = manifest.get("suderra_source_sha")
        if not isinstance(value, str) or not SOURCE_SHA_RE.fullmatch(value):
            failures.append("$.suderra_source_sha: must be a lowercase git commit sha")
    if "suderra_external_tree_sha256" in manifest:
        check_sha256(failures, "$.suderra_external_tree_sha256", manifest.get("suderra_external_tree_sha256"))
    if "suderra_release_source_id" in manifest:
        check_sha256(failures, "$.suderra_release_source_id", manifest.get("suderra_release_source_id"))
    if manifest.get("buildroot_applied_diff_sha256") is not None:
        check_sha256(failures, "$.buildroot_applied_diff_sha256", manifest.get("buildroot_applied_diff_sha256"))
    for field in (
        "buildroot_expected_diff_sha256",
        "buildroot_staged_diff_sha256",
        "buildroot_worktree_diff_sha256",
    ):
        if manifest.get(field) is not None:
            check_sha256(failures, f"$.{field}", manifest.get(field))
    if not isinstance(manifest.get("buildroot_expected_patched"), bool):
        failures.append("$.buildroot_expected_patched: must be a boolean")
    validate_buildroot_identity(failures, "$.buildroot_source_identity", manifest)
    patch_files = manifest.get("buildroot_patch_files")
    if not isinstance(patch_files, list):
        failures.append("$.buildroot_patch_files: must be a list")
    else:
        seen_patch_paths: set[str] = set()
        for idx, patch in enumerate(patch_files):
            patch_path = f"$.buildroot_patch_files[{idx}]"
            if not isinstance(patch, dict):
                failures.append(f"{patch_path}: must be an object")
                continue
            rel_path = check_relative_path(failures, f"{patch_path}.path", patch.get("path"))
            if rel_path is not None:
                rel = rel_path.as_posix()
                if rel in seen_patch_paths:
                    failures.append(f"{patch_path}.path: must be unique")
                seen_patch_paths.add(rel)
            check_sha256(failures, f"{patch_path}.sha256", patch.get("sha256"))
            if not isinstance(patch.get("bytes"), int) or patch.get("bytes", 0) <= 0:
                failures.append(f"{patch_path}.bytes: must be a positive integer")
    parse_utc(manifest.get("generated_at"), "$.generated_at", failures)
    expires_at = parse_utc(manifest.get("expires_at"), "$.expires_at", failures)
    if expires_at is not None and expires_at <= now_utc():
        failures.append("$.expires_at: must be in the future")
    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        failures.append("$.producer: must be an object")
    else:
        for field in ("provider", "repository", "workflow", "run_id", "run_attempt", "actor"):
            check_string(failures, f"$.producer.{field}", producer.get(field))
    schema_roles = manifest.get("schema_roles")
    if not isinstance(schema_roles, dict):
        failures.append("$.schema_roles: must be an object")
    else:
        for role, expected in SCHEMA_ROLES.items():
            if schema_roles.get(role) != expected:
                failures.append(f"$.schema_roles.{role}: must be {expected}")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        failures.append("$.files: must be a non-empty list")
        files = []
    seen_paths: set[str] = set()
    preflight_records_by_path: dict[str, list[int]] = {}
    has_image_build_contract = False
    for idx, item in enumerate(files):
        path = f"$.files[{idx}]"
        if not isinstance(item, dict):
            failures.append(f"{path}: must be an object")
            continue
        for field in ("role", "defconfig", "target", "artifact"):
            check_string(failures, f"{path}.{field}", item.get(field))
        source = item.get("source")
        if source not in {"build-artifact", "build-evidence", "installer-artifact", "image-build-contract", "preflight-input"}:
            failures.append(
                f"{path}.source: must be build-artifact, build-evidence, installer-artifact, "
                "image-build-contract, or preflight-input"
            )
        if source == "image-build-contract" and item.get("role") == "image-build-contract":
            has_image_build_contract = True
        rel_path = check_relative_path(failures, f"{path}.path", item.get("path"))
        check_sha256(failures, f"{path}.sha256", item.get("sha256"))
        allow_empty = source == "preflight-input" and item.get("role") in OPTIONAL_EMPTY_INPUT_ROLES
        if not isinstance(item.get("bytes"), int) or item.get("bytes", -1) < 0 or (item.get("bytes") == 0 and not allow_empty):
            failures.append(f"{path}.bytes: must be a positive integer unless role allows empty evidence")
        if rel_path is not None:
            rel = rel_path.as_posix()
            if rel in seen_paths:
                failures.append(f"{path}.path: must be unique")
            seen_paths.add(rel)
            if source == "preflight-input":
                allowed_input_dirs = set(
                    evidence_contract.preflight_input_roots(str(manifest.get("profile", "")), contract=EVIDENCE_CONTRACT)
                )
                if not rel_path.parts or rel_path.parts[0] not in allowed_input_dirs:
                    failures.append(f"{path}.path: preflight input must be under an allowed input tree")
                expected_role = input_role_for_path(rel_path)
                if item.get("role") != expected_role:
                    failures.append(f"{path}.role: does not match preflight input path role {expected_role}")
                preflight_records_by_path.setdefault(rel, []).append(idx)
            root = input_root if source == "preflight-input" else artifact_root
            if root is not None:
                actual = root / rel_path
                if not actual.is_file() or (actual.stat().st_size <= 0 and not allow_empty):
                    failures.append(f"{path}.path: referenced file is missing or empty: {rel}")
                else:
                    if actual.stat().st_size != item.get("bytes"):
                        failures.append(f"{path}.bytes: does not match referenced file size")
                    if sha256_file(actual) != item.get("sha256"):
                        failures.append(f"{path}.sha256: does not match referenced file sha256")
    dry_run_records = [
        item
        for item in files
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and Path(item["path"]).parts[:1] == ("release-dry-run",)
    ]
    if dry_run_records and manifest.get("profile") != "rc-evidence-dry-run":
        failures.append("$.files: release-dry-run inputs are only valid for rc-evidence-dry-run")
    if manifest.get("profile") == "rc-evidence-dry-run":
        version = str(manifest.get("version", ""))
        required_dry_run_paths = {
            f"release-dry-run/{version}/dry-run-report.json",
            f"release-dry-run/{version}/bundle-manifest.json",
            f"release-dry-run/{version}/gaps.json",
        }
        present_dry_run_paths = {str(item.get("path")) for item in dry_run_records}
        missing_dry_run_paths = sorted(required_dry_run_paths - present_dry_run_paths)
        if missing_dry_run_paths:
            failures.append(
                "$.files: rc-evidence-dry-run must preserve dry-run report, bundle manifest, and gap report: "
                + ", ".join(missing_dry_run_paths)
            )
    if not has_image_build_contract:
        failures.append("$.files: must include image-build-contract evidence")
    if manifest.get("profile") in STRICT_PREFLIGHT_PROFILES:
        version = str(manifest.get("version", ""))
        expected_manifest = f"release-ingress/{version}/{EVIDENCE_INGRESS_MANIFEST}"
        expected_sidecars = [
            f"release-ingress/{version}/{sidecar}"
            for sidecar in EVIDENCE_INGRESS_SIGNATURE_SIDECARS
        ]
        manifest_records = preflight_records_by_path.get(expected_manifest, [])
        if len(manifest_records) != 1:
            failures.append(
                "$.files: release-candidate and production-candidate profiles must include exactly one "
                f"operator evidence ingress manifest record at {expected_manifest}"
            )
        for sidecar in expected_sidecars:
            sidecar_records = preflight_records_by_path.get(sidecar, [])
            if len(sidecar_records) != 1:
                failures.append(
                    "$.files: release-candidate and production-candidate profiles must include exactly one "
                    f"operator evidence ingress signature sidecar record at {sidecar}"
                )
        if input_root is None:
            failures.append(
                "release-candidate and production-candidate profiles require --input-root to validate "
                "operator evidence ingress"
            )
        elif len(manifest_records) == 1:
            failures.extend(
                validate_operator_evidence_ingress(
                    manifest=manifest,
                    input_root=input_root,
                    require_signature=require_evidence_ingress_signature,
                    certificate_identity=evidence_ingress_certificate_identity,
                    certificate_oidc_issuer=evidence_ingress_certificate_oidc_issuer,
                )
            )
        if (
            manifest.get("profile") == "production-candidate"
            and input_root is not None
            and binding_manifest is not None
            and isinstance(binding, dict)
        ):
            graph_path = input_root / "release-subject-graph" / version / "release-subject-graph.json"
            if not graph_path.is_file() or graph_path.stat().st_size <= 0:
                failures.append(f"release ingress missing authoritative preflight subject graph: {graph_path}")
            else:
                try:
                    validate_inputs = load_validate_release_inputs_module()
                    matrix = validate_inputs.load_matrix(validate_inputs.DEFAULT_MATRIX)
                    failures.extend(
                        validate_inputs.validate_subject_graph(
                            graph_path,
                            version=version,
                            profile=str(manifest.get("profile")),
                            source_sha=str(manifest.get("source_sha")),
                            source_run_id=str(manifest.get("source_run_id")),
                            matrix=matrix,
                            binding=binding,
                            root=input_root,
                            check_files=True,
                        )
                    )
                except Exception as exc:
                    failures.append(f"release subject graph semantic replay failed: {exc}")
    if require_signature:
        failures.extend(verify_manifest_signature(manifest_path, certificate_identity, certificate_oidc_issuer))
    return failures


def create_command(args: argparse.Namespace) -> int:
    manifest, failures = create_manifest(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote release ingress manifest: {args.output}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    failures = validate_manifest(
        args.manifest,
        args.artifact_root,
        args.input_root,
        args.binding_manifest,
        args.expected_version,
        args.expected_source_sha,
        args.require_signature,
        args.certificate_identity,
        args.certificate_oidc_issuer,
        args.require_evidence_ingress_signature,
        args.evidence_ingress_certificate_identity,
        args.evidence_ingress_certificate_oidc_issuer,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated release ingress manifest: {args.manifest}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create an ingress manifest from a binding and artifacts")
    create.add_argument("--binding-manifest", type=Path, required=True)
    create.add_argument("--artifact-root", type=Path, required=True)
    create.add_argument("--input-root", type=Path)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--workflow", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", required=True)
    create.add_argument("--actor", required=True)
    create.add_argument("--expires-days", type=int, default=30)
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate", help="validate an ingress manifest")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--artifact-root", type=Path)
    validate.add_argument("--input-root", type=Path)
    validate.add_argument("--binding-manifest", type=Path)
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-source-sha")
    validate.add_argument("--require-signature", action="store_true")
    validate.add_argument("--certificate-identity")
    validate.add_argument("--certificate-oidc-issuer")
    validate.add_argument("--require-evidence-ingress-signature", action="store_true")
    validate.add_argument("--evidence-ingress-certificate-identity")
    validate.add_argument("--evidence-ingress-certificate-oidc-issuer")
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
