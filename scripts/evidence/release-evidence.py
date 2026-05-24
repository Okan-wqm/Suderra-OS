#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Generate and validate Suderra OS release evidence bundles.

The evidence contract intentionally uses only JSON plus Python's standard
library. A release bundle is rooted at:

    <evidence-root>/<version>/<target>/evidence.json

The validator checks the schema on every run and can also enforce the stricter
"ready for release" invariants with --require-pass.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.release-evidence.v5"
LEGACY_SCHEMA_VERSIONS = {"suderra.release-evidence.v2", "suderra.release-evidence.v3", "suderra.release-evidence.v4"}
ASSET_MANIFEST_SCHEMA_VERSION = "suderra.release-assets.v1"
APPROVAL_SCHEMA_VERSION = "suderra.release-approval.v2"

TOP_LEVEL_FIELDS = {
    "schema_version",
    "version",
    "target",
    "generated_at",
    "target_contract",
    "source",
    "asset_manifest",
    "artifacts",
    "sbom",
    "vex",
    "reproducibility",
    "security_scans",
    "machine_verification",
    "build_evidence",
    "preflight_inputs",
    "governance",
    "qemu",
    "runtime_qemu",
    "hardware",
    "station_acquisitions",
    "hsm_signing_sessions",
    "release_image_scan_reports",
    "runtime_checks",
    "approvals",
    "residual_risk",
    "release_decision",
}

TARGET_CONTRACT_FIELDS = {
    "defconfig",
    "target",
    "arch",
    "artifact",
    "release_artifact",
    "profile",
    "boot_mode",
    "partition_table",
    "root_partition",
    "root_identity",
    "signing",
    "acceptance",
    "production_required",
    "production_ready",
}

STATUS_VALUES = {"passed", "failed", "not_run", "not_applicable", "not_collected"}
FAILURE_CLASS_VALUES = {"none", "timeout", "infra_error", "semantic_failure", "security_failure", "operator_error"}
VEX_STATUS_VALUES = {"present", "not_applicable", "not_collected"}
RISK_STATUS_VALUES = {"none", "accepted", "blocked"}
DECISION_STATUS_VALUES = {"approved", "approved_with_residual_risk", "blocked"}
MACHINE_VERIFICATION_CHECKS = ("sha256sums", "cosign", "attestations")
MACHINE_VERIFICATION_SCHEMA_VERSION = "suderra.machine-verification.v3"
LEGACY_MACHINE_VERIFICATION_SCHEMA_VERSIONS = {"suderra.machine-verification.v2"}
GOVERNANCE_CHECKS = (
    "policy_validation",
    "snapshot_manifest",
    "repo",
    "branch_protection",
    "rulesets",
    "release_sign_environment",
    "release_sign_environment_deployment_policy",
    "release_environment",
    "release_environment_deployment_policy",
    "workflow_permissions",
    "codeowners",
    "audit_log",
)
REQUIRED_RUNTIME_CHECKS = (
    "secure_boot",
    "dm_verity",
    "dm_verity_tamper",
    "rauc_good_update",
    "rauc_bad_signature",
    "rauc_health_rollback",
    "anti_rollback",
    "data_luks",
    "lockdown",
    "nmap",
    "systemd_security",
)
REQUIRED_QEMU_CHECKS = (
    "boot",
    "systemd",
    "zero-failed-units",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
)
REQUIRED_HARDWARE_CHECKS = (
    "board-identity",
    "artifact-hash",
    "flash-transcript",
    "full-readback-hash",
    "serial-boot-log",
    "post-install-boot",
    "partitions",
    "root-data-mounts",
    "network",
    "listeners",
    "failed-units",
    "thermal",
    "watchdog",
)
REQUIRED_HARDWARE_BOARDS_BY_TARGET = {
    "rpi4": ("raspberry-pi-4-model-b", "cm4-lite-sd", "cm4-emmc-io-board"),
    "pi-cm4-revpi-usb-installer": (
        "raspberry-pi-4-model-b",
        "cm4-lite-sd",
        "cm4-emmc-io-board",
        "revpi-connect-4",
    ),
    "revpi4": ("revpi-connect-4",),
}
ALLOWED_RELEASE_ASSET_ROLES = {
    "release-image",
    "checksum",
    "manifest",
    "payload-signature",
    "sbom",
    "signature",
    "certificate",
    "installer",
    "release-control",
    "attestation",
    "evidence",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class Validation:
    def __init__(self, evidence_path: Path, check_files: bool) -> None:
        self.evidence_path = evidence_path
        self.evidence_dir = evidence_path.parent
        self.check_files = check_files
        self.errors: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line.rstrip()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def parse_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"expected key/value entry: {text!r}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def load_matrix(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"defconfigs": [], "variants": [], "security_scans": []}
    section: str | None = None
    current: dict[str, Any] | None = None
    pending_key: str | None = None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()

        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            data.setdefault(section, [])
            current = None
            pending_key = None
            continue

        if section in {"defconfigs", "variants"}:
            if indent == 2 and text.startswith("- "):
                current = {}
                data[section].append(current)
                rest = text[2:].strip()
                if rest:
                    key, value = parse_key_value(rest)
                    current[key] = parse_scalar(value)
                pending_key = None
                continue
            if indent == 4 and current is not None:
                key, value = parse_key_value(text)
                if value:
                    current[key] = parse_scalar(value)
                    pending_key = None
                else:
                    current[key] = []
                    pending_key = key
                continue
            if indent == 6 and text.startswith("- ") and current is not None and pending_key:
                current[pending_key].append(parse_scalar(text[2:].strip()))
                continue

        if section == "security_scans" and indent == 2 and text.startswith("- "):
            data[section].append(parse_scalar(text[2:].strip()))
            continue

        raise ValueError(f"unsupported YAML subset at {path}:{lineno}: {raw}")

    return data


def targets_by_id(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for entry in matrix.get("defconfigs", []):
        target = str(entry.get("target", ""))
        if target:
            targets[target] = entry
        name = str(entry.get("name", ""))
        if name:
            targets.setdefault(name, entry)
    return targets


def git_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def release_base(release_artifact: str) -> str:
    if release_artifact.endswith(".img.xz"):
        return release_artifact[: -len(".img.xz")]
    return release_artifact[:-3] if release_artifact.endswith(".xz") else release_artifact


def contract_from_matrix(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "defconfig": row["name"],
        "target": row["target"],
        "arch": row["arch"],
        "artifact": row["artifact"],
        "release_artifact": row["release_artifact"],
        "profile": row["profile"],
        "boot_mode": row["boot_mode"],
        "partition_table": row["partition_table"],
        "root_partition": row["root_partition"],
        "root_identity": row["root_identity"],
        "signing": row["signing"],
        "acceptance": row["acceptance"],
        "production_required": row["production_required"],
        "production_ready": row["production_ready"],
    }


def generated_evidence(version: str, row: dict[str, Any], security_scans: list[str]) -> dict[str, Any]:
    contract = contract_from_matrix(row)
    release_artifact = str(contract["release_artifact"])
    base = release_base(release_artifact)
    acceptance = str(contract["acceptance"])
    production_required = bool(contract["production_required"])
    qemu_required = bool(row.get("qemu_test", False))
    hardware_required = production_required or "hardware" in acceptance
    dirty = bool(git_output(["status", "--porcelain"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "target": contract["target"],
        "generated_at": now_utc(),
        "target_contract": contract,
        "source": {
            "repository": git_output(["config", "--get", "remote.origin.url"]) or "unknown",
            "git_commit": git_output(["rev-parse", "HEAD"]) or "unknown",
            "git_tag": version,
            "dirty": dirty,
            "ci": {
                "provider": "github-actions",
                "workflow": "release",
                "run_id": "not_collected",
                "run_attempt": "not_collected",
            },
        },
        "asset_manifest": {
            "path": "release-assets.json",
            "sha256": None,
            "verified": False,
        },
        "artifacts": [
            {
                "name": release_artifact,
                "role": "release-image",
                "path": f"artifacts/{release_artifact}",
                "sha256": None,
                "bytes": None,
                "signature": {
                    "path": f"artifacts/{release_artifact}.sig",
                    "certificate": f"artifacts/{release_artifact}.cert",
                    "verified": False,
                },
                "provenance": {
                    "path": f"provenance/{release_artifact}.intoto.jsonl",
                    "verified": False,
                },
            }
        ],
        "sbom": {
            "format": "cyclonedx-json",
            "path": f"sbom/{base}.cyclonedx.json",
            "sha256": None,
            "component_count": None,
            "signature_verified": False,
        },
        "vex": {
            "status": "not_collected",
            "path": None,
            "sha256": None,
            "signature_verified": False,
        },
        "reproducibility": {
            "status": "not_run",
            "comparison": None,
            "logs": [],
        },
        "security_scans": [
            {"name": str(name), "status": "not_run", "report": None} for name in security_scans
        ],
        "machine_verification": {
            name: {"status": "not_run", "logs": [], "record": None} for name in MACHINE_VERIFICATION_CHECKS
        },
        "build_evidence": {
            "status": "not_collected",
            "logs": [],
            "warnings": [],
            "source_identity": [],
        },
        "preflight_inputs": {
            "approval": None,
            "reproducibility": None,
            "security_reports": [],
            "security_raw_evidence": [],
            "qemu": None,
            "lab": None,
        },
        "governance": {
            "retention_years": 7,
            "approval_model": "enterprise-two-role",
            "checks": {
                name: {"status": "not_collected", "evidence": None}
                for name in GOVERNANCE_CHECKS
            },
        },
        "qemu": {
            "required": qemu_required,
            "status": "not_run" if qemu_required else "not_applicable",
            "logs": [],
            "checks": [],
        },
        "runtime_qemu": {
            "required": production_required,
            "status": "not_run" if production_required else "not_applicable",
            "production_suites": [],
        },
        "hardware": {
            "required": hardware_required,
            "status": "not_run" if hardware_required else "not_applicable",
            "devices": [],
        },
        "station_acquisitions": [],
        "hsm_signing_sessions": [],
        "release_image_scan_reports": [],
        "runtime_checks": {
            name: {
                "required": production_required,
                "status": "not_run" if production_required else "not_applicable",
                "evidence": None,
            }
            for name in REQUIRED_RUNTIME_CHECKS
        },
        "approvals": [],
        "residual_risk": {
            "status": "none",
            "items": [],
            "accepted_by": None,
            "accepted_at": None,
            "expires_at": None,
        },
        "release_decision": {
            "status": "blocked",
            "decided_by": None,
            "decided_at": None,
            "rationale": "Evidence has not been reviewed.",
        },
    }


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_string(validation: Validation, path: str, value: Any) -> None:
    if not is_non_empty_string(value):
        validation.error(path, "must be a non-empty string")


def check_bool(validation: Validation, path: str, value: Any) -> None:
    if not isinstance(value, bool):
        validation.error(path, "must be true or false")


def check_status(validation: Validation, path: str, value: Any, allowed: set[str]) -> None:
    if value not in allowed:
        validation.error(path, f"must be one of: {', '.join(sorted(allowed))}")


def normalize_release_status(value: Any) -> str:
    if value == "passed":
        return "passed"
    if value in {"failed", "timeout", "infra-error", "infra_error"}:
        return "failed"
    if value in {"not-applicable", "not_applicable"}:
        return "not_applicable"
    if value in STATUS_VALUES:
        return str(value)
    return "not_collected"


def check_sha256(validation: Validation, path: str, value: Any, required: bool) -> None:
    if value is None and not required:
        return
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        validation.error(path, "must be a lowercase sha256 hex digest")


def check_positive_int(validation: Validation, path: str, value: Any, required: bool) -> None:
    if value is None and not required:
        return
    if not isinstance(value, int) or value <= 0:
        validation.error(path, "must be a positive integer")


def check_relative_path(validation: Validation, path: str, value: Any, required: bool) -> Path | None:
    if value is None and not required:
        return None
    if not is_non_empty_string(value):
        validation.error(path, "must be a relative path")
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        validation.error(path, "must be relative and must not contain '..'")
        return None
    actual = validation.evidence_dir / rel
    if validation.check_files:
        if not actual.is_file():
            validation.error(path, f"referenced file is missing: {value}")
            return None
        if actual.stat().st_size <= 0:
            validation.error(path, f"referenced file is empty: {value}")
            return None
    return actual


def file_for_relative_path(validation: Validation, value: Any) -> Path | None:
    if not validation.check_files or not is_non_empty_string(value):
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    actual = validation.evidence_dir / rel
    if not actual.is_file():
        return None
    return actual


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def matrix_digest(path: Path = DEFAULT_MATRIX) -> str:
    return sha256_file(path)


def buildroot_index_sha() -> str:
    return git_output(["ls-tree", "HEAD", "buildroot"]) or "unknown"


def buildroot_source_metadata(source_sha: str) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
    spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
    if spec is None or spec.loader is None:
        return {"buildroot_index_sha": buildroot_index_sha()}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.metadata(source_sha)
    except Exception:
        return {"buildroot_index_sha": buildroot_index_sha()}


def buildroot_metadata_for_manifest(identity: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if "schema_version" in identity:
        output["buildroot_source_identity_schema_version"] = identity.get("schema_version")
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


def buildroot_metadata_from_release_binding(binding: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if "buildroot_source_identity_schema_version" in binding:
        output["buildroot_source_identity_schema_version"] = binding.get("buildroot_source_identity_schema_version")
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
            output[field] = binding.get(field)
    return output


def load_script_module(name: str, rel_path: str) -> Any:
    script = ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tracked_source_dirty() -> bool:
    status = git_output(["status", "--porcelain", "--untracked-files=no"])
    return bool(status)


def classify_release_asset(name: str) -> str:
    if name.endswith(".img.xz"):
        return "release-image"
    if name.endswith(".sha256") or name == "SHA256SUMS":
        return "checksum"
    if name.endswith(".manifest.txt") or name.endswith(".payload-manifest.json") or name == "manifest.json":
        return "manifest"
    if name.endswith(".payload-manifest.sig"):
        return "payload-signature"
    if name.endswith(".cyclonedx.json"):
        return "sbom"
    if name.endswith(".intoto.jsonl") or name.endswith(".attestation.json"):
        return "attestation"
    if name.startswith("release-evidence-") and (name.endswith(".tar.zst") or name.endswith(".tar.gz")):
        return "evidence"
    if name.endswith(".sig"):
        return "signature"
    if name.endswith(".cert"):
        return "certificate"
    if name.startswith("suderra-installer-"):
        return "installer"
    return "release-control"


def release_asset_manifest(
    version: str,
    release_dir: Path,
    matrix_path: Path,
    binding_manifest: Path | None = None,
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(release_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            continue
        files.append(
            {
                "name": path.name,
                "role": classify_release_asset(path.name),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    git_commit = git_output(["rev-parse", "HEAD"]) or "unknown"
    buildroot_metadata: dict[str, Any] = {}
    if binding_manifest is not None:
        binding = read_json(binding_manifest)
        if not isinstance(binding, dict):
            raise ValueError(f"binding manifest is missing or invalid JSON: {binding_manifest}")
        buildroot_metadata = buildroot_metadata_from_release_binding(binding)
    elif re.fullmatch(r"[0-9a-f]{40}", git_commit):
        buildroot_metadata = buildroot_metadata_for_manifest(buildroot_source_metadata(git_commit))
    return {
        "schema_version": ASSET_MANIFEST_SCHEMA_VERSION,
        "version": version,
        "generated_at": now_utc(),
        "source": {
            "repository": git_output(["config", "--get", "remote.origin.url"]) or "unknown",
            "git_commit": git_commit,
            "git_tag": version,
            "dirty": tracked_source_dirty(),
            "ci": {
                "provider": "github-actions",
                "workflow": os.environ.get("GITHUB_WORKFLOW", "release"),
                "run_id": os.environ.get("GITHUB_RUN_ID", "not_collected"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "not_collected"),
            },
        },
        "matrix_sha256": matrix_digest(matrix_path),
        **buildroot_metadata,
        "files": files,
    }


def copy_into_bundle(bundle_dir: Path, source: Path, rel: str) -> str:
    destination = bundle_dir / rel
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return rel


def copy_input_relative(bundle_dir: Path, source_root: Path, rel: str, dest_root: str) -> str | None:
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        return None
    source = source_root / rel_path
    if not source.is_file():
        return None
    return copy_into_bundle(bundle_dir, source, str(Path(dest_root) / rel_path))


def count_cyclonedx_components(path: Path) -> int | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    components = payload.get("components")
    return len(components) if isinstance(components, list) else None


def read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def machine_record_covers_subject(record_path: Path, *, name: str, sha256: str) -> bool:
    payload = read_json(record_path)
    if not isinstance(payload, dict):
        return False
    subjects = payload.get("verified_subjects") if payload.get("name") == "attestations" else payload.get("subjects")
    if not isinstance(subjects, list):
        return False
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        if subject.get("name") == name and subject.get("sha256") == sha256:
            return True
    return False


def apply_machine_verification(bundle_dir: Path, release_dir: Path, evidence: dict[str, Any]) -> None:
    try:
        verifier = load_script_module(
            "machine_verification_record",
            "scripts/evidence/machine-verification-record.py",
        )
    except Exception:
        verifier = None
    for name in MACHINE_VERIFICATION_CHECKS:
        source = release_dir / "machine-verification" / f"{name}.log"
        record_source = release_dir / "machine-verification" / f"{name}.json"
        record_payload = read_json(record_source)
        record_valid = False
        if verifier is not None and isinstance(record_payload, dict):
            record_valid = verifier.validate_record(record_payload, expected_name=name) == []
        if source.is_file() and source.stat().st_size > 0 and record_source.is_file() and record_valid:
            record_rel = copy_into_bundle(
                bundle_dir,
                record_source,
                f"machine-verification/{name}.json",
            )
            material_refs: list[dict[str, Any]] = []
            material = record_payload.get("verification_material") if isinstance(record_payload, dict) else None
            if name == "attestations" and isinstance(material, dict):
                files = material.get("files")
                if isinstance(files, list):
                    for item in files:
                        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                            continue
                        source_json = release_dir / "machine-verification" / "attestations" / Path(item["path"]).name
                        if not source_json.is_file() or source_json.stat().st_size <= 0:
                            continue
                        rel = copy_into_bundle(
                            bundle_dir,
                            source_json,
                            f"machine-verification/attestations/{source_json.name}",
                        )
                        material_refs.append(
                            {
                                "path": rel,
                                "sha256": sha256_file(bundle_dir / rel),
                                "bytes": (bundle_dir / rel).stat().st_size,
                            }
                        )
            evidence["machine_verification"][name] = {
                "status": "passed",
                "logs": [copy_into_bundle(bundle_dir, source, f"machine-verification/{name}.log")],
                "record": {
                    "path": record_rel,
                    "sha256": sha256_file(bundle_dir / record_rel),
                    "bytes": (bundle_dir / record_rel).stat().st_size,
                },
            }
            if material_refs:
                evidence["machine_verification"][name]["materials"] = material_refs


def apply_build_evidence(bundle_dir: Path, input_root: Path, version: str, target: str, evidence: dict[str, Any]) -> None:
    profile = "release-candidate" if "-" in version else "production-candidate"
    binding = read_json(input_root / "release-inputs" / version / f"{profile}.json")
    if not isinstance(binding, dict):
        binding = read_json(input_root / "release-inputs" / version / "release-candidate.json")
    if not isinstance(binding, dict):
        return
    records = {"logs": [], "warnings": [], "source_identity": []}
    for item in binding.get("build_evidence", []):
        if not isinstance(item, dict) or item.get("target") != target:
            continue
        rel = item.get("path")
        if not isinstance(rel, str):
            continue
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            continue
        source = input_root / "build-artifacts" / rel_path
        if not source.is_file() or source.stat().st_size <= 0:
            continue
        role = item.get("role")
        destination = f"build/{Path(rel).name}"
        copied = copy_into_bundle(bundle_dir, source, destination)
        record = {
            "path": copied,
            "sha256": sha256_file(bundle_dir / copied),
            "bytes": (bundle_dir / copied).stat().st_size,
        }
        if isinstance(item.get("sha256"), str):
            record["ingress_sha256"] = item["sha256"]
        if role == "warning-classifier-evidence":
            records["warnings"].append(record)
        elif role == "buildroot-source-identity":
            records["source_identity"].append(record)
        else:
            records["logs"].append(record)
    if records["logs"] or records["warnings"] or records["source_identity"]:
        evidence["build_evidence"] = {
            "status": "passed",
            "logs": records["logs"],
            "warnings": records["warnings"],
            "source_identity": records["source_identity"],
        }


def apply_governance(bundle_dir: Path, governance_root: Path, version: str, evidence: dict[str, Any]) -> None:
    mapping = {
        "policy_validation": "governance-policy-validation.json",
        "snapshot_manifest": "snapshot-manifest.json",
        "repo": "repo.json",
        "branch_protection": "main-branch-protection.json",
        "rulesets": "rulesets.json",
        "release_sign_environment": "release-sign-environment.json",
        "release_sign_environment_deployment_policy": "release-sign-deployment-branch-policies.json",
        "release_environment": "release-publish-environment.json",
        "release_environment_deployment_policy": "release-publish-deployment-branch-policies.json",
        "workflow_permissions": "workflow-permissions.json",
        "codeowners": "codeowners.json",
        "audit_log": "audit-log.json",
    }
    for name, filename in mapping.items():
        source = governance_root / version / filename
        if source.is_file() and source.stat().st_size > 0:
            evidence["governance"]["checks"][name] = {
                "status": "passed",
                "evidence": copy_into_bundle(bundle_dir, source, f"governance/{filename}"),
            }


def apply_qemu_input(bundle_dir: Path, lab_root: Path, version: str, target: str, evidence: dict[str, Any]) -> None:
    qemu_input = read_json(lab_root / version / target / "qemu.json")
    if not isinstance(qemu_input, dict):
        return
    logs = []
    qemu_dir = lab_root / version / target
    input_copy = copy_into_bundle(bundle_dir, qemu_dir / "qemu.json", "qemu/input/qemu.json")
    evidence["preflight_inputs"]["qemu"] = {
        "path": input_copy,
        "sha256": sha256_file(bundle_dir / input_copy),
        "bytes": (bundle_dir / input_copy).stat().st_size,
    }
    for idx, log in enumerate(qemu_input.get("logs", [])):
        role = None
        expected_sha = None
        if isinstance(log, str):
            log_path = log
        elif isinstance(log, dict) and isinstance(log.get("path"), str):
            log_path = log["path"]
            role = log.get("role") if isinstance(log.get("role"), str) else None
            expected_sha = log.get("sha256") if isinstance(log.get("sha256"), str) else None
        else:
            continue
        source = qemu_dir / log_path
        copy_input_relative(bundle_dir, qemu_dir, log_path, "qemu/input")
        if source.is_file():
            copied = copy_into_bundle(bundle_dir, source, f"qemu/{idx}-{Path(log_path).name}")
            copied_path = bundle_dir / copied
            record: dict[str, Any] = {
                "path": copied,
                "sha256": sha256_file(copied_path),
                "bytes": copied_path.stat().st_size,
            }
            if role is not None:
                record["role"] = role
            if expected_sha is not None:
                record["input_sha256"] = expected_sha
            logs.append(record)
    checks = qemu_input.get("checks")
    semantic_checks = checks if isinstance(checks, dict) else {}
    if isinstance(checks, dict):
        checks = [
            str(name)
            for name, result in checks.items()
            if isinstance(result, dict) and result.get("status") == "passed"
        ]
    execution_fields = (
        "schema_version",
        "profile",
        "started_at",
        "completed_at",
        "timeout_seconds",
        "qemu_exit_status",
        "qemu_args",
        "termination",
        "failure_class",
        "result",
        "error",
    )
    execution = {
        field: qemu_input.get(field)
        for field in execution_fields
        if field in qemu_input
    }
    evidence["qemu"] = {
        "required": True,
        "status": normalize_release_status(qemu_input.get("status", "not_collected")),
        "failure_class": qemu_input.get("failure_class", "none" if qemu_input.get("status") == "passed" else "semantic_failure"),
        "validation_profile": qemu_input.get("profile"),
        "input": {
            "path": input_copy,
            "sha256": sha256_file(bundle_dir / input_copy),
            "bytes": (bundle_dir / input_copy).stat().st_size,
        },
        "image": qemu_input.get("image"),
        "image_sha256": qemu_input.get("image_sha256"),
        "firmware": qemu_input.get("firmware"),
        "firmware_sha256": qemu_input.get("firmware_sha256"),
        "logs": logs,
        "checks": checks if isinstance(checks, list) else [],
        "check_details": semantic_checks,
        "semantic_checks": semantic_checks,
        "execution": execution,
        "guest_facts": qemu_input.get("guest_facts", {}),
    }


def apply_hardware_input(
    bundle_dir: Path,
    lab_root: Path,
    governance_root: Path,
    version: str,
    target: str,
    evidence: dict[str, Any],
) -> None:
    lab_dir = lab_root / version / target
    lab_input = read_json(lab_dir / "lab.json")
    if not isinstance(lab_input, dict):
        return
    input_copy = copy_into_bundle(bundle_dir, lab_dir / "lab.json", "hardware/input/lab.json")
    evidence["preflight_inputs"]["lab"] = {
        "path": input_copy,
        "sha256": sha256_file(bundle_dir / input_copy),
        "bytes": (bundle_dir / input_copy).stat().st_size,
    }
    evidence["hardware"]["input"] = {
        "path": input_copy,
        "sha256": sha256_file(bundle_dir / input_copy),
        "bytes": (bundle_dir / input_copy).stat().st_size,
    }
    if isinstance(lab_input.get("station"), dict):
        evidence["hardware"]["station"] = lab_input["station"]
    if isinstance(lab_input.get("artifact_binding"), dict):
        evidence["hardware"]["artifact_binding"] = lab_input["artifact_binding"]
    registry_source = governance_root / version / "station-registry.json"
    registry_source_domain = "release-governance"
    if not registry_source.is_file():
        registry_source = lab_root / "station-registry.json"
        registry_source_domain = "release-lab-input"
    if registry_source.is_file():
        registry_rel = copy_into_bundle(bundle_dir, registry_source, "hardware/input/station-registry.json")
        evidence["hardware"]["station_registry"] = {
            "path": registry_rel,
            "sha256": sha256_file(bundle_dir / registry_rel),
            "bytes": (bundle_dir / registry_rel).stat().st_size,
            "source_domain": registry_source_domain,
        }
    if isinstance(lab_input.get("station_bundle"), dict):
        station_bundle = dict(lab_input["station_bundle"])
        bundle_path = station_bundle.get("path")
        if isinstance(bundle_path, str):
            copied = copy_input_relative(bundle_dir, lab_dir, bundle_path, "hardware/input")
            if copied is not None:
                station_bundle["path"] = copied
        evidence["hardware"]["station_bundle"] = station_bundle
    if isinstance(lab_input.get("station_signature"), dict):
        station_signature = dict(lab_input["station_signature"])
        for field in ("signature", "public_key"):
            rel_path = station_signature.get(field)
            if isinstance(rel_path, str):
                copied = copy_input_relative(bundle_dir, lab_dir, rel_path, "hardware/input")
                if copied is not None:
                    station_signature[field] = copied
        evidence["hardware"]["station_signature"] = station_signature
    devices = []
    for device in lab_input.get("devices", []):
        if not isinstance(device, dict):
            continue
        board = str(device.get("board", "unknown"))
        logs = []
        for idx, log in enumerate(device.get("logs", [])):
            if isinstance(log, str):
                log_path = log
                expected_sha = None
            elif isinstance(log, dict) and isinstance(log.get("path"), str):
                log_path = log["path"]
                expected_sha = log.get("sha256") if isinstance(log.get("sha256"), str) else None
            else:
                continue
            source = lab_dir / log_path
            copy_input_relative(bundle_dir, lab_dir, log_path, "hardware/input")
            if source.is_file() and source.stat().st_size > 0:
                rel_log = copy_into_bundle(bundle_dir, source, f"hardware/{board}/logs/{idx}-{Path(log_path).name}")
                log_record = {"path": rel_log, "sha256": sha256_file(bundle_dir / rel_log)}
                if expected_sha is not None:
                    log_record["input_sha256"] = expected_sha
                logs.append(log_record)
        checks: dict[str, dict[str, Any]] = {}
        raw_checks = device.get("checks", {})
        if isinstance(raw_checks, dict):
            for check_name, check in raw_checks.items():
                if not isinstance(check, dict):
                    continue
                rel_evidence = None
                evidence_path = check.get("evidence")
                if isinstance(evidence_path, str):
                    source = lab_dir / evidence_path
                    copy_input_relative(bundle_dir, lab_dir, evidence_path, "hardware/input")
                    if source.is_file() and source.stat().st_size > 0:
                        rel_evidence = copy_into_bundle(
                            bundle_dir,
                            source,
                            f"hardware/{board}/checks/{check_name}-{Path(evidence_path).name}",
                        )
                check_record = {
                    "status": check.get("status", "not_collected"),
                    "evidence": rel_evidence,
                }
                if rel_evidence is not None:
                    check_record["evidence_sha256"] = sha256_file(bundle_dir / rel_evidence)
                for field in ("command", "expected", "observed", "parsed_result"):
                    if isinstance(check.get(field), str):
                        check_record[field] = check[field]
                checks[str(check_name)] = check_record
        devices.append(
            {
                "board": board,
                "serial": device.get("serial", "not_collected"),
                "sku": device.get("sku", "not_collected"),
                "storage_serial": device.get("storage_serial", "not_collected"),
                "uart_adapter": device.get("uart_adapter", "not_collected"),
                "power_supply": device.get("power_supply", "not_collected"),
                "boot_firmware": device.get("boot_firmware", "not_collected"),
                "tested_at": device.get("tested_at", "not_collected"),
                "operator": device.get("operator", lab_input.get("operator", "not_collected")),
                "status": device.get("status", "not_collected"),
                "logs": logs,
                "checks": checks,
                "device_identity": device.get("device_identity") if isinstance(device.get("device_identity"), dict) else {},
                "readback": device.get("readback") if isinstance(device.get("readback"), dict) else {},
            }
        )
    evidence["hardware"]["devices"] = devices
    negative_tests = []
    for item in lab_input.get("negative_tests", []):
        if not isinstance(item, dict):
            continue
        evidence_path = item.get("evidence")
        rel_evidence = None
        if isinstance(evidence_path, str):
            source = lab_dir / evidence_path
            copy_input_relative(bundle_dir, lab_dir, evidence_path, "hardware/input")
            if source.is_file() and source.stat().st_size > 0:
                rel_evidence = copy_into_bundle(
                    bundle_dir,
                    source,
                    f"hardware/negative-tests/{Path(evidence_path).name}",
                )
        negative_test = {
            "name": item.get("name", "unknown"),
            "failure_code": item.get("failure_code", "not_collected"),
            "status": item.get("status", "not_collected"),
            "evidence": rel_evidence,
        }
        if rel_evidence is not None:
            negative_test["evidence_sha256"] = sha256_file(bundle_dir / rel_evidence)
        if isinstance(item.get("write_prevention"), dict):
            negative_test["write_prevention"] = item["write_prevention"]
        negative_tests.append(negative_test)
    if negative_tests:
        evidence["hardware"]["negative_tests"] = negative_tests
    if devices and all(device.get("status") == "passed" for device in devices):
        evidence["hardware"]["status"] = "passed"


def apply_release_inputs(
    bundle_dir: Path,
    release_dir: Path,
    input_root: Path,
    version: str,
    target: str,
    evidence: dict[str, Any],
) -> None:
    repro = input_root / "release-reproducibility" / version / f"{target}.json"
    if repro.is_file() and repro.stat().st_size > 0:
        repro_payload = read_json(repro)
        rel_repro = copy_into_bundle(bundle_dir, repro, "preflight/reproducibility/reproducibility.json")
        evidence["preflight_inputs"]["reproducibility"] = {
            "path": rel_repro,
            "sha256": sha256_file(bundle_dir / rel_repro),
            "bytes": (bundle_dir / rel_repro).stat().st_size,
        }
        evidence["reproducibility"] = {
            "status": repro_payload.get("status") if isinstance(repro_payload, dict) else "failed",
            "comparison": repro_payload.get("comparison") if isinstance(repro_payload, dict) else "invalid input",
            "logs": [rel_repro],
        }
    for scan in evidence["security_scans"]:
        report = input_root / "release-security" / version / f"{scan['name']}.json"
        if report.is_file() and report.stat().st_size > 0:
            report_payload = read_json(report)
            scan["status"] = "passed"
            rel_report = copy_into_bundle(bundle_dir, report, f"preflight/security/{report.name}")
            scan["report"] = rel_report
            evidence["preflight_inputs"]["security_reports"].append(
                {
                    "name": scan["name"],
                    "path": rel_report,
                    "sha256": sha256_file(bundle_dir / rel_report),
                    "bytes": (bundle_dir / rel_report).stat().st_size,
                }
            )
            if isinstance(report_payload, dict):
                if report_payload.get("schema_version") == "suderra.release-security-report.v2":
                    evidence["release_image_scan_reports"].append(
                        {
                            "name": scan["name"],
                            "path": rel_report,
                            "sha256": sha256_file(bundle_dir / rel_report),
                            "bytes": (bundle_dir / rel_report).stat().st_size,
                        }
                    )
                evidence_path = report_payload.get("evidence_path")
                evidence_sha = report_payload.get("evidence_sha256")
                evidence_bytes = report_payload.get("evidence_bytes")
                if isinstance(evidence_path, str) and not Path(evidence_path).is_absolute() and ".." not in Path(evidence_path).parts:
                    raw_source = input_root / "release-security" / evidence_path
                    if raw_source.is_file() and raw_source.stat().st_size > 0:
                        raw_rel = copy_into_bundle(
                            bundle_dir,
                            raw_source,
                            f"preflight/security/raw/{sha256_file(raw_source)}-{Path(evidence_path).name}",
                        )
                        raw_record = {
                            "name": scan["name"],
                            "source_path": evidence_path,
                            "path": raw_rel,
                            "sha256": sha256_file(bundle_dir / raw_rel),
                            "bytes": (bundle_dir / raw_rel).stat().st_size,
                        }
                        if isinstance(evidence_sha, str):
                            raw_record["report_sha256"] = evidence_sha
                        if isinstance(evidence_bytes, int):
                            raw_record["report_bytes"] = evidence_bytes
                        raw_items = evidence["preflight_inputs"]["security_raw_evidence"]
                        if not any(
                            isinstance(item, dict)
                            and item.get("sha256") == raw_record["sha256"]
                            and item.get("source_path") == raw_record["source_path"]
                            for item in raw_items
                        ):
                            raw_items.append(raw_record)
                raw = report_payload.get("raw")
                if isinstance(raw, dict):
                    raw_path_value = raw.get("path")
                    raw_sha = raw.get("sha256")
                    raw_bytes = raw.get("bytes")
                    if isinstance(raw_path_value, str) and not Path(raw_path_value).is_absolute() and ".." not in Path(raw_path_value).parts:
                        raw_source = input_root / "release-security" / raw_path_value
                        if raw_source.is_file() and raw_source.stat().st_size > 0:
                            raw_rel = copy_into_bundle(
                                bundle_dir,
                                raw_source,
                                f"preflight/security/raw/{sha256_file(raw_source)}-{Path(raw_path_value).name}",
                            )
                            raw_record = {
                                "name": scan["name"],
                                "source_path": raw_path_value,
                                "path": raw_rel,
                                "sha256": sha256_file(bundle_dir / raw_rel),
                                "bytes": (bundle_dir / raw_rel).stat().st_size,
                            }
                            if isinstance(raw_sha, str):
                                raw_record["report_sha256"] = raw_sha
                            if isinstance(raw_bytes, int):
                                raw_record["report_bytes"] = raw_bytes
                            raw_items = evidence["preflight_inputs"]["security_raw_evidence"]
                            if not any(
                                isinstance(item, dict)
                                and item.get("sha256") == raw_record["sha256"]
                                and item.get("source_path") == raw_record["source_path"]
                                for item in raw_items
                            ):
                                raw_items.append(raw_record)
    runtime_suite = input_root / "release-runtime" / version / target / "production-runtime.json"
    if runtime_suite.is_file() and runtime_suite.stat().st_size > 0:
        rel_runtime = copy_into_bundle(bundle_dir, runtime_suite, "preflight/runtime/production-runtime.json")
        evidence["runtime_qemu"]["production_suites"].append(
            {
                "path": rel_runtime,
                "sha256": sha256_file(bundle_dir / rel_runtime),
                "bytes": (bundle_dir / rel_runtime).stat().st_size,
            }
        )
        runtime_payload = read_json(runtime_suite)
        if isinstance(runtime_payload, dict):
            for scenario in runtime_payload.get("scenarios", []) if isinstance(runtime_payload.get("scenarios"), list) else []:
                if not isinstance(scenario, dict):
                    continue
                for log in scenario.get("logs", []) if isinstance(scenario.get("logs"), list) else []:
                    if not isinstance(log, dict) or not isinstance(log.get("path"), str):
                        continue
                    rel_log = Path(log["path"])
                    if rel_log.is_absolute() or ".." in rel_log.parts:
                        continue
                    log_source = runtime_suite.parent / rel_log
                    if log_source.is_file():
                        copy_into_bundle(bundle_dir, log_source, str(Path("preflight/runtime") / rel_log))
            scenarios = runtime_payload.get("scenarios")
            if isinstance(scenarios, list) and all(isinstance(item, dict) and item.get("status") == "passed" for item in scenarios):
                evidence["runtime_qemu"]["status"] = "passed"
                scenario_to_runtime = {
                    "signed-boot": "secure_boot",
                    "dm-verity-rootfs-tamper-rejection": "dm_verity_tamper",
                    "rauc-good-update": "rauc_good_update",
                    "rauc-bad-signature-rejection": "rauc_bad_signature",
                    "rauc-health-rollback": "rauc_health_rollback",
                    "anti-rollback-downgrade-rejection": "anti_rollback",
                    "data-luks-swtpm": "data_luks",
                }
                for scenario in scenarios:
                    check_name = scenario_to_runtime.get(str(scenario.get("name")))
                    if check_name in evidence["runtime_checks"]:
                        evidence["runtime_checks"][check_name]["status"] = "passed"
                        evidence["runtime_checks"][check_name]["evidence"] = rel_runtime
    signing_root = input_root / "release-signing" / version / target
    if signing_root.is_dir():
        for session in sorted(signing_root.glob("*.json")):
            rel_session = copy_into_bundle(bundle_dir, session, f"preflight/signing/{session.name}")
            evidence["hsm_signing_sessions"].append(
                {
                    "path": rel_session,
                    "sha256": sha256_file(bundle_dir / rel_session),
                    "bytes": (bundle_dir / rel_session).stat().st_size,
                }
            )
    acquisition = input_root / "release-lab-input" / version / target / "station-acquisition.json"
    if acquisition.is_file() and acquisition.stat().st_size > 0:
        rel_acquisition = copy_into_bundle(bundle_dir, acquisition, "hardware/input/station-acquisition.json")
        acquisition_payload = read_json(acquisition)
        if isinstance(acquisition_payload, dict) and isinstance(acquisition_payload.get("events_root"), str):
            events_root = Path(acquisition_payload["events_root"])
            if not events_root.is_absolute() and ".." not in events_root.parts:
                source_events = acquisition.parent / events_root
                if source_events.is_dir():
                    for event_file in sorted(path for path in source_events.rglob("*") if path.is_file()):
                        event_rel = event_file.relative_to(acquisition.parent).as_posix()
                        copy_into_bundle(bundle_dir, event_file, str(Path("hardware/input") / event_rel))
        evidence["station_acquisitions"].append(
            {
                "path": rel_acquisition,
                "sha256": sha256_file(bundle_dir / rel_acquisition),
                "bytes": (bundle_dir / rel_acquisition).stat().st_size,
            }
        )
    approval_path = input_root / "release-approvals" / version / f"{target}.json"
    approvals = read_json(approval_path)
    if isinstance(approvals, dict):
        rel_approval = copy_into_bundle(bundle_dir, approval_path, "preflight/approval.json")
        evidence["preflight_inputs"]["approval"] = {
            "path": rel_approval,
            "sha256": sha256_file(bundle_dir / rel_approval),
            "bytes": (bundle_dir / rel_approval).stat().st_size,
        }
        if isinstance(approvals.get("approvals"), list):
            evidence["approvals"] = approvals["approvals"]
        if isinstance(approvals.get("residual_risk"), dict):
            evidence["residual_risk"] = approvals["residual_risk"]
        if isinstance(approvals.get("release_decision"), dict):
            evidence["release_decision"] = approvals["release_decision"]


def check_file_sha256(validation: Validation, path: str, rel: Any, expected: Any) -> None:
    if not validation.check_files or expected is None:
        return
    actual = file_for_relative_path(validation, rel)
    if actual is not None and sha256_file(actual) != expected:
        validation.error(path, "does not match referenced file sha256")


def check_file_size(validation: Validation, path: str, rel: Any, expected: Any) -> None:
    if not validation.check_files or expected is None:
        return
    actual = file_for_relative_path(validation, rel)
    if actual is not None and actual.stat().st_size != expected:
        validation.error(path, "does not match referenced file size")


def validate_asset_manifest(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    asset_manifest = evidence.get("asset_manifest")
    if not isinstance(asset_manifest, dict):
        validation.error("$.asset_manifest", "must be an object")
        return
    check_relative_path(validation, "$.asset_manifest.path", asset_manifest.get("path"), True)
    check_sha256(validation, "$.asset_manifest.sha256", asset_manifest.get("sha256"), require_pass)
    check_file_sha256(
        validation,
        "$.asset_manifest.sha256",
        asset_manifest.get("path"),
        asset_manifest.get("sha256"),
    )
    check_bool(validation, "$.asset_manifest.verified", asset_manifest.get("verified"))
    if require_pass and asset_manifest.get("verified") is not True:
        validation.error("$.asset_manifest.verified", "must be true for release-ready evidence")
    if validation.check_files:
        manifest_file = file_for_relative_path(validation, asset_manifest.get("path"))
        if manifest_file is not None:
            try:
                payload = json.loads(manifest_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                validation.error("$.asset_manifest.path", f"must be readable JSON: {exc}")
                return
            if payload.get("schema_version") != ASSET_MANIFEST_SCHEMA_VERSION:
                validation.error(
                    "$.asset_manifest.path",
                    f"schema_version must be {ASSET_MANIFEST_SCHEMA_VERSION}",
                )
            if payload.get("version") != evidence.get("version"):
                validation.error("$.asset_manifest.path", "version must match evidence.version")
            files = payload.get("files")
            if not isinstance(files, list) or not files:
                validation.error("$.asset_manifest.path", "files must be a non-empty list")
            else:
                seen_names: set[str] = set()
                manifest_by_name: dict[str, dict[str, Any]] = {}
                for idx, entry in enumerate(files):
                    entry_path = f"$.asset_manifest.files[{idx}]"
                    if not isinstance(entry, dict):
                        validation.error(entry_path, "must be an object")
                        continue
                    name = entry.get("name")
                    role = entry.get("role")
                    check_string(validation, f"{entry_path}.name", name)
                    check_string(validation, f"{entry_path}.role", role)
                    check_sha256(validation, f"{entry_path}.sha256", entry.get("sha256"), True)
                    check_positive_int(validation, f"{entry_path}.bytes", entry.get("bytes"), True)
                    if isinstance(role, str) and role not in ALLOWED_RELEASE_ASSET_ROLES:
                        validation.error(f"{entry_path}.role", f"must be one of: {', '.join(sorted(ALLOWED_RELEASE_ASSET_ROLES))}")
                    if isinstance(name, str):
                        if name in seen_names:
                            validation.error(f"{entry_path}.name", "must be unique within release-assets.json")
                        seen_names.add(name)
                        manifest_by_name[name] = entry
                expected_artifacts = {
                    artifact.get("name")
                    for artifact in evidence.get("artifacts", [])
                    if isinstance(artifact, dict)
                }
                manifest_artifacts = set(manifest_by_name)
                missing = sorted(str(name) for name in expected_artifacts - manifest_artifacts if name)
                if missing:
                    validation.error(
                        "$.asset_manifest.path",
                        f"missing release artifact subject(s): {', '.join(missing)}",
                    )
                for idx, artifact in enumerate(evidence.get("artifacts", [])):
                    if not isinstance(artifact, dict):
                        continue
                    name = artifact.get("name")
                    if not isinstance(name, str) or name not in manifest_by_name:
                        continue
                    manifest_entry = manifest_by_name[name]
                    if artifact.get("sha256") and manifest_entry.get("sha256") != artifact.get("sha256"):
                        validation.error(
                            f"$.artifacts[{idx}].sha256",
                            "does not match release-assets.json entry",
                        )
                    if artifact.get("bytes") and manifest_entry.get("bytes") != artifact.get("bytes"):
                        validation.error(
                            f"$.artifacts[{idx}].bytes",
                            "does not match release-assets.json entry",
                        )


def parse_timestamp(validation: Validation, path: str, value: Any, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not is_non_empty_string(value):
        validation.error(path, "must be an ISO-8601 UTC timestamp")
        return None
    text = value.strip()
    if not text.endswith("Z"):
        validation.error(path, "must use UTC Z suffix")
        return None
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        validation.error(path, "must be an ISO-8601 UTC timestamp")
        return None


def check_path_contract(validation: Validation, evidence: dict[str, Any]) -> None:
    parts = validation.evidence_path.as_posix().split("/")
    if len(parts) < 3 or parts[-1] != "evidence.json":
        validation.error(
            "$path",
            "must end with <version>/<target>/evidence.json",
        )
        return
    if parts[-3] != evidence.get("version"):
        validation.error("$path", "version directory must match evidence.version")
    if parts[-2] != evidence.get("target"):
        validation.error("$path", "target directory must match evidence.target")


def validate_artifacts(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        validation.error("$.artifacts", "must be a non-empty list")
        return

    for idx, artifact in enumerate(artifacts):
        path = f"$.artifacts[{idx}]"
        if not isinstance(artifact, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("name", "role"):
            check_string(validation, f"{path}.{field}", artifact.get(field))
        check_relative_path(validation, f"{path}.path", artifact.get("path"), True)
        check_sha256(validation, f"{path}.sha256", artifact.get("sha256"), require_pass)
        check_positive_int(validation, f"{path}.bytes", artifact.get("bytes"), require_pass)
        check_file_sha256(validation, f"{path}.sha256", artifact.get("path"), artifact.get("sha256"))
        check_file_size(validation, f"{path}.bytes", artifact.get("path"), artifact.get("bytes"))

        signature = artifact.get("signature")
        if not isinstance(signature, dict):
            validation.error(f"{path}.signature", "must be an object")
        else:
            require_signed_controls = require_pass
            signature_path = (
                signature.get("path")
                if require_signed_controls or signature.get("verified") is True
                else None
            )
            certificate_path = (
                signature.get("certificate")
                if require_signed_controls or signature.get("verified") is True
                else None
            )
            check_relative_path(validation, f"{path}.signature.path", signature_path, require_signed_controls)
            check_relative_path(
                validation,
                f"{path}.signature.certificate",
                certificate_path,
                require_signed_controls,
            )
            check_bool(validation, f"{path}.signature.verified", signature.get("verified"))
            if require_signed_controls and signature.get("verified") is not True:
                validation.error(f"{path}.signature.verified", "must be true for release-ready evidence")

        provenance = artifact.get("provenance")
        if not isinstance(provenance, dict):
            validation.error(f"{path}.provenance", "must be an object")
        else:
            require_provenance = require_pass
            provenance_path = (
                provenance.get("path")
                if require_provenance or provenance.get("verified") is True
                else None
            )
            check_relative_path(validation, f"{path}.provenance.path", provenance_path, require_provenance)
            check_bool(validation, f"{path}.provenance.verified", provenance.get("verified"))
            if require_provenance and provenance.get("verified") is not True:
                validation.error(f"{path}.provenance.verified", "must be true for release-ready evidence")


def validate_sbom(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    sbom = evidence.get("sbom")
    if not isinstance(sbom, dict):
        validation.error("$.sbom", "must be an object")
        return
    if sbom.get("format") != "cyclonedx-json":
        validation.error("$.sbom.format", "must be cyclonedx-json")
    check_relative_path(validation, "$.sbom.path", sbom.get("path"), True)
    check_sha256(validation, "$.sbom.sha256", sbom.get("sha256"), require_pass)
    check_positive_int(validation, "$.sbom.component_count", sbom.get("component_count"), require_pass)
    check_file_sha256(validation, "$.sbom.sha256", sbom.get("path"), sbom.get("sha256"))
    check_bool(validation, "$.sbom.signature_verified", sbom.get("signature_verified"))
    if validation.check_files:
        sbom_file = file_for_relative_path(validation, sbom.get("path"))
        if sbom_file is not None:
            try:
                payload = json.loads(sbom_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                validation.error("$.sbom.path", f"must be readable CycloneDX JSON: {exc}")
            else:
                components = payload.get("components")
                actual_count = len(components) if isinstance(components, list) else 0
                if actual_count <= 0:
                    validation.error("$.sbom.component_count", "CycloneDX components must be non-empty")
                if isinstance(sbom.get("component_count"), int) and sbom["component_count"] != actual_count:
                    validation.error("$.sbom.component_count", "does not match CycloneDX components length")
    if require_pass and sbom.get("signature_verified") is not True:
        validation.error("$.sbom.signature_verified", "must be true for release-ready evidence")


def validate_vex(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    vex = evidence.get("vex")
    if not isinstance(vex, dict):
        validation.error("$.vex", "must be an object")
        return
    check_status(validation, "$.vex.status", vex.get("status"), VEX_STATUS_VALUES)
    present = vex.get("status") == "present"
    check_relative_path(validation, "$.vex.path", vex.get("path"), present)
    check_sha256(validation, "$.vex.sha256", vex.get("sha256"), present)
    check_file_sha256(validation, "$.vex.sha256", vex.get("path"), vex.get("sha256"))
    check_bool(validation, "$.vex.signature_verified", vex.get("signature_verified"))
    if require_pass and release_tier == "production" and not present:
        validation.error("$.vex.status", "must be present for release-ready evidence")
    if present and require_pass and release_tier == "production" and vex.get("signature_verified") is not True:
        validation.error("$.vex.signature_verified", "must be true when VEX is present")


def validate_status_list(
    validation: Validation,
    base_path: str,
    value: Any,
    require_pass: bool,
    require_report: bool,
    expected_names: list[str] | None = None,
) -> None:
    if not isinstance(value, list):
        validation.error(base_path, "must be a list")
        return
    if expected_names is not None:
        actual_names = [
            str(entry.get("name"))
            for entry in value
            if isinstance(entry, dict) and is_non_empty_string(entry.get("name"))
        ]
        if sorted(actual_names) != sorted(expected_names):
            validation.error(base_path, f"must contain exactly: {', '.join(sorted(expected_names))}")
    for idx, entry in enumerate(value):
        path = f"{base_path}[{idx}]"
        if not isinstance(entry, dict):
            validation.error(path, "must be an object")
            continue
        check_string(validation, f"{path}.name", entry.get("name"))
        check_status(validation, f"{path}.status", entry.get("status"), STATUS_VALUES)
        check_relative_path(
            validation,
            f"{path}.report",
            entry.get("report"),
            require_report or (require_pass and entry.get("status") == "passed"),
        )
        if require_pass and entry.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
    if require_pass and not value:
        validation.error(base_path, "must not be empty for release-ready evidence")


def validate_machine_verification(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    machine_verification = evidence.get("machine_verification")
    if not isinstance(machine_verification, dict):
        validation.error("$.machine_verification", "must be an object")
        return
    covered_subjects: dict[str, set[tuple[str, str]]] = {}
    for name in MACHINE_VERIFICATION_CHECKS:
        if name not in machine_verification:
            validation.error("$.machine_verification", f"missing required check: {name}")
    for name, check in machine_verification.items():
        path = f"$.machine_verification.{name}"
        if not isinstance(check, dict):
            validation.error(path, "must be an object")
            continue
        check_status(validation, f"{path}.status", check.get("status"), STATUS_VALUES)
        logs = check.get("logs")
        if not isinstance(logs, list):
            validation.error(f"{path}.logs", "must be a list")
        else:
            for idx, log in enumerate(logs):
                check_relative_path(validation, f"{path}.logs[{idx}]", log, require_pass)
        record_file = validate_preserved_ref(validation, f"{path}.record", check.get("record"), require_pass)
        if record_file is not None:
            payload = read_json(record_file)
            if not isinstance(payload, dict):
                validation.error(f"{path}.record.path", "must be machine verification JSON")
            else:
                schema_version = payload.get("schema_version")
                if schema_version not in LEGACY_MACHINE_VERIFICATION_SCHEMA_VERSIONS | {MACHINE_VERIFICATION_SCHEMA_VERSION}:
                    validation.error(
                        f"{path}.record.path",
                        f"schema_version must be {MACHINE_VERIFICATION_SCHEMA_VERSION}",
                    )
                elif require_pass and schema_version != MACHINE_VERIFICATION_SCHEMA_VERSION:
                    validation.error(
                        f"{path}.record.path",
                        f"release-ready evidence requires {MACHINE_VERIFICATION_SCHEMA_VERSION}",
                    )
                try:
                    verifier = load_script_module(
                        "machine_verification_record",
                        "scripts/evidence/machine-verification-record.py",
                    )
                    for failure in verifier.validate_record(payload, expected_name=name):
                        validation.error(f"{path}.record.path", failure)
                    subject_source = payload.get("verified_subjects") if name == "attestations" else payload.get("subjects")
                    if isinstance(subject_source, list):
                        covered_subjects[name] = {
                            (str(subject.get("name")), str(subject.get("sha256")))
                            for subject in subject_source
                            if isinstance(subject, dict)
                            and isinstance(subject.get("name"), str)
                            and isinstance(subject.get("sha256"), str)
                        }
                except Exception as exc:
                    validation.error(f"{path}.record.path", f"cannot validate machine verification JSON: {exc}")
                log = payload.get("log")
                if isinstance(log, dict) and isinstance(log.get("path"), str) and isinstance(log.get("sha256"), str):
                    matching_logs = [
                        log_path
                        for log_path in logs
                        if isinstance(log_path, str) and Path(log_path).name == log["path"]
                    ]
                    if not matching_logs:
                        validation.error(f"{path}.record.path", "record log path must match preserved logs")
                    elif validation.check_files:
                        actual_log = file_for_relative_path(validation, matching_logs[0])
                        if actual_log is not None and sha256_file(actual_log) != log["sha256"]:
                            validation.error(f"{path}.record.path", "record log sha256 must match preserved log")
                if name == "attestations" and require_pass:
                    materials = check.get("materials")
                    if not isinstance(materials, list) or not materials:
                        validation.error(f"{path}.materials", "must preserve raw attestation JSON material")
                    else:
                        for idx, material_ref in enumerate(materials):
                            validate_preserved_ref(validation, f"{path}.materials[{idx}]", material_ref, True)
        if require_pass and check.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
        if require_pass and not logs:
            validation.error(f"{path}.logs", "must include machine-verification logs")
    if require_pass:
        artifacts = evidence.get("artifacts")
        if isinstance(artifacts, list):
            for idx, artifact in enumerate(artifacts):
                if not isinstance(artifact, dict):
                    continue
                subject = (artifact.get("name"), artifact.get("sha256"))
                if not all(isinstance(value, str) for value in subject):
                    continue
                for check_name in ("cosign", "attestations"):
                    if subject not in covered_subjects.get(check_name, set()):
                        validation.error(
                            f"$.machine_verification.{check_name}.record",
                            f"must cover artifact subject {subject[0]}",
                        )


def validate_build_evidence(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    build_evidence = evidence.get("build_evidence")
    if not isinstance(build_evidence, dict):
        validation.error("$.build_evidence", "must be an object")
        return
    check_status(validation, "$.build_evidence.status", build_evidence.get("status"), STATUS_VALUES)
    for collection in ("logs", "warnings", "source_identity"):
        items = build_evidence.get(collection)
        if not isinstance(items, list):
            validation.error(f"$.build_evidence.{collection}", "must be a list")
            continue
        for idx, item in enumerate(items):
            path = f"$.build_evidence.{collection}[{idx}]"
            if not isinstance(item, dict):
                validation.error(path, "must be an object")
                continue
            check_relative_path(validation, f"{path}.path", item.get("path"), require_pass)
            check_sha256(validation, f"{path}.sha256", item.get("sha256"), require_pass)
            check_positive_int(validation, f"{path}.bytes", item.get("bytes"), require_pass)
            check_file_sha256(validation, f"{path}.sha256", item.get("path"), item.get("sha256"))
            check_file_size(validation, f"{path}.bytes", item.get("path"), item.get("bytes"))
            if collection == "warnings" and validation.check_files:
                warning_path = file_for_relative_path(validation, item.get("path"))
                if warning_path is not None:
                    payload = read_json(warning_path)
                    if not isinstance(payload, dict):
                        validation.error(f"{path}.path", "must be warning classifier JSON")
                    else:
                        summary = payload.get("summary")
                        if not isinstance(summary, dict):
                            validation.error(f"{path}.path", "warning summary must be an object")
                        else:
                            if summary.get("owned") != 0:
                                validation.error(f"{path}.path", "warning owned count must be 0")
                            if summary.get("third-party") != 0:
                                validation.error(f"{path}.path", "warning third-party count must be 0")
                        for field in ("failing", "policy_errors"):
                            if payload.get(field) != []:
                                validation.error(f"{path}.path", f"warning {field} must be empty")
            if collection == "source_identity" and validation.check_files:
                source_identity_path = file_for_relative_path(validation, item.get("path"))
                if source_identity_path is not None:
                    payload = read_json(source_identity_path)
                    if not isinstance(payload, dict):
                        validation.error(f"{path}.path", "must be Buildroot source identity JSON")
                    else:
                        script = ROOT / "scripts" / "ci" / "buildroot-patch-identity.py"
                        spec = importlib.util.spec_from_file_location("buildroot_patch_identity", script)
                        if spec is None or spec.loader is None:
                            validation.error(f"{path}.path", f"cannot import {script}")
                        else:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            for failure in module.validate_metadata_payload(payload):
                                validation.error(f"{path}.path", failure)
                            if payload.get("buildroot_patch_files") and not payload.get("buildroot_applied_diff_sha256"):
                                validation.error(
                                    f"{path}.path",
                                    "patched Buildroot source identity must include buildroot_applied_diff_sha256",
                                )
    if require_pass and build_evidence.get("status") != "passed":
        validation.error("$.build_evidence.status", "must be passed for release-ready evidence")
    if require_pass and (
        not build_evidence.get("logs")
        or not build_evidence.get("warnings")
        or not build_evidence.get("source_identity")
    ):
        validation.error(
            "$.build_evidence",
            "must include build logs, warning classifier evidence, and Buildroot source identity",
                )


def validate_preserved_ref(validation: Validation, path: str, value: Any, require_pass: bool) -> Path | None:
    if value is None and not require_pass:
        return None
    if not isinstance(value, dict):
        validation.error(path, "must be an object preserving a preflight input")
        return None
    check_relative_path(validation, f"{path}.path", value.get("path"), require_pass)
    check_sha256(validation, f"{path}.sha256", value.get("sha256"), require_pass)
    check_positive_int(validation, f"{path}.bytes", value.get("bytes"), require_pass)
    check_file_sha256(validation, f"{path}.sha256", value.get("path"), value.get("sha256"))
    check_file_size(validation, f"{path}.bytes", value.get("path"), value.get("bytes"))
    return file_for_relative_path(validation, value.get("path"))


def validate_preflight_inputs(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    inputs = evidence.get("preflight_inputs")
    if not isinstance(inputs, dict):
        validation.error("$.preflight_inputs", "must be an object")
        return
    approval_path = validate_preserved_ref(validation, "$.preflight_inputs.approval", inputs.get("approval"), require_pass)
    if require_pass and approval_path is not None:
        try:
            module = load_script_module("release_approval", "scripts/evidence/release_approval.py")
            payload = read_json(approval_path)
            if not isinstance(payload, dict):
                validation.error("$.preflight_inputs.approval.path", "must be approval JSON")
            else:
                for failure in module.validate_approval_payload(
                    payload,
                    str(evidence.get("version")),
                    str(evidence.get("target")),
                    evidence.get("source", {}).get("git_commit") if isinstance(evidence.get("source"), dict) else None,
                    require_pass=True,
                ):
                    validation.error("$.preflight_inputs.approval.path", failure)
        except Exception as exc:
            validation.error("$.preflight_inputs.approval.path", f"cannot validate approval JSON: {exc}")
    repro_path = validate_preserved_ref(
        validation,
        "$.preflight_inputs.reproducibility",
        inputs.get("reproducibility"),
        require_pass,
    )
    if require_pass and repro_path is not None:
        try:
            module = load_script_module("validate_release_inputs", "scripts/evidence/validate-release-inputs.py")
            source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
            ci = source.get("ci") if isinstance(source.get("ci"), dict) else {}
            for failure in module.validate_repro(
                repro_path,
                str(evidence.get("version")),
                str(evidence.get("target")),
                source.get("git_commit") if isinstance(source.get("git_commit"), str) else None,
                ci.get("run_id") if isinstance(ci.get("run_id"), str) else None,
                True,
            ):
                validation.error("$.preflight_inputs.reproducibility.path", failure)
        except Exception as exc:
            validation.error("$.preflight_inputs.reproducibility.path", f"cannot validate reproducibility input: {exc}")
    reports = inputs.get("security_reports")
    if not isinstance(reports, list):
        validation.error("$.preflight_inputs.security_reports", "must be a list")
        reports = []
    raw_reports = inputs.get("security_raw_evidence")
    raw_by_source: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(raw_reports, list):
        validation.error("$.preflight_inputs.security_raw_evidence", "must be a list")
        raw_reports = []
    for idx, item in enumerate(raw_reports):
        raw_path = f"$.preflight_inputs.security_raw_evidence[{idx}]"
        raw_file = validate_preserved_ref(validation, raw_path, item, require_pass)
        if not isinstance(item, dict):
            continue
        check_string(validation, f"{raw_path}.name", item.get("name"))
        check_string(validation, f"{raw_path}.source_path", item.get("source_path"))
        if isinstance(item.get("source_path"), str):
            rel = Path(item["source_path"])
            if rel.is_absolute() or ".." in rel.parts:
                validation.error(f"{raw_path}.source_path", "must be relative and must not contain '..'")
        if "report_sha256" in item:
            check_sha256(validation, f"{raw_path}.report_sha256", item.get("report_sha256"), True)
            if item.get("report_sha256") != item.get("sha256"):
                validation.error(f"{raw_path}.report_sha256", "must match preserved raw evidence sha256")
        if "report_bytes" in item:
            check_positive_int(validation, f"{raw_path}.report_bytes", item.get("report_bytes"), True)
            if item.get("report_bytes") != item.get("bytes"):
                validation.error(f"{raw_path}.report_bytes", "must match preserved raw evidence bytes")
        if isinstance(item.get("source_path"), str) and isinstance(item.get("sha256"), str):
            raw_by_source[(item["source_path"], item["sha256"])] = item
        if raw_file is not None and raw_file.stat().st_size > 10 * 1024 * 1024:
            validation.error(raw_path, "raw security evidence exceeds 10 MiB cap")
    for idx, item in enumerate(reports):
        report_path = validate_preserved_ref(
            validation,
            f"$.preflight_inputs.security_reports[{idx}]",
            item,
            require_pass,
        )
        if require_pass and report_path is not None:
            try:
                module = load_script_module("validate_release_inputs", "scripts/evidence/validate-release-inputs.py")
                scan = item.get("name") if isinstance(item, dict) else None
                source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
                ci = source.get("ci") if isinstance(source.get("ci"), dict) else {}
                for failure in module.validate_security_report(
                    report_path,
                    str(scan),
                    str(evidence.get("version")),
                    source.get("git_commit") if isinstance(source.get("git_commit"), str) else None,
                    str(ci.get("run_id")) if ci.get("run_id") is not None else None,
                    validation.check_files,
                ):
                    validation.error(f"$.preflight_inputs.security_reports[{idx}].path", failure)
                report_payload = read_json(report_path)
                if isinstance(report_payload, dict):
                    evidence_path = report_payload.get("evidence_path")
                    evidence_sha = report_payload.get("evidence_sha256")
                    evidence_bytes = report_payload.get("evidence_bytes")
                    if isinstance(evidence_path, str) and isinstance(evidence_sha, str):
                        raw = raw_by_source.get((evidence_path, evidence_sha))
                        if not isinstance(raw, dict):
                            validation.error(
                                f"$.preflight_inputs.security_reports[{idx}].path",
                                "must preserve matching raw security evidence",
                            )
                        elif isinstance(evidence_bytes, int) and raw.get("bytes") != evidence_bytes:
                            validation.error(
                                f"$.preflight_inputs.security_reports[{idx}].path",
                                "raw security evidence bytes must match report",
                            )
            except Exception as exc:
                validation.error(f"$.preflight_inputs.security_reports[{idx}].path", f"cannot validate security report: {exc}")


def validate_governance(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    governance = evidence.get("governance")
    if not isinstance(governance, dict):
        validation.error("$.governance", "must be an object")
        return
    retention_years = governance.get("retention_years")
    if not isinstance(retention_years, int) or retention_years < 1:
        validation.error("$.governance.retention_years", "must be a positive integer")
    elif require_pass and retention_years < 7:
        validation.error("$.governance.retention_years", "must be at least 7 for enterprise release evidence")
    check_string(validation, "$.governance.approval_model", governance.get("approval_model"))
    checks = governance.get("checks")
    if not isinstance(checks, dict):
        validation.error("$.governance.checks", "must be an object")
        return
    for name in GOVERNANCE_CHECKS:
        if name not in checks:
            validation.error("$.governance.checks", f"missing required check: {name}")
    for name, check in checks.items():
        path = f"$.governance.checks.{name}"
        if not isinstance(check, dict):
            validation.error(path, "must be an object")
            continue
        check_status(validation, f"{path}.status", check.get("status"), STATUS_VALUES)
        check_relative_path(validation, f"{path}.evidence", check.get("evidence"), require_pass)
        if require_pass and check.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
        if require_pass and name == "policy_validation":
            report = file_for_relative_path(validation, check.get("evidence"))
            if report is None:
                continue
            payload = read_json(report)
            if not isinstance(payload, dict):
                validation.error(f"{path}.evidence", "must be a governance validation JSON object")
                continue
            if require_pass:
                if payload.get("schema_version") != "suderra.github-governance-validation.v2":
                    validation.error(
                        f"{path}.evidence",
                        "schema_version must be suderra.github-governance-validation.v2",
                    )
            elif payload.get("schema_version") not in {
                "suderra.github-governance-validation.v1",
                "suderra.github-governance-validation.v2",
            }:
                validation.error(
                    f"{path}.evidence",
                    "schema_version must be suderra.github-governance-validation.v1 or v2",
                )
            if payload.get("status") != "passed":
                validation.error(f"{path}.evidence", "governance policy validation must be passed")


def validate_qemu(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    expected_required: bool,
) -> None:
    qemu = evidence.get("qemu")
    if not isinstance(qemu, dict):
        validation.error("$.qemu", "must be an object")
        return
    check_bool(validation, "$.qemu.required", qemu.get("required"))
    if isinstance(qemu.get("required"), bool) and qemu.get("required") != expected_required:
        validation.error("$.qemu.required", f"must match matrix-derived requirement {expected_required}")
    check_status(validation, "$.qemu.status", qemu.get("status"), STATUS_VALUES)
    logs = qemu.get("logs")
    if not isinstance(logs, list):
        validation.error("$.qemu.logs", "must be a list")
    else:
        for idx, log in enumerate(logs):
            path = f"$.qemu.logs[{idx}]"
            if isinstance(log, dict):
                if "role" in log:
                    check_string(validation, f"{path}.role", log.get("role"))
                check_relative_path(validation, f"{path}.path", log.get("path"), True)
                check_sha256(validation, f"{path}.sha256", log.get("sha256"), True)
                allow_empty = log.get("role") == "qemu-stderr"
                if allow_empty:
                    if not isinstance(log.get("bytes"), int) or log.get("bytes") < 0:
                        validation.error(f"{path}.bytes", "must be a non-negative integer")
                else:
                    check_positive_int(validation, f"{path}.bytes", log.get("bytes"), True)
                check_file_sha256(validation, f"{path}.sha256", log.get("path"), log.get("sha256"))
                check_file_size(validation, f"{path}.bytes", log.get("path"), log.get("bytes"))
                if "input_sha256" in log:
                    check_sha256(validation, f"{path}.input_sha256", log.get("input_sha256"), True)
            else:
                check_relative_path(validation, path, log, True)
    checks = qemu.get("checks")
    if not isinstance(checks, list):
        validation.error("$.qemu.checks", "must be a list")
    else:
        for idx, check in enumerate(checks):
            if not is_non_empty_string(check):
                validation.error(f"$.qemu.checks[{idx}]", "must be a non-empty string")
    if "failure_class" in qemu and qemu.get("failure_class") not in FAILURE_CLASS_VALUES:
        validation.error("$.qemu.failure_class", f"must be one of: {', '.join(sorted(FAILURE_CLASS_VALUES))}")
    execution = qemu.get("execution")
    if execution is not None:
        if not isinstance(execution, dict):
            validation.error("$.qemu.execution", "must be an object")
        else:
            if "termination" in execution:
                termination = execution.get("termination")
                if not isinstance(termination, dict):
                    validation.error("$.qemu.execution.termination", "must be an object")
                else:
                    for field in ("killed", "timeout", "qmp_quit_sent", "qmp_quit_ack", "acceptable"):
                        if field in termination and not isinstance(termination.get(field), bool):
                            validation.error(f"$.qemu.execution.termination.{field}", "must be a boolean")
                    if require_pass and expected_required:
                        if termination.get("acceptable") is not True:
                            validation.error("$.qemu.execution.termination.acceptable", "must be true when QEMU evidence is required")
                        if termination.get("killed") is not False:
                            validation.error("$.qemu.execution.termination.killed", "must be false when QEMU evidence is required")
                        if termination.get("exit_status") != 0:
                            validation.error("$.qemu.execution.termination.exit_status", "must be 0 when QEMU evidence is required")
            if require_pass and expected_required and execution.get("qemu_exit_status") not in (0, None):
                validation.error("$.qemu.execution.qemu_exit_status", "must be 0 when QEMU evidence is required")
    check_details = qemu.get("check_details")
    if check_details is not None and not isinstance(check_details, dict):
        validation.error("$.qemu.check_details", "must be an object")

    if require_pass and expected_required:
        qemu_input = qemu.get("input")
        if not isinstance(qemu_input, dict):
            validation.error("$.qemu.input", "must preserve the validated QEMU input JSON")
        else:
            check_relative_path(validation, "$.qemu.input.path", qemu_input.get("path"), True)
            check_sha256(validation, "$.qemu.input.sha256", qemu_input.get("sha256"), True)
            check_positive_int(validation, "$.qemu.input.bytes", qemu_input.get("bytes"), True)
            check_file_sha256(validation, "$.qemu.input.sha256", qemu_input.get("path"), qemu_input.get("sha256"))
            check_file_size(validation, "$.qemu.input.bytes", qemu_input.get("path"), qemu_input.get("bytes"))
            if validation.check_files:
                qemu_input_path = file_for_relative_path(validation, qemu_input.get("path"))
                if qemu_input_path is not None:
                    try:
                        module = load_script_module("validate_qemu_input", "scripts/evidence/validate-qemu-input.py")
                        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
                        profile = qemu.get("validation_profile")
                        if not isinstance(profile, str) or not profile:
                            profile = "release-candidate" if "-" in str(evidence.get("version", "")) else "production-candidate"
                        for failure in module.validate(
                            qemu_input_path,
                            True,
                            True,
                            profile,
                            str(evidence.get("version")),
                            str(evidence.get("target")),
                            source.get("git_commit") if isinstance(source.get("git_commit"), str) else None,
                            qemu.get("image_sha256") if isinstance(qemu.get("image_sha256"), str) else None,
                        ):
                            validation.error("$.qemu.input.path", failure)
                    except Exception as exc:
                        validation.error("$.qemu.input.path", f"cannot replay QEMU input validation: {exc}")
        for field in ("image", "firmware"):
            check_string(validation, f"$.qemu.{field}", qemu.get(field))
        for field in ("image_sha256", "firmware_sha256"):
            check_sha256(validation, f"$.qemu.{field}", qemu.get(field), True)
        facts = qemu.get("guest_facts")
        if not isinstance(facts, dict) or not facts:
            validation.error("$.qemu.guest_facts", "must include semantic guest facts")
        else:
            for field in (
                "os_release",
                "kernel",
                "rootfs",
                "failed_units",
                "network",
                "listeners",
                "firewall",
                "firstboot",
                "lockdown",
            ):
                if field not in facts:
                    validation.error("$.qemu.guest_facts", f"missing semantic fact: {field}")
        semantic_checks = qemu.get("check_details") or qemu.get("semantic_checks")
        if not isinstance(semantic_checks, dict) or not semantic_checks:
            validation.error("$.qemu.check_details", "must preserve semantic QEMU check details")
        if qemu.get("status") != "passed":
            validation.error("$.qemu.status", "must be passed when QEMU evidence is required")
        if not logs:
            validation.error("$.qemu.logs", "must include at least one log when QEMU is required")
        missing_checks = sorted(set(REQUIRED_QEMU_CHECKS) - set(checks or []))
        if missing_checks:
            validation.error("$.qemu.checks", f"missing required checks: {', '.join(missing_checks)}")


def validate_runtime_qemu(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
    expected_required: bool,
) -> None:
    runtime_qemu = evidence.get("runtime_qemu")
    if not isinstance(runtime_qemu, dict):
        validation.error("$.runtime_qemu", "must be an object")
        return
    check_bool(validation, "$.runtime_qemu.required", runtime_qemu.get("required"))
    if isinstance(runtime_qemu.get("required"), bool) and runtime_qemu.get("required") != expected_required:
        validation.error("$.runtime_qemu.required", f"must match matrix-derived requirement {expected_required}")
    check_status(validation, "$.runtime_qemu.status", runtime_qemu.get("status"), STATUS_VALUES)
    suites = runtime_qemu.get("production_suites")
    if not isinstance(suites, list):
        validation.error("$.runtime_qemu.production_suites", "must be a list")
        return
    if require_pass and release_tier == "production" and expected_required and not suites:
        validation.error("$.runtime_qemu.production_suites", "must include production-runtime QEMU suite evidence")
    source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
    expected_source_sha = source.get("git_commit") if isinstance(source.get("git_commit"), str) else None
    for idx, item in enumerate(suites):
        suite_path = validate_preserved_ref(validation, f"$.runtime_qemu.production_suites[{idx}]", item, require_pass)
        if require_pass and suite_path is not None:
            try:
                module = load_script_module(
                    "validate_production_runtime_suite",
                    "scripts/evidence/validate-production-runtime-suite.py",
                )
                for failure in module.validate(
                    suite_path,
                    check_files=validation.check_files,
                    require_pass=True,
                    expected_version=str(evidence.get("version")),
                    expected_target=None,
                    expected_source_sha=expected_source_sha,
                ):
                    validation.error(f"$.runtime_qemu.production_suites[{idx}].path", failure)
            except Exception as exc:
                validation.error(
                    f"$.runtime_qemu.production_suites[{idx}].path",
                    f"cannot replay production-runtime suite validation: {exc}",
                )
    if require_pass and release_tier == "production" and expected_required and runtime_qemu.get("status") != "passed":
        validation.error("$.runtime_qemu.status", "must be passed for production release evidence")


def validate_hsm_signing_sessions(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
    expected_required: bool,
) -> None:
    sessions = evidence.get("hsm_signing_sessions")
    if not isinstance(sessions, list):
        validation.error("$.hsm_signing_sessions", "must be a list")
        return
    if require_pass and release_tier == "production" and expected_required and not sessions:
        validation.error("$.hsm_signing_sessions", "must preserve production HSM signing sessions")
    for idx, item in enumerate(sessions):
        session_path = validate_preserved_ref(validation, f"$.hsm_signing_sessions[{idx}]", item, require_pass)
        if require_pass and session_path is not None:
            payload = read_json(session_path)
            if not isinstance(payload, dict):
                validation.error(f"$.hsm_signing_sessions[{idx}].path", "must be HSM signing evidence JSON")
                continue
            if payload.get("schema_version") != "suderra.hsm-signing-session.v2":
                validation.error(f"$.hsm_signing_sessions[{idx}].schema_version", "must be suderra.hsm-signing-session.v2")
            if payload.get("mode") != "production":
                validation.error(f"$.hsm_signing_sessions[{idx}].mode", "must be production")
            for field in ("pkcs11_uri", "certificate_sha256", "hsm_serial", "ceremony_id"):
                check_string(validation, f"$.hsm_signing_sessions[{idx}].{field}", payload.get(field))
            if not isinstance(payload.get("challenge"), dict):
                validation.error(f"$.hsm_signing_sessions[{idx}].challenge", "must preserve signed challenge")
            artifacts = payload.get("artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                validation.error(f"$.hsm_signing_sessions[{idx}].artifacts", "must bind signed artifacts")


def validate_station_acquisitions(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
    expected_required: bool,
) -> None:
    acquisitions = evidence.get("station_acquisitions")
    if not isinstance(acquisitions, list):
        validation.error("$.station_acquisitions", "must be a list")
        return
    if require_pass and release_tier == "production" and expected_required and not acquisitions:
        validation.error("$.station_acquisitions", "must preserve adapter-acquired station evidence")
    for idx, item in enumerate(acquisitions):
        acquisition_path = validate_preserved_ref(validation, f"$.station_acquisitions[{idx}]", item, require_pass)
        if require_pass and acquisition_path is not None:
            payload = read_json(acquisition_path)
            if not isinstance(payload, dict):
                validation.error(f"$.station_acquisitions[{idx}].path", "must be station acquisition JSON")
                continue
            if payload.get("schema_version") != "suderra.station-acquisition.v1":
                validation.error(f"$.station_acquisitions[{idx}].schema_version", "must be suderra.station-acquisition.v1")
            events = payload.get("events")
            if not isinstance(events, list) or not events:
                validation.error(f"$.station_acquisitions[{idx}].events", "must include adapter events")
            try:
                module = load_script_module("station_acquisition", "scripts/evidence/station-acquisition.py")
                for failure in module.validate_payload(payload, acquisition_path.parent, validation.check_files):
                    validation.error(f"$.station_acquisitions[{idx}].path", failure)
            except Exception as exc:
                validation.error(f"$.station_acquisitions[{idx}].path", f"cannot replay station acquisition: {exc}")


def validate_release_image_scan_reports(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
    expected_required: bool,
) -> None:
    reports = evidence.get("release_image_scan_reports")
    if not isinstance(reports, list):
        validation.error("$.release_image_scan_reports", "must be a list")
        return
    if require_pass and release_tier == "production" and expected_required and not reports:
        validation.error("$.release_image_scan_reports", "must include scanner-native release image reports")
    for idx, item in enumerate(reports):
        validate_preserved_ref(validation, f"$.release_image_scan_reports[{idx}]", item, require_pass)


def validate_hardware(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    expected_required: bool,
) -> None:
    hardware = evidence.get("hardware")
    if not isinstance(hardware, dict):
        validation.error("$.hardware", "must be an object")
        return
    check_bool(validation, "$.hardware.required", hardware.get("required"))
    if isinstance(hardware.get("required"), bool) and hardware.get("required") != expected_required:
        validation.error("$.hardware.required", f"must match matrix-derived requirement {expected_required}")
    check_status(validation, "$.hardware.status", hardware.get("status"), STATUS_VALUES)
    if require_pass and expected_required:
        station_registry_path: Path | None = None
        station_registry = hardware.get("station_registry")
        if not isinstance(station_registry, dict):
            validation.error("$.hardware.station_registry", "must preserve external station registry")
        else:
            if station_registry.get("source_domain") != "release-governance":
                validation.error(
                    "$.hardware.station_registry.source_domain",
                    "must be release-governance for release-ready evidence",
                )
            check_relative_path(validation, "$.hardware.station_registry.path", station_registry.get("path"), True)
            check_sha256(validation, "$.hardware.station_registry.sha256", station_registry.get("sha256"), True)
            check_positive_int(validation, "$.hardware.station_registry.bytes", station_registry.get("bytes"), True)
            check_file_sha256(
                validation,
                "$.hardware.station_registry.sha256",
                station_registry.get("path"),
                station_registry.get("sha256"),
            )
            check_file_size(
                validation,
                "$.hardware.station_registry.bytes",
                station_registry.get("path"),
                station_registry.get("bytes"),
            )
            if validation.check_files:
                station_registry_path = file_for_relative_path(validation, station_registry.get("path"))
        lab_input = hardware.get("input")
        if not isinstance(lab_input, dict):
            validation.error("$.hardware.input", "must preserve the validated lab input JSON")
        else:
            check_relative_path(validation, "$.hardware.input.path", lab_input.get("path"), True)
            check_sha256(validation, "$.hardware.input.sha256", lab_input.get("sha256"), True)
            check_positive_int(validation, "$.hardware.input.bytes", lab_input.get("bytes"), True)
            check_file_sha256(validation, "$.hardware.input.sha256", lab_input.get("path"), lab_input.get("sha256"))
            check_file_size(validation, "$.hardware.input.bytes", lab_input.get("path"), lab_input.get("bytes"))
            if validation.check_files:
                lab_input_path = file_for_relative_path(validation, lab_input.get("path"))
                if lab_input_path is not None:
                    try:
                        module = load_script_module("validate_lab_input", "scripts/evidence/validate-lab-input.py")
                        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
                        ci = source.get("ci") if isinstance(source.get("ci"), dict) else {}
                        profile = "release-candidate" if "-" in str(evidence.get("version", "")) else "production-candidate"
                        for failure in module.validate_lab(
                            lab_input_path,
                            True,
                            True,
                            str(evidence.get("version")),
                            str(evidence.get("target")),
                            profile,
                            source.get("git_commit") if isinstance(source.get("git_commit"), str) else None,
                            str(ci.get("run_id")) if ci.get("run_id") is not None else None,
                            station_registry_path,
                        ):
                            validation.error("$.hardware.input.path", failure)
                    except Exception as exc:
                        validation.error("$.hardware.input.path", f"cannot replay lab input validation: {exc}")
        if not isinstance(hardware.get("station"), dict) or not hardware["station"]:
            validation.error("$.hardware.station", "must preserve station identity")
        if not isinstance(hardware.get("artifact_binding"), dict) or not hardware["artifact_binding"]:
            validation.error("$.hardware.artifact_binding", "must preserve artifact binding")
        station_bundle = hardware.get("station_bundle")
        if not isinstance(station_bundle, dict):
            validation.error("$.hardware.station_bundle", "must preserve signed station bundle")
        else:
            check_relative_path(validation, "$.hardware.station_bundle.path", station_bundle.get("path"), True)
            check_sha256(validation, "$.hardware.station_bundle.sha256", station_bundle.get("sha256"), True)
            check_positive_int(validation, "$.hardware.station_bundle.bytes", station_bundle.get("bytes"), True)
            check_file_sha256(
                validation,
                "$.hardware.station_bundle.sha256",
                station_bundle.get("path"),
                station_bundle.get("sha256"),
            )
            check_file_size(
                validation,
                "$.hardware.station_bundle.bytes",
                station_bundle.get("path"),
                station_bundle.get("bytes"),
            )
        station_signature = hardware.get("station_signature")
        if not isinstance(station_signature, dict):
            validation.error("$.hardware.station_signature", "must preserve station signature")
        else:
            for field in ("algorithm", "signature", "public_key"):
                check_string(validation, f"$.hardware.station_signature.{field}", station_signature.get(field))
            for field in ("signature_sha256", "public_key_sha256"):
                check_sha256(validation, f"$.hardware.station_signature.{field}", station_signature.get(field), True)
            check_relative_path(
                validation,
                "$.hardware.station_signature.signature",
                station_signature.get("signature"),
                True,
            )
            check_relative_path(
                validation,
                "$.hardware.station_signature.public_key",
                station_signature.get("public_key"),
                True,
            )
            check_file_sha256(
                validation,
                "$.hardware.station_signature.signature_sha256",
                station_signature.get("signature"),
                station_signature.get("signature_sha256"),
            )
            check_file_sha256(
                validation,
                "$.hardware.station_signature.public_key_sha256",
                station_signature.get("public_key"),
                station_signature.get("public_key_sha256"),
            )
    devices = hardware.get("devices")
    if not isinstance(devices, list):
        validation.error("$.hardware.devices", "must be a list")
        return

    for idx, device in enumerate(devices):
        path = f"$.hardware.devices[{idx}]"
        if not isinstance(device, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("board", "serial", "operator"):
            check_string(validation, f"{path}.{field}", device.get(field))
        for field in ("sku", "storage_serial", "uart_adapter", "power_supply", "boot_firmware", "tested_at"):
            if field in device:
                check_string(validation, f"{path}.{field}", device.get(field))
        check_status(validation, f"{path}.status", device.get("status"), STATUS_VALUES)
        logs = device.get("logs")
        if not isinstance(logs, list):
            validation.error(f"{path}.logs", "must be a list")
        else:
            for log_idx, log in enumerate(logs):
                log_path = f"{path}.logs[{log_idx}]"
                if isinstance(log, dict):
                    check_relative_path(validation, f"{log_path}.path", log.get("path"), True)
                    if "sha256" in log:
                        check_sha256(validation, f"{log_path}.sha256", log.get("sha256"), True)
                        check_file_sha256(validation, f"{log_path}.sha256", log.get("path"), log.get("sha256"))
                    if "input_sha256" in log:
                        check_sha256(validation, f"{log_path}.input_sha256", log.get("input_sha256"), True)
                else:
                    check_relative_path(validation, log_path, log, True)
        checks = device.get("checks")
        if not isinstance(checks, dict):
            validation.error(f"{path}.checks", "must be an object")
        else:
            for check_name, check in checks.items():
                check_path = f"{path}.checks.{check_name}"
                if not isinstance(check, dict):
                    validation.error(check_path, "must be an object")
                    continue
                check_status(validation, f"{check_path}.status", check.get("status"), STATUS_VALUES)
                check_relative_path(
                    validation,
                    f"{check_path}.evidence",
                    check.get("evidence"),
                    require_pass
                    and expected_required
                    and check_name in REQUIRED_HARDWARE_CHECKS,
                )
                if "evidence_sha256" in check:
                    check_sha256(validation, f"{check_path}.evidence_sha256", check.get("evidence_sha256"), True)
                    check_file_sha256(
                        validation,
                        f"{check_path}.evidence_sha256",
                        check.get("evidence"),
                        check.get("evidence_sha256"),
                    )
                if require_pass and check.get("status") != "passed":
                    validation.error(f"{check_path}.status", "must be passed for release-ready evidence")

        if require_pass and expected_required and device.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
        if require_pass and expected_required:
            if not logs:
                validation.error(f"{path}.logs", "must include serial/install logs")
            if isinstance(checks, dict):
                missing_checks = sorted(set(REQUIRED_HARDWARE_CHECKS) - set(checks))
                if missing_checks:
                    validation.error(
                        f"{path}.checks",
                        f"missing required checks: {', '.join(missing_checks)}",
                    )
            identity = device.get("device_identity")
            if not isinstance(identity, dict) or not identity:
                validation.error(f"{path}.device_identity", "must preserve board/storage identity")
            else:
                for field in ("model", "compatible", "storage_by_id", "storage_serial", "root_partuuid"):
                    check_string(validation, f"{path}.device_identity.{field}", identity.get(field))
            readback = device.get("readback")
            if not isinstance(readback, dict) or not readback:
                validation.error(f"{path}.readback", "must preserve full readback evidence")
            else:
                if readback.get("scope") != "full":
                    validation.error(f"{path}.readback.scope", "must be full")
                check_sha256(validation, f"{path}.readback.expected_sha256", readback.get("expected_sha256"), True)
                check_sha256(validation, f"{path}.readback.actual_sha256", readback.get("actual_sha256"), True)
                if readback.get("expected_sha256") != readback.get("actual_sha256"):
                    validation.error(f"{path}.readback.actual_sha256", "must match expected_sha256")
                check_positive_int(validation, f"{path}.readback.bytes_read", readback.get("bytes_read"), True)

    if require_pass and expected_required:
        if hardware.get("status") != "passed":
            validation.error("$.hardware.status", "must be passed when hardware evidence is required")
        if not devices:
            validation.error("$.hardware.devices", "must include at least one device")
        required_boards = REQUIRED_HARDWARE_BOARDS_BY_TARGET.get(str(evidence.get("target", "")), ())
        if required_boards:
            seen_boards = {
                device.get("board")
                for device in devices
                if isinstance(device, dict) and isinstance(device.get("board"), str)
            }
            missing_boards = sorted(set(required_boards) - seen_boards)
            if missing_boards:
                validation.error(
                    "$.hardware.devices",
                    f"missing required board evidence: {', '.join(missing_boards)}",
                )
        if evidence.get("target") == "pi-cm4-revpi-usb-installer":
            negative_tests = hardware.get("negative_tests")
            if not isinstance(negative_tests, list) or not negative_tests:
                validation.error("$.hardware.negative_tests", "must include USB installer negative tests")
            else:
                for idx, item in enumerate(negative_tests):
                    item_path = f"$.hardware.negative_tests[{idx}]"
                    if not isinstance(item, dict):
                        validation.error(item_path, "must be an object")
                        continue
                    for field in ("name", "failure_code"):
                        check_string(validation, f"{item_path}.{field}", item.get(field))
                    check_status(validation, f"{item_path}.status", item.get("status"), STATUS_VALUES)
                    check_relative_path(validation, f"{item_path}.evidence", item.get("evidence"), True)
                    if "evidence_sha256" in item:
                        check_sha256(validation, f"{item_path}.evidence_sha256", item.get("evidence_sha256"), True)
                        check_file_sha256(
                            validation,
                            f"{item_path}.evidence_sha256",
                            item.get("evidence"),
                            item.get("evidence_sha256"),
                        )
                    if item.get("status") != "passed":
                        validation.error(f"{item_path}.status", "must be passed for release-ready evidence")


def validate_runtime_checks(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
    expected_required: bool,
) -> None:
    runtime_checks = evidence.get("runtime_checks")
    if not isinstance(runtime_checks, dict):
        validation.error("$.runtime_checks", "must be an object")
        return
    for name in REQUIRED_RUNTIME_CHECKS:
        if name not in runtime_checks:
            validation.error("$.runtime_checks", f"missing required check: {name}")
    for name, check in runtime_checks.items():
        path = f"$.runtime_checks.{name}"
        if not isinstance(check, dict):
            validation.error(path, "must be an object")
            continue
        check_bool(validation, f"{path}.required", check.get("required"))
        if isinstance(check.get("required"), bool) and check.get("required") != expected_required:
            validation.error(f"{path}.required", f"must match matrix-derived requirement {expected_required}")
        check_status(validation, f"{path}.status", check.get("status"), STATUS_VALUES)
        check_relative_path(
            validation,
            f"{path}.evidence",
            check.get("evidence"),
            require_pass and release_tier == "production" and expected_required,
        )
        if require_pass and release_tier == "production" and expected_required and check.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")


def validate_approvals(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    approvals = evidence.get("approvals")
    if not isinstance(approvals, list):
        validation.error("$.approvals", "must be a list")
        return
    for idx, approval in enumerate(approvals):
        path = f"$.approvals[{idx}]"
        if not isinstance(approval, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("role", "name", "approved_at"):
            check_string(validation, f"{path}.{field}", approval.get(field))
        parse_timestamp(validation, f"{path}.approved_at", approval.get("approved_at"), True)
        if "ticket" in approval:
            check_string(validation, f"{path}.ticket", approval.get("ticket"))
    if require_pass and not approvals:
        validation.error("$.approvals", "must include at least one approval")
    if require_pass:
        roles = {
            approval.get("role")
            for approval in approvals
            if isinstance(approval, dict) and isinstance(approval.get("role"), str)
        }
        if "release-owner" not in roles:
            validation.error("$.approvals", "must include release-owner approval")
        if not ({"maintainer", "security-compliance"} & roles):
            validation.error("$.approvals", "must include maintainer or security-compliance approval")
        if len(roles) < 2:
            validation.error("$.approvals", "must include at least two distinct approval roles")


def validate_residual_risk(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    risk = evidence.get("residual_risk")
    if not isinstance(risk, dict):
        validation.error("$.residual_risk", "must be an object")
        return
    check_status(validation, "$.residual_risk.status", risk.get("status"), RISK_STATUS_VALUES)
    items = risk.get("items")
    if not isinstance(items, list):
        validation.error("$.residual_risk.items", "must be a list")
        items = []
    for idx, item in enumerate(items):
        path = f"$.residual_risk.items[{idx}]"
        if not isinstance(item, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("id", "severity", "description", "mitigation", "owner", "ticket"):
            check_string(validation, f"{path}.{field}", item.get(field))

    decision = evidence.get("release_decision")
    decision_status = decision.get("status") if isinstance(decision, dict) else None
    if require_pass and risk.get("status") == "blocked":
        validation.error("$.residual_risk.status", "must not be blocked for release-ready evidence")
    if require_pass and decision_status == "approved":
        if risk.get("status") != "none":
            validation.error(
                "$.residual_risk.status",
                "must be none when release decision is approved without residual risk",
            )
        if items:
            validation.error(
                "$.residual_risk.items",
                "must be empty when release decision is approved without residual risk",
            )
    if require_pass and decision_status == "approved_with_residual_risk":
        if risk.get("status") != "accepted":
            validation.error(
                "$.residual_risk.status",
                "must be accepted when release decision carries residual risk",
            )
        if not items:
            validation.error("$.residual_risk.items", "must list accepted residual risks")
        for field in ("accepted_by", "accepted_at", "expires_at"):
            check_string(validation, f"$.residual_risk.{field}", risk.get(field))
        parse_timestamp(validation, "$.residual_risk.accepted_at", risk.get("accepted_at"), True)
        expires_at = parse_timestamp(validation, "$.residual_risk.expires_at", risk.get("expires_at"), True)
        if expires_at is not None and expires_at <= datetime.now(timezone.utc):
            validation.error("$.residual_risk.expires_at", "must be in the future")


def validate_release_decision(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    decision = evidence.get("release_decision")
    if not isinstance(decision, dict):
        validation.error("$.release_decision", "must be an object")
        return
    check_status(validation, "$.release_decision.status", decision.get("status"), DECISION_STATUS_VALUES)
    for field in ("decided_by", "decided_at", "rationale"):
        required = require_pass or field == "rationale"
        value = decision.get(field)
        if required or value is not None:
            check_string(validation, f"$.release_decision.{field}", value)
    parse_timestamp(validation, "$.release_decision.decided_at", decision.get("decided_at"), require_pass)
    if require_pass and decision.get("status") not in {"approved", "approved_with_residual_risk"}:
        validation.error("$.release_decision.status", "must be approved for release-ready evidence")


def validate_source(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    source = evidence.get("source")
    if not isinstance(source, dict):
        validation.error("$.source", "must be an object")
        return
    for field in ("repository", "git_commit", "git_tag"):
        check_string(validation, f"$.source.{field}", source.get(field))
    check_bool(validation, "$.source.dirty", source.get("dirty"))
    if source.get("git_tag") != evidence.get("version"):
        validation.error("$.source.git_tag", "must match evidence.version")
    ci = source.get("ci")
    if not isinstance(ci, dict):
        validation.error("$.source.ci", "must be an object")
    else:
        for field in ("provider", "workflow", "run_id", "run_attempt"):
            check_string(validation, f"$.source.ci.{field}", ci.get(field))
        if require_pass:
            if ci.get("run_id") == "not_collected":
                validation.error("$.source.ci.run_id", "must be collected for release-ready evidence")
            if ci.get("run_attempt") == "not_collected":
                validation.error("$.source.ci.run_attempt", "must be collected for release-ready evidence")
    if require_pass:
        if not isinstance(source.get("git_commit"), str) or not re.fullmatch(
            r"[0-9a-f]{40}", source["git_commit"]
        ):
            validation.error("$.source.git_commit", "must be a full git commit sha")
        if source.get("dirty") is not False:
            validation.error("$.source.dirty", "must be false for release-ready evidence")


def validate_reproducibility(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    reproducibility = evidence.get("reproducibility")
    if not isinstance(reproducibility, dict):
        validation.error("$.reproducibility", "must be an object")
        return
    check_status(validation, "$.reproducibility.status", reproducibility.get("status"), STATUS_VALUES)
    comparison = reproducibility.get("comparison")
    if comparison is not None:
        check_string(validation, "$.reproducibility.comparison", comparison)
    logs = reproducibility.get("logs")
    if not isinstance(logs, list):
        validation.error("$.reproducibility.logs", "must be a list")
    else:
        for idx, log in enumerate(logs):
            check_relative_path(validation, f"$.reproducibility.logs[{idx}]", log, True)
    if require_pass and reproducibility.get("status") != "passed":
        validation.error("$.reproducibility.status", "must be passed for release-ready evidence")


def validate_target_contract(
    validation: Validation,
    evidence: dict[str, Any],
    matrix: dict[str, Any] | None,
) -> None:
    contract = evidence.get("target_contract")
    if not isinstance(contract, dict):
        validation.error("$.target_contract", "must be an object")
        return
    missing = sorted(TARGET_CONTRACT_FIELDS - set(contract))
    extra = sorted(set(contract) - TARGET_CONTRACT_FIELDS)
    if missing:
        validation.error("$.target_contract", f"missing fields: {', '.join(missing)}")
    if extra:
        validation.error("$.target_contract", f"unknown fields: {', '.join(extra)}")
    if contract.get("target") != evidence.get("target"):
        validation.error("$.target_contract.target", "must match evidence.target")
    for field in TARGET_CONTRACT_FIELDS - {"production_required", "production_ready"}:
        check_string(validation, f"$.target_contract.{field}", contract.get(field))
    for field in ("production_required", "production_ready"):
        check_bool(validation, f"$.target_contract.{field}", contract.get(field))

    if matrix is None:
        return
    row = targets_by_id(matrix).get(str(evidence.get("target", "")))
    if row is None:
        validation.error("$.target", "must exist in ci/build-matrix.yml")
        return
    expected = contract_from_matrix(row)
    for field, expected_value in expected.items():
        if contract.get(field) != expected_value:
            validation.error(
                f"$.target_contract.{field}",
                f"does not match matrix value {expected_value!r}",
            )


def release_tier_from_version(version: Any) -> str:
    if isinstance(version, str) and "-" in version:
        return "alpha"
    return "production"


def expected_gate_requirements(
    evidence: dict[str, Any],
    matrix: dict[str, Any] | None,
) -> tuple[bool, bool, bool]:
    contract = evidence.get("target_contract")
    if not isinstance(contract, dict):
        return False, False, False
    row = targets_by_id(matrix).get(str(evidence.get("target", ""))) if matrix is not None else None
    qemu_required = bool(row.get("qemu_test", False)) if isinstance(row, dict) else False
    production_required = bool(contract.get("production_required"))
    acceptance = str(contract.get("acceptance", ""))
    hardware_required = production_required or "hardware" in acceptance
    runtime_required = production_required
    return qemu_required, hardware_required, runtime_required


def validate_evidence(
    evidence_path: Path,
    matrix_path: Path | None,
    require_pass: bool,
    check_files: bool,
    release_tier: str | None,
    allow_tier_override: bool = False,
) -> list[str]:
    validation = Validation(evidence_path, check_files)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{evidence_path}: cannot read evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{evidence_path}: invalid JSON: {exc}"]
    if not isinstance(evidence, dict):
        return [f"{evidence_path}: top-level JSON value must be an object"]

    missing = sorted(TOP_LEVEL_FIELDS - set(evidence))
    extra = sorted(set(evidence) - TOP_LEVEL_FIELDS)
    if missing:
        validation.error("$", f"missing fields: {', '.join(missing)}")
    if extra:
        validation.error("$", f"unknown fields: {', '.join(extra)}")

    if evidence.get("schema_version") != SCHEMA_VERSION:
        validation.error("$.schema_version", f"must be {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at"):
        check_string(validation, f"$.{field}", evidence.get(field))
    parse_timestamp(validation, "$.generated_at", evidence.get("generated_at"), True)
    for field in ("version", "target"):
        value = evidence.get(field)
        if isinstance(value, str) and not SAFE_ID_RE.fullmatch(value):
            validation.error(f"$.{field}", "must be a safe path identifier")
    inferred_tier = release_tier_from_version(evidence.get("version"))
    effective_tier = release_tier or inferred_tier
    if release_tier is not None and release_tier != inferred_tier and not allow_tier_override:
        validation.error(
            "$.version",
            f"release tier must be {inferred_tier} for version {evidence.get('version')!r}",
        )

    check_path_contract(validation, evidence)

    matrix = None
    if matrix_path is not None:
        try:
            matrix = load_matrix(matrix_path)
        except (OSError, ValueError) as exc:
            validation.error("$matrix", f"cannot read matrix: {exc}")

    validate_target_contract(validation, evidence, matrix)
    qemu_required, hardware_required, runtime_required = expected_gate_requirements(evidence, matrix)
    validate_source(validation, evidence, require_pass)
    validate_asset_manifest(validation, evidence, require_pass)
    validate_artifacts(validation, evidence, require_pass, effective_tier)
    validate_sbom(validation, evidence, require_pass, effective_tier)
    validate_vex(validation, evidence, require_pass, effective_tier)
    validate_reproducibility(validation, evidence, require_pass)
    expected_security_scans = None
    if matrix is not None:
        expected_security_scans = [str(item) for item in matrix.get("security_scans", [])]
    validate_status_list(
        validation,
        "$.security_scans",
        evidence.get("security_scans"),
        require_pass,
        False,
        expected_security_scans if require_pass else None,
    )
    validate_machine_verification(validation, evidence, require_pass)
    validate_build_evidence(validation, evidence, require_pass)
    validate_preflight_inputs(validation, evidence, require_pass)
    validate_governance(validation, evidence, require_pass)
    validate_qemu(validation, evidence, require_pass, qemu_required)
    validate_runtime_qemu(validation, evidence, require_pass, effective_tier, runtime_required)
    validate_hardware(validation, evidence, require_pass, hardware_required)
    validate_station_acquisitions(validation, evidence, require_pass, effective_tier, hardware_required)
    validate_hsm_signing_sessions(validation, evidence, require_pass, effective_tier, runtime_required)
    validate_release_image_scan_reports(validation, evidence, require_pass, effective_tier, runtime_required)
    validate_runtime_checks(validation, evidence, require_pass, effective_tier, runtime_required)
    validate_approvals(validation, evidence, require_pass)
    validate_release_decision(validation, evidence, require_pass)
    validate_residual_risk(validation, evidence, require_pass)
    return validation.errors


def schema_contract() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "path": "release-evidence/<version>/<target>/evidence.json",
        "required_top_level_fields": sorted(TOP_LEVEL_FIELDS),
        "target_contract_fields": sorted(TARGET_CONTRACT_FIELDS),
        "status_values": sorted(STATUS_VALUES),
        "failure_class_values": sorted(FAILURE_CLASS_VALUES),
        "vex_status_values": sorted(VEX_STATUS_VALUES),
        "residual_risk_status_values": sorted(RISK_STATUS_VALUES),
        "release_decision_status_values": sorted(DECISION_STATUS_VALUES),
        "release_tiers": ["alpha", "production"],
        "asset_manifest_schema_version": ASSET_MANIFEST_SCHEMA_VERSION,
        "approval_schema_version": APPROVAL_SCHEMA_VERSION,
        "machine_verification_schema_version": MACHINE_VERIFICATION_SCHEMA_VERSION,
        "machine_verification_checks": list(MACHINE_VERIFICATION_CHECKS),
        "production_runtime_suite_schema_version": "suderra.qemu-production-runtime-suite.v1",
        "hsm_signing_session_schema_version": "suderra.hsm-signing-session.v2",
        "release_security_report_schema_version": "suderra.release-security-report.v2",
        "governance_checks": list(GOVERNANCE_CHECKS),
        "required_runtime_checks": list(REQUIRED_RUNTIME_CHECKS),
        "required_qemu_checks": list(REQUIRED_QEMU_CHECKS),
        "required_hardware_checks": list(REQUIRED_HARDWARE_CHECKS),
        "required_hardware_boards_by_target": {
            target: list(boards)
            for target, boards in sorted(REQUIRED_HARDWARE_BOARDS_BY_TARGET.items())
        },
        "release_ready_invariants": [
            "source.dirty is false and source.git_commit is a full commit sha",
            "asset_manifest is generated from staged release bytes and verified",
            "build logs, warning classifier evidence, and Buildroot source identity are retained in the bundle",
            "artifact hashes, sizes, signatures, and provenance are present, verified, and match referenced files",
            "SBOM is CycloneDX JSON with a non-empty matching component count and verified signature",
            "signed VEX is present",
            "reproducibility and every matrix security scan are passed with reports",
            "machine verification records bind SHA256SUMS, cosign, and attestation checks to structured subjects",
            "governance snapshots show branch, ruleset, tag, release-sign, and release-publish environment protections",
            "required QEMU and hardware evidence sections are passed",
            "required runtime checks have passed evidence files",
            "release_decision is approved or approved_with_residual_risk",
            "approval and decision timestamps are ISO-8601 UTC",
            "approved requires residual_risk.status none and no residual risk items",
            "approved_with_residual_risk requires accepted, future-expiring residual risk records",
        ],
    }


def generate_command(args: argparse.Namespace) -> int:
    matrix = load_matrix(args.matrix)
    row = targets_by_id(matrix).get(args.target)
    if row is None:
        print(f"ERROR: target not found in matrix: {args.target}", file=sys.stderr)
        return 1

    evidence = generated_evidence(
        args.version,
        row,
        [str(item) for item in matrix.get("security_scans", [])],
    )
    output = args.output
    if output is None:
        output = Path("release-evidence") / args.version / str(evidence["target"]) / "evidence.json"
    if output.exists() and not args.force:
        print(f"ERROR: refusing to overwrite existing evidence file: {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


def validate_command(args: argparse.Namespace) -> int:
    errors = validate_evidence(
        args.evidence,
        args.matrix,
        args.require_pass,
        args.check_files,
        args.release_tier,
        args.allow_tier_override,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    mode = "release-ready" if args.require_pass else "schema"
    print(f"validated {mode} evidence: {args.evidence}")
    return 0


def migrate_command(args: argparse.Namespace) -> int:
    try:
        evidence = json.loads(args.input.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"ERROR: cannot read evidence: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(evidence, dict):
        print("ERROR: top-level JSON value must be an object", file=sys.stderr)
        return 1
    if evidence.get("schema_version") not in LEGACY_SCHEMA_VERSIONS | {SCHEMA_VERSION}:
        print(f"ERROR: unsupported schema_version: {evidence.get('schema_version')!r}", file=sys.stderr)
        return 1
    evidence["schema_version"] = SCHEMA_VERSION
    governance = evidence.setdefault("governance", {})
    if isinstance(governance, dict):
        checks = governance.setdefault("checks", {})
        if isinstance(checks, dict):
            for name in GOVERNANCE_CHECKS:
                checks.setdefault(name, {"status": "not_collected", "evidence": None})
    output = args.output or args.input
    if output.exists() and output != args.input and not args.force:
        print(f"ERROR: refusing to overwrite existing evidence file: {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


def asset_manifest_command(args: argparse.Namespace) -> int:
    if not args.release_dir.is_dir():
        print(f"ERROR: release directory not found: {args.release_dir}", file=sys.stderr)
        return 1
    try:
        manifest = release_asset_manifest(args.version, args.release_dir, args.matrix, args.binding_manifest)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if not manifest["files"]:
        print(f"ERROR: release directory contains no files: {args.release_dir}", file=sys.stderr)
        return 1
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


def assemble_release_command(args: argparse.Namespace) -> int:
    matrix = load_matrix(args.matrix)
    asset_manifest_path = args.release_dir / "release-assets.json"
    asset_manifest = read_json(asset_manifest_path)
    if not isinstance(asset_manifest, dict):
        print(f"ERROR: missing release asset manifest: {asset_manifest_path}", file=sys.stderr)
        return 1
    failed = False
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        evidence = generated_evidence(
            args.version,
            row,
            [str(item) for item in matrix.get("security_scans", [])],
        )
        target = str(evidence["target"])
        bundle_dir = args.output_root / args.version / target
        if bundle_dir.exists() and args.force:
            shutil.rmtree(bundle_dir)
        elif bundle_dir.exists():
            print(f"ERROR: refusing to overwrite evidence bundle: {bundle_dir}", file=sys.stderr)
            failed = True
            continue
        bundle_dir.mkdir(parents=True, exist_ok=True)

        evidence["source"] = asset_manifest.get("source", evidence["source"])
        evidence["asset_manifest"]["path"] = copy_into_bundle(
            bundle_dir,
            asset_manifest_path,
            "release-assets.json",
        )
        evidence["asset_manifest"]["sha256"] = sha256_file(bundle_dir / "release-assets.json")
        evidence["asset_manifest"]["verified"] = True

        release_artifact = str(evidence["target_contract"]["release_artifact"])
        artifact_path = args.release_dir / release_artifact
        if artifact_path.is_file():
            artifact = evidence["artifacts"][0]
            artifact["path"] = copy_into_bundle(bundle_dir, artifact_path, f"artifacts/{release_artifact}")
            artifact["sha256"] = sha256_file(bundle_dir / artifact["path"])
            artifact["bytes"] = (bundle_dir / artifact["path"]).stat().st_size
            sig_path = args.release_dir / f"{release_artifact}.sig"
            cert_path = args.release_dir / f"{release_artifact}.cert"
            if sig_path.is_file() and cert_path.is_file():
                artifact["signature"]["path"] = copy_into_bundle(
                    bundle_dir,
                    sig_path,
                    f"artifacts/{release_artifact}.sig",
                )
                artifact["signature"]["certificate"] = copy_into_bundle(
                    bundle_dir,
                    cert_path,
                    f"artifacts/{release_artifact}.cert",
                )
                artifact["signature"]["verified"] = machine_record_covers_subject(
                    args.release_dir / "machine-verification" / "cosign.json",
                    name=release_artifact,
                    sha256=artifact["sha256"],
                )
            attestation_log = args.release_dir / "machine-verification" / "attestations.log"
            if attestation_log.is_file() and attestation_log.stat().st_size > 0:
                artifact["provenance"]["path"] = copy_into_bundle(
                    bundle_dir,
                    attestation_log,
                    f"provenance/{release_artifact}.attestation.log",
                )
                artifact["provenance"]["verified"] = machine_record_covers_subject(
                    args.release_dir / "machine-verification" / "attestations.json",
                    name=release_artifact,
                    sha256=artifact["sha256"],
                )

        sbom_name = f"{release_base(release_artifact)}.cyclonedx.json"
        sbom_path = args.release_dir / sbom_name
        if sbom_path.is_file():
            evidence["sbom"]["path"] = copy_into_bundle(bundle_dir, sbom_path, f"sbom/{sbom_name}")
            evidence["sbom"]["sha256"] = sha256_file(bundle_dir / evidence["sbom"]["path"])
            evidence["sbom"]["component_count"] = count_cyclonedx_components(bundle_dir / evidence["sbom"]["path"])
            if (args.release_dir / f"{sbom_name}.sig").is_file() and (args.release_dir / f"{sbom_name}.cert").is_file():
                evidence["sbom"]["signature_verified"] = True

        apply_machine_verification(bundle_dir, args.release_dir, evidence)
        apply_build_evidence(bundle_dir, args.input_root, args.version, target, evidence)
        apply_governance(bundle_dir, args.governance_root, args.version, evidence)
        apply_qemu_input(bundle_dir, args.lab_root, args.version, target, evidence)
        apply_hardware_input(bundle_dir, args.lab_root, args.governance_root, args.version, target, evidence)
        apply_release_inputs(bundle_dir, args.release_dir, args.input_root, args.version, target, evidence)

        evidence_path = bundle_dir / "evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(evidence_path)
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="create a blocked evidence.json skeleton")
    generate.add_argument("--version", required=True)
    generate.add_argument("--target", required=True, help="matrix target id or defconfig name")
    generate.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    generate.add_argument("--output", type=Path)
    generate.add_argument("--force", action="store_true")
    generate.set_defaults(func=generate_command)

    validate = subparsers.add_parser("validate", help="validate an evidence.json file")
    validate.add_argument("evidence", type=Path)
    validate.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate.add_argument("--require-pass", action="store_true")
    validate.add_argument("--check-files", action="store_true")
    validate.add_argument(
        "--release-tier",
        choices=("alpha", "production"),
        default=None,
        help="defaults from SemVer; alpha relaxes production-only VEX/runtime gates",
    )
    validate.add_argument(
        "--allow-tier-override",
        action="store_true",
        help="unsafe/dev-only: allow --release-tier to disagree with the SemVer tag",
    )
    validate.set_defaults(func=validate_command)

    migrate = subparsers.add_parser("migrate", help="migrate legacy evidence JSON to the current schema")
    migrate.add_argument("input", type=Path)
    migrate.add_argument("--output", type=Path)
    migrate.add_argument("--force", action="store_true")
    migrate.set_defaults(func=migrate_command)

    schema = subparsers.add_parser("schema", help="print the canonical evidence contract")
    schema.set_defaults(
        func=lambda _args: print(json.dumps(schema_contract(), indent=2, sort_keys=True)) or 0
    )

    asset_manifest = subparsers.add_parser(
        "asset-manifest",
        help="write an immutable manifest for staged release assets",
    )
    asset_manifest.add_argument("--version", required=True)
    asset_manifest.add_argument("--release-dir", type=Path, required=True)
    asset_manifest.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    asset_manifest.add_argument("--binding-manifest", type=Path)
    asset_manifest.add_argument("--output", type=Path, required=True)
    asset_manifest.set_defaults(func=asset_manifest_command)

    assemble_release = subparsers.add_parser(
        "assemble-release",
        help="assemble target evidence bundles from staged release bytes and release inputs",
    )
    assemble_release.add_argument("--version", required=True)
    assemble_release.add_argument("--release-dir", type=Path, required=True)
    assemble_release.add_argument("--output-root", type=Path, default=Path("release-evidence"))
    assemble_release.add_argument("--input-root", type=Path, default=Path("."))
    assemble_release.add_argument("--lab-root", type=Path, default=Path("release-lab-input"))
    assemble_release.add_argument("--governance-root", type=Path, default=Path("release-governance"))
    assemble_release.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    assemble_release.add_argument("--force", action="store_true")
    assemble_release.set_defaults(func=assemble_release_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
