#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Pre-tag/pre-publish release input readiness gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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


def find_hsm_certificate(session: Path, payload: dict[str, Any]) -> Path | None:
    certificate_ref = payload.get("certificate_path")
    certificate = payload.get("certificate")
    if isinstance(certificate, dict) and isinstance(certificate.get("path"), str):
        certificate_ref = certificate["path"]
    if isinstance(certificate_ref, str) and certificate_ref.strip():
        candidate = Path(certificate_ref)
        if not candidate.is_absolute():
            candidate = session.parent / candidate
        if candidate.is_file():
            return candidate
    expected_sha = payload.get("certificate_sha256")
    if isinstance(expected_sha, str) and SHA256_RE.fullmatch(expected_sha):
        for candidate in sorted(session.parent.glob("*")):
            if candidate.is_file() and candidate.suffix.lower() in {".crt", ".cer", ".pem"}:
                try:
                    if sha256_file(candidate) == expected_sha:
                        return candidate
                except OSError:
                    continue
    return None


EVIDENCE_CONTRACT = evidence_contract.load_contract()
SIGNED_ARTIFACT_ROLES = evidence_contract.signed_artifact_roles(EVIDENCE_CONTRACT)
SIGNING_ROLE_BINDINGS = evidence_contract.signing_role_bindings(EVIDENCE_CONTRACT)


def validate_hsm_session_replay(
    session: Path,
    payload: dict[str, Any],
    failures: list[str],
    *,
    expected_artifact_sha256s: set[str] | None = None,
) -> None:
    cert = find_hsm_certificate(session, payload)
    if cert is None:
        failures.append(f"HSM signing session certificate file is missing or not digest-bound: {session}")
        return
    pkcs11_uri = payload.get("pkcs11_uri")
    if not isinstance(pkcs11_uri, str) or not pkcs11_uri.strip():
        failures.append(f"HSM signing session missing pkcs11_uri: {session}")
        return
    artifacts = payload.get("artifacts")
    replay_items = artifacts if isinstance(artifacts, list) and artifacts else [None]
    matched_expected_artifact = expected_artifact_sha256s is None
    for artifact in replay_items:
        replay_args = [
            sys.executable,
            "scripts/evidence/validate-hsm-signing-evidence.py",
            "validate",
            str(session),
            "--pkcs11-uri",
            pkcs11_uri,
            "--certificate",
            str(cert),
            "--require-production",
            "--replay-crypto",
        ]
        if isinstance(artifact, dict):
            role = artifact.get("role")
            digest = artifact.get("sha256")
            if (
                expected_artifact_sha256s is not None
                and isinstance(role, str)
                and role in SIGNED_ARTIFACT_ROLES
                and isinstance(digest, str)
                and digest in expected_artifact_sha256s
            ):
                matched_expected_artifact = True
            if isinstance(role, str) and role.strip():
                replay_args.extend(["--artifact-role", role])
            if isinstance(digest, str) and digest.strip():
                replay_args.extend(["--artifact-sha256", digest])
            artifact_path = artifact.get("path")
            if isinstance(artifact_path, str) and artifact_path.strip():
                candidate = Path(artifact_path)
                if not candidate.is_absolute():
                    candidate = session.parent / candidate
                if not candidate.is_file():
                    failures.append(f"HSM artifact path missing: {session}: {artifact_path}")
                else:
                    if candidate.stat().st_size != artifact.get("bytes"):
                        failures.append(f"HSM artifact bytes mismatch: {session}: {artifact_path}")
                    if sha256_file(candidate) != digest:
                        failures.append(f"HSM artifact sha256 mismatch: {session}: {artifact_path}")
        failures.extend(run(replay_args))
    if not matched_expected_artifact:
        expected = ", ".join(sorted(expected_artifact_sha256s or [])) or "no bound artifacts"
        failures.append(f"HSM signing session does not bind a release artifact digest for {session}: {expected}")


def expected_release_subject_id(
    version: str,
    target: str,
    source_sha: str | None,
    source_run_id: str | None,
) -> str | None:
    if source_sha is None or source_run_id is None:
        return None
    return evidence_contract.release_subject_id(
        version=version,
        target=target,
        source_sha=source_sha,
        source_run_id=str(source_run_id),
        contract=EVIDENCE_CONTRACT,
    )


def _relative_non_placeholder(value: Any) -> bool:
    if is_placeholder(value) or not isinstance(value, str) or not value.strip():
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def _subject_graph_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    subjects = payload.get("subjects")
    if isinstance(subjects, list):
        return [item for item in subjects if isinstance(item, dict)]
    nodes = payload.get("nodes")
    if isinstance(nodes, list):
        return [
            item
            for item in nodes
            if isinstance(item, dict) and item.get("role") in {None, "release-subject", "root-subject"}
        ]
    if isinstance(payload.get("subject_id"), str):
        return [payload]
    return []


def _subject_graph_evidence_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = payload.get("evidence_nodes")
    if isinstance(nodes, list):
        return [item for item in nodes if isinstance(item, dict)]
    return []


def _safe_relative_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    return rel


def validate_subject_graph(
    path: Path,
    *,
    version: str,
    profile: str,
    source_sha: str | None,
    source_run_id: str | None,
    matrix: dict[str, Any],
    binding: dict[str, Any] | None,
    root: Path | None = None,
    check_files: bool = False,
) -> list[str]:
    failures: list[str] = []
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"release subject graph missing or invalid JSON: {path}"]
    schema_version = evidence_contract.schema_version("release_subject_graph", EVIDENCE_CONTRACT)
    if payload.get("schema_version") != schema_version:
        failures.append(f"release subject graph schema_version must be {schema_version}: {path}")
    if payload.get("version") not in {None, version}:
        failures.append(f"release subject graph version mismatch: {path}")
    if payload.get("profile") not in {None, profile}:
        failures.append(f"release subject graph profile mismatch: {path}")
    if source_sha is None or source_run_id is None:
        failures.append("release subject graph validation requires source_sha and source_run_id")
        return failures
    nodes = _subject_graph_nodes(payload)
    if not nodes:
        failures.append(f"release subject graph must contain subject nodes: {path}")
        return failures
    subject_ids = {str(node.get("subject_id")) for node in nodes if isinstance(node.get("subject_id"), str)}
    by_target = {str(node.get("target")): node for node in nodes if isinstance(node.get("target"), str)}
    for row in matrix.get("defconfigs", []):
        if not isinstance(row, dict) or not row.get("target"):
            continue
        target = str(row["target"])
        policy = evidence_contract.target_policy(target, EVIDENCE_CONTRACT)
        if not policy or not (policy.get("production_gate") or policy.get("release_public")):
            continue
        node = by_target.get(target)
        if not isinstance(node, dict):
            failures.append(f"release subject graph missing target node: {target}")
            continue
        expected_subject = evidence_contract.release_subject_id(
            version=version,
            target=target,
            source_sha=source_sha,
            source_run_id=str(source_run_id),
            contract=EVIDENCE_CONTRACT,
        )
        if node.get("subject_id") != expected_subject:
            failures.append(f"release subject graph subject_id mismatch for {target}: {path}")
        if node.get("source_sha") != source_sha:
            failures.append(f"release subject graph source_sha mismatch for {target}: {path}")
        if str(node.get("source_run_id")) != str(source_run_id):
            failures.append(f"release subject graph source_run_id mismatch for {target}: {path}")
        if node.get("defconfig") not in {None, row.get("name")}:
            failures.append(f"release subject graph defconfig mismatch for {target}: {path}")
        if profile == "production-candidate":
            raw = node.get("raw_image_sha256")
            raw_bytes = node.get("raw_image_bytes")
            if not isinstance(raw, str) or not SHA256_RE.fullmatch(raw) or raw == "0" * 64:
                failures.append(f"release subject graph raw_image_sha256 must be bound for {target}: {path}")
            if not isinstance(raw_bytes, int) or raw_bytes <= 0:
                failures.append(f"release subject graph raw_image_bytes must be bound for {target}: {path}")
        refs = binding_artifact_refs_for_target(binding, target)
        artifact_digests = {str(item.get("sha256")) for item in refs}
        compressed = node.get("compressed_artifact_sha256")
        compressed_bytes = node.get("compressed_artifact_bytes")
        artifacts = node.get("artifacts") if isinstance(node.get("artifacts"), dict) else {}
        if compressed is None and isinstance(artifacts, dict):
            compressed_ref = artifacts.get("compressed_release_artifact")
            if isinstance(compressed_ref, dict):
                compressed = compressed_ref.get("sha256")
                compressed_bytes = compressed_ref.get("bytes")
        if profile == "production-candidate":
            if not isinstance(compressed, str) or not SHA256_RE.fullmatch(compressed) or compressed == "0" * 64:
                failures.append(f"release subject graph compressed_artifact_sha256 must be bound for {target}: {path}")
            if not isinstance(compressed_bytes, int) or compressed_bytes <= 0:
                failures.append(f"release subject graph compressed_artifact_bytes must be bound for {target}: {path}")
        if artifact_digests and compressed not in artifact_digests:
            failures.append(f"release subject graph compressed artifact digest must bind release input for {target}: {path}")
    evidence_nodes = _subject_graph_evidence_nodes(payload)
    if not evidence_nodes:
        failures.append(f"release subject graph must contain evidence_nodes closure: {path}")
        return failures
    edges = payload.get("evidence_edges")
    if not isinstance(edges, list) or not edges:
        failures.append(f"release subject graph must contain evidence_edges closure: {path}")
        edges = []
    edge_pairs = {
        (str(edge.get("from")), str(edge.get("to")))
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("from"), str) and isinstance(edge.get("to"), str)
    }
    seen_node_ids: set[str] = set()
    for idx, item in enumerate(evidence_nodes):
        node_path = f"release subject graph evidence_nodes[{idx}]"
        node_id = item.get("node_id")
        subject_id = item.get("subject_id")
        if not isinstance(node_id, str) or not node_id.strip():
            failures.append(f"{node_path}.node_id is required: {path}")
            continue
        if node_id in seen_node_ids:
            failures.append(f"{node_path}.node_id must be unique: {path}")
        seen_node_ids.add(node_id)
        if subject_id not in subject_ids:
            failures.append(f"{node_path}.subject_id must reference a subject node: {path}")
        if (str(subject_id), node_id) not in edge_pairs:
            failures.append(f"{node_path} must have a subject evidence edge: {path}")
        for field in ("role", "schema_role", "schema_version", "producer"):
            if is_placeholder(item.get(field)) or not isinstance(item.get(field), str):
                failures.append(f"{node_path}.{field} must be non-placeholder: {path}")
        rel = _safe_relative_path(item.get("path"))
        if rel is None:
            failures.append(f"{node_path}.path must be a relative non-placeholder path: {path}")
            continue
        required = item.get("required") is True
        if profile == "production-candidate" and item.get("role") in {"raw-image", "compressed-release-artifact"}:
            for field in ("sha256", "bytes"):
                if field == "sha256":
                    value = item.get(field)
                    if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                        failures.append(f"{node_path}.{field} must bind production artifact bytes: {path}")
                elif not isinstance(item.get(field), int) or item.get(field, 0) <= 0:
                    failures.append(f"{node_path}.{field} must bind production artifact bytes: {path}")
        if check_files and required and root is not None:
            actual = root / rel
            if not actual.is_file() or actual.stat().st_size <= 0:
                failures.append(f"{node_path}.path missing required evidence file: {actual}")
                continue
            expected_sha = item.get("sha256")
            expected_bytes = item.get("bytes")
            if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha) or expected_sha == "0" * 64:
                failures.append(f"{node_path}.sha256 must be preserved for required evidence: {path}")
            elif sha256_file(actual) != expected_sha:
                failures.append(f"{node_path}.sha256 mismatch for required evidence: {actual}")
            if not isinstance(expected_bytes, int) or expected_bytes <= 0:
                failures.append(f"{node_path}.bytes must be preserved for required evidence: {path}")
            elif actual.stat().st_size != expected_bytes:
                failures.append(f"{node_path}.bytes mismatch for required evidence: {actual}")
    required_paths = payload.get("required_paths")
    if not isinstance(required_paths, list) or not required_paths:
        failures.append(f"release subject graph required_paths must be non-empty: {path}")
    else:
        node_required_paths = {
            str(item.get("path"))
            for item in evidence_nodes
            if item.get("required") is True and isinstance(item.get("path"), str)
        }
        listed_required_paths = {str(item) for item in required_paths if isinstance(item, str)}
        missing_listed = sorted(node_required_paths - listed_required_paths)
        if missing_listed:
            failures.append("release subject graph required_paths missing node paths: " + ", ".join(missing_listed))
    closure = payload.get("retention_closure")
    if not isinstance(closure, dict):
        failures.append(f"release subject graph retention_closure is required: {path}")
    else:
        expected_exports = set(evidence_contract.retention_required_exports(EVIDENCE_CONTRACT))
        actual_exports = {str(item) for item in closure.get("required_exports", []) if isinstance(item, str)}
        missing_exports = sorted(expected_exports - actual_exports)
        if missing_exports:
            failures.append("release subject graph retention_closure missing exports: " + ", ".join(missing_exports))
    return failures


def expected_signing_roles_for_policy(policy: dict[str, Any]) -> set[str]:
    roles: set[str] = set()
    if policy.get("ota_capable") is True:
        roles.update(
            role
            for role, binding in SIGNING_ROLE_BINDINGS.items()
            if binding.get("required_for_ota_capable") is True
        )
    if policy.get("release_public") is True:
        roles.update(
            role
            for role, binding in SIGNING_ROLE_BINDINGS.items()
            if binding.get("required_for_release_public") is True
        )
    return roles


def validate_signing_manifest(
    path: Path,
    *,
    version: str,
    target: str,
    source_sha: str | None,
    source_run_id: str | None,
    expected_artifact_sha256s: set[str],
    expected_role_output_sha256s: dict[str, str] | None = None,
) -> list[str]:
    failures: list[str] = []
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"signing manifest missing or invalid JSON: {path}"]
    schema_version = evidence_contract.schema_version("signing_manifest", EVIDENCE_CONTRACT)
    if payload.get("schema_version") != schema_version:
        failures.append(f"signing manifest schema_version must be {schema_version}: {path}")
    for field, expected in (("version", version), ("target", target)):
        if payload.get(field) != expected:
            failures.append(f"signing manifest {field} mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"signing manifest source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"signing manifest source_run_id mismatch: {path}")
    subject_id = expected_release_subject_id(version, target, source_sha, source_run_id)
    if subject_id is None:
        failures.append(f"signing manifest validation requires source_sha and source_run_id: {path}")
    elif payload.get("subject_id") != subject_id:
        failures.append(f"signing manifest subject_id mismatch: {path}")
    policy = evidence_contract.target_policy(target, EVIDENCE_CONTRACT)
    expected_roles = expected_signing_roles_for_policy(policy)
    roles = payload.get("roles")
    if not isinstance(roles, list) or not roles:
        failures.append(f"signing manifest roles must be non-empty: {path}")
        return failures
    seen_roles: set[str] = set()
    for idx, role_payload in enumerate(roles):
        if not isinstance(role_payload, dict):
            failures.append(f"signing manifest roles[{idx}] must be an object: {path}")
            continue
        role = role_payload.get("role")
        if isinstance(role, str):
            if role in seen_roles:
                failures.append(f"signing manifest roles[{idx}].role must be unique: {path}")
            seen_roles.add(role)
        if role not in SIGNED_ARTIFACT_ROLES:
            failures.append(f"signing manifest roles[{idx}].role is not governed: {path}")
        for field in EVIDENCE_CONTRACT["signing"]["role_required_fields"]:
            value = role_payload.get(field)
            if field.endswith("sha256"):
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                    failures.append(f"signing manifest roles[{idx}].{field} must be a non-zero sha256: {path}")
            elif field == "artifact_bytes":
                if not isinstance(value, int) or value <= 0:
                    failures.append(f"signing manifest roles[{idx}].artifact_bytes must be positive: {path}")
            elif field == "artifact_path":
                if not _relative_non_placeholder(value):
                    failures.append(f"signing manifest roles[{idx}].artifact_path must be a safe relative path: {path}")
            elif field == "replay_status":
                if value != "passed":
                    failures.append(f"signing manifest roles[{idx}].replay_status must be passed: {path}")
            elif is_placeholder(value) or not isinstance(value, str) or not value.strip():
                failures.append(f"signing manifest roles[{idx}].{field} must be non-placeholder: {path}")
        pkcs11_uri = role_payload.get("pkcs11_uri")
        if isinstance(pkcs11_uri, str) and any(token in pkcs11_uri.lower() for token in ("softhsm", "file:", "software")):
            failures.append(f"signing manifest roles[{idx}].pkcs11_uri must name a production HSM token: {path}")
        output_sha = role_payload.get("output_sha256")
        if expected_artifact_sha256s and role in {"release-artifact", "release-image"} and output_sha not in expected_artifact_sha256s:
            failures.append(f"signing manifest roles[{idx}].output_sha256 must bind release artifact digest: {path}")
        if expected_role_output_sha256s and isinstance(role, str) and role in expected_role_output_sha256s:
            if output_sha != expected_role_output_sha256s[role]:
                failures.append(
                    f"signing manifest roles[{idx}].output_sha256 must bind {role} OTA artifact digest: {path}"
                )
        verifier = role_payload.get("verifier")
        if isinstance(role, str) and isinstance(verifier, str):
            verifier_text = verifier.strip()
            role_verifier_tokens = {
                "rauc-bundle": ("rauc info", "rauc verify"),
                "release-image": ("sbverify",),
                "release-artifact": ("cosign verify-blob",),
                "os-update-manifest": ("create-os-update-manifest.py verify", "suderra-ota verify-manifest"),
            }
            expected_tokens = role_verifier_tokens.get(role)
            if expected_tokens and not any(token in verifier_text for token in expected_tokens):
                failures.append(f"signing manifest roles[{idx}].verifier must be role-specific replay command for {role}: {path}")
    missing = sorted(expected_roles - seen_roles)
    if missing:
        failures.append(f"signing manifest missing required roles for {target}: {', '.join(missing)}")
    return failures


def ota_signing_digest_expectations(path: Path) -> dict[str, str]:
    payload = read_json(path)
    expectations: dict[str, str] = {}
    if not isinstance(payload, dict):
        return expectations
    bundle = payload.get("bundle")
    if isinstance(bundle, dict) and isinstance(bundle.get("sha256"), str):
        expectations["rauc-bundle"] = bundle["sha256"]
    manifest = payload.get("manifest")
    if isinstance(manifest, dict) and isinstance(manifest.get("sha256"), str):
        expectations["os-update-manifest"] = manifest["sha256"]
    return expectations


def station_registry_entry(registry: dict[str, Any] | None, station_id: Any) -> dict[str, Any] | None:
    if not isinstance(registry, dict) or not isinstance(station_id, str) or not station_id:
        return None
    stations = registry.get("stations")
    if not isinstance(stations, list):
        return None
    for station in stations:
        if isinstance(station, dict) and station.get("station_id") == station_id:
            return station
    return None


def station_acquisition_measurements(payload: dict[str, Any] | None) -> dict[str, Any]:
    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        return {
            "event_ids": set(),
            "events_by_id": {},
            "readback_sha256s": set(),
            "storage_by_ids": set(),
        }
    event_ids: set[str] = set()
    events_by_id: dict[str, dict[str, Any]] = {}
    readback_sha256s: set[str] = set()
    storage_by_ids: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = event.get("event_id")
        if isinstance(event_id, str):
            event_ids.add(event_id)
            events_by_id[event_id] = event
        measured = event.get("measured")
        if not isinstance(measured, dict):
            continue
        role = event.get("role")
        if role == "readback":
            for field in ("sha256", "actual_sha256", "readback_sha256"):
                value = measured.get(field)
                if isinstance(value, str) and SHA256_RE.fullmatch(value):
                    readback_sha256s.add(value)
        if role == "storage":
            by_id = measured.get("by_id") or measured.get("storage_by_id")
            if isinstance(by_id, str) and by_id.strip():
                storage_by_ids.add(by_id)
    return {
        "event_ids": event_ids,
        "events_by_id": events_by_id,
        "readback_sha256s": readback_sha256s,
        "storage_by_ids": storage_by_ids,
    }


def validate_hardware_subject(
    path: Path,
    *,
    version: str,
    target: str,
    source_sha: str | None,
    source_run_id: str | None,
    expected_artifact_sha256s: set[str],
    station_event_ids: set[str] | None = None,
    station_acquisition: dict[str, Any] | None = None,
    station_registry: dict[str, Any] | None = None,
) -> list[str]:
    failures: list[str] = []
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"hardware subject missing or invalid JSON: {path}"]
    schema_version = evidence_contract.schema_version("hardware_subject", EVIDENCE_CONTRACT)
    if payload.get("schema_version") != schema_version:
        failures.append(f"hardware subject schema_version must be {schema_version}: {path}")
    for field, expected in (("version", version), ("target", target)):
        if payload.get(field) != expected:
            failures.append(f"hardware subject {field} mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"hardware subject source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"hardware subject source_run_id mismatch: {path}")
    subject_id = expected_release_subject_id(version, target, source_sha, source_run_id)
    if subject_id is None:
        failures.append(f"hardware subject validation requires source_sha and source_run_id: {path}")
    elif payload.get("subject_id") != subject_id:
        failures.append(f"hardware subject subject_id mismatch: {path}")
    for field in EVIDENCE_CONTRACT["hardware"]["subject_binding"]["required_fields"]:
        if is_placeholder(payload.get(field)) or payload.get(field) is None:
            failures.append(f"hardware subject missing required field {field}: {path}")
    readback_sha = payload.get("readback_sha256")
    compressed_sha = payload.get("compressed_artifact_sha256")
    raw_sha = payload.get("raw_image_sha256")
    for field, value in (
        ("readback_sha256", readback_sha),
        ("compressed_artifact_sha256", compressed_sha),
        ("raw_image_sha256", raw_sha),
        ("adapter_inventory_sha256", payload.get("adapter_inventory_sha256")),
    ):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
            failures.append(f"hardware subject {field} must be a non-zero sha256: {path}")
    if expected_artifact_sha256s and compressed_sha not in expected_artifact_sha256s and readback_sha not in expected_artifact_sha256s:
        failures.append(f"hardware subject must bind a release artifact digest for {target}: {path}")
    if readback_sha != raw_sha and readback_sha != compressed_sha:
        failures.append(f"hardware subject readback_sha256 must match raw or compressed build subject: {path}")
    event_id = payload.get("station_acquisition_event_id")
    if station_event_ids is not None and event_id not in station_event_ids:
        failures.append(f"hardware subject station_acquisition_event_id must match station-acquisition event: {path}")
    if station_acquisition is not None:
        if station_acquisition.get("version") != version:
            failures.append(f"hardware subject station-acquisition version mismatch: {path}")
        if station_acquisition.get("target") != target:
            failures.append(f"hardware subject station-acquisition target mismatch: {path}")
        if source_sha is not None and station_acquisition.get("source_sha") != source_sha:
            failures.append(f"hardware subject station-acquisition source_sha mismatch: {path}")
        if source_run_id is not None and str(station_acquisition.get("source_run_id")) != str(source_run_id):
            failures.append(f"hardware subject station-acquisition source_run_id mismatch: {path}")
        if payload.get("station_id") != station_acquisition.get("station_id"):
            failures.append(f"hardware subject station_id must come from station-acquisition evidence: {path}")
        if payload.get("adapter_inventory_sha256") != station_acquisition.get("registry_sha256"):
            failures.append(f"hardware subject adapter_inventory_sha256 must match station registry digest: {path}")
        acquisition_sha = station_acquisition.get("artifact_sha256")
        if isinstance(acquisition_sha, str) and readback_sha != acquisition_sha:
            failures.append(f"hardware subject readback_sha256 must match station-acquisition readback artifact: {path}")
        measurements = station_acquisition_measurements(station_acquisition)
        if event_id not in measurements["events_by_id"]:
            failures.append(f"hardware subject station_acquisition_event_id must identify a station event: {path}")
        if measurements["readback_sha256s"] and readback_sha not in measurements["readback_sha256s"]:
            failures.append(f"hardware subject readback_sha256 must be derived from station readback event: {path}")
        storage_by_id = payload.get("storage_by_id")
        if measurements["storage_by_ids"] and storage_by_id not in measurements["storage_by_ids"]:
            failures.append(f"hardware subject storage_by_id must be derived from station storage event: {path}")
        device_identity = payload.get("device_identity")
        if isinstance(device_identity, dict) and isinstance(storage_by_id, str):
            device_storage = device_identity.get("storage_by_id")
            if device_storage != storage_by_id:
                failures.append(f"hardware subject device_identity.storage_by_id must match storage_by_id: {path}")
    if station_registry is not None:
        entry = station_registry_entry(station_registry, payload.get("station_id"))
        if entry is None:
            failures.append(f"hardware subject station_id must exist in station registry: {path}")
        else:
            if payload.get("fixture_id") != entry.get("fixture_id"):
                failures.append(f"hardware subject fixture_id must match station registry: {path}")
            allowed_storage = entry.get("allowed_storage_by_id")
            storage_by_id = payload.get("storage_by_id")
            if isinstance(allowed_storage, list) and storage_by_id not in allowed_storage:
                failures.append(f"hardware subject storage_by_id must be allowed by station registry: {path}")
    return failures


def validate_governance_role_bindings(
    path: Path,
    *,
    version: str,
) -> list[str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"governance role bindings missing or invalid JSON: {path}"]
    failures: list[str] = []
    schema_version = evidence_contract.schema_version("governance_role_bindings", EVIDENCE_CONTRACT)
    if payload.get("schema_version") != schema_version:
        failures.append(f"governance role bindings schema_version must be {schema_version}: {path}")
    if payload.get("version") != version:
        failures.append(f"governance role bindings version mismatch: {path}")
    bindings = payload.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        failures.append(f"governance role bindings must be non-empty: {path}")
        return failures
    seen_roles: set[str] = set()
    for idx, item in enumerate(bindings):
        if not isinstance(item, dict):
            failures.append(f"governance role bindings[{idx}] must be an object: {path}")
            continue
        role = item.get("role")
        if isinstance(role, str):
            seen_roles.add(role)
        for field in (
            "role",
            "github_subject",
            "subject_type",
            "github_node_id",
            "source_snapshot_sha256",
            "permission_snapshot_sha256",
            "environment_reviewer_binding_sha256",
            "effective_permission",
        ):
            if not isinstance(item.get(field), str) or not item[field].strip():
                failures.append(f"governance role bindings[{idx}].{field} must be non-empty: {path}")
        if item.get("github_subject") == role:
            failures.append(f"governance role bindings[{idx}].github_subject must be a real GitHub identity, not the role name: {path}")
        if item.get("subject_type") not in {"user", "team", "github-app"}:
            failures.append(f"governance role bindings[{idx}].subject_type must identify a GitHub user/team/app: {path}")
        if isinstance(item.get("github_node_id"), str) and item["github_node_id"].lower() in {"unknown", "pending", "not_collected"}:
            failures.append(f"governance role bindings[{idx}].github_node_id must be the real GitHub node id: {path}")
        if item.get("effective_permission") not in {"admin", "maintain", "write"}:
            failures.append(f"governance role bindings[{idx}].effective_permission must be admin/maintain/write: {path}")
        for sha_field in ("source_snapshot_sha256", "permission_snapshot_sha256", "environment_reviewer_binding_sha256"):
            if isinstance(item.get(sha_field), str) and not SHA256_RE.fullmatch(item[sha_field]):
                failures.append(f"governance role bindings[{idx}].{sha_field} must be a sha256: {path}")
    for role in ("release-owner", "security-owner"):
        if role not in seen_roles:
            failures.append(f"governance role bindings missing {role}: {path}")
    return failures


def validate_retention_manifest(
    path: Path,
    *,
    version: str,
    source_sha: str | None,
    source_run_id: str | None,
) -> list[str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"retention manifest missing or invalid JSON: {path}"]
    failures: list[str] = []
    policy = evidence_contract.retention_policy(EVIDENCE_CONTRACT)
    if payload.get("schema_version") != policy["manifest_schema_version"]:
        failures.append(f"retention manifest schema_version must be {policy['manifest_schema_version']}: {path}")
    if payload.get("policy_id") != policy["policy_id"]:
        failures.append(f"retention manifest policy_id mismatch: {path}")
    if payload.get("version") != version:
        failures.append(f"retention manifest version mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"retention manifest source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"retention manifest source_run_id mismatch: {path}")
    if payload.get("store_class") != policy["store_class"]:
        failures.append(f"retention manifest store_class mismatch: {path}")
    if not isinstance(payload.get("retention_years"), int) or payload["retention_years"] < policy["minimum_years"]:
        failures.append(f"retention manifest retention_years must be at least {policy['minimum_years']}: {path}")
    exports = payload.get("exports")
    if not isinstance(exports, list):
        failures.append(f"retention manifest exports must be a list: {path}")
        exports = []
    export_names = {item.get("name") for item in exports if isinstance(item, dict)}
    missing_exports = sorted(set(policy["required_exports"]) - export_names)
    if missing_exports:
        failures.append(f"retention manifest missing exports: {', '.join(missing_exports)}")
    replay_tests = payload.get("restore_replay_tests")
    if not isinstance(replay_tests, list) or not replay_tests:
        failures.append(f"retention manifest restore_replay_tests must be non-empty: {path}")
        replay_tests = []
    replay_names = {item.get("name") for item in replay_tests if isinstance(item, dict) and item.get("status") == "passed"}
    missing_replay = sorted(set(policy["required_replay"]) - replay_names)
    if missing_replay:
        failures.append(f"retention manifest missing passed replay tests: {', '.join(missing_replay)}")
    for field in (
        "kms_key_id",
        "custody_chain",
        "access_log",
        "archive_object_uri",
        "archive_object_version_id",
        "archive_object_sha256",
        "retention_lock_mode",
        "retain_until",
        "legal_hold_status",
        "access_log_sha256",
        "restore_job_id",
        "restored_archive_sha256",
        "replay_validator_output_sha256",
    ):
        if is_placeholder(payload.get(field)) or not isinstance(payload.get(field), str):
            failures.append(f"retention manifest {field} must be non-placeholder: {path}")
    for field in ("archive_object_sha256", "access_log_sha256", "restored_archive_sha256", "replay_validator_output_sha256"):
        value = payload.get(field)
        if isinstance(value, str) and not SHA256_RE.fullmatch(value):
            failures.append(f"retention manifest {field} must be a sha256: {path}")
    archive_uri = payload.get("archive_object_uri")
    if isinstance(archive_uri, str):
        if "://" not in archive_uri or archive_uri.startswith("github-artifact://"):
            failures.append(f"retention manifest archive_object_uri must be an immutable archive object URI, not transient CI storage: {path}")
    if str(payload.get("retention_lock_mode", "")).lower() not in {"governance", "compliance"}:
        failures.append(f"retention manifest retention_lock_mode must be governance or compliance: {path}")
    if payload.get("restored_archive_sha256") != payload.get("archive_object_sha256"):
        failures.append(f"retention manifest restored_archive_sha256 must match archived object digest after restore: {path}")
    retain_until = payload.get("retain_until")
    if isinstance(retain_until, str):
        try:
            parsed_retain_until = datetime.fromisoformat(retain_until.replace("Z", "+00:00"))
        except ValueError:
            failures.append(f"retention manifest retain_until must be an ISO-8601 UTC timestamp: {path}")
        else:
            if parsed_retain_until.tzinfo is None:
                failures.append(f"retention manifest retain_until must include timezone: {path}")
            elif parsed_retain_until.astimezone(timezone.utc) <= datetime.now(timezone.utc):
                failures.append(f"retention manifest retain_until must be in the future: {path}")
    legal_hold_id = payload.get("legal_hold_id")
    if not isinstance(legal_hold_id, str) or not legal_hold_id.strip():
        failures.append(f"retention manifest legal_hold_id must be non-placeholder: {path}")
    custody_events = payload.get("custody_events")
    if not isinstance(custody_events, list) or not custody_events:
        failures.append(f"retention manifest custody_events must be a non-empty list: {path}")
    else:
        for idx, event in enumerate(custody_events):
            if not isinstance(event, dict):
                failures.append(f"retention manifest custody_events[{idx}] must be an object: {path}")
                continue
            for field in ("event_id", "event_type", "actor", "occurred_at", "evidence_sha256"):
                if not isinstance(event.get(field), str) or not event[field].strip():
                    failures.append(f"retention manifest custody_events[{idx}].{field} must be non-empty: {path}")
            value = event.get("evidence_sha256")
            if isinstance(value, str) and not SHA256_RE.fullmatch(value):
                failures.append(f"retention manifest custody_events[{idx}].evidence_sha256 must be a sha256: {path}")
    return failures


def validate_ota_artifacts(
    path: Path,
    *,
    version: str,
    target: str,
    source_sha: str | None,
    source_run_id: str | None,
) -> list[str]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return [f"OTA artifacts manifest missing or invalid JSON: {path}"]
    failures: list[str] = []
    schema_version = evidence_contract.schema_version("ota_artifacts", EVIDENCE_CONTRACT)
    if payload.get("schema_version") != schema_version:
        failures.append(f"OTA artifacts schema_version must be {schema_version}: {path}")
    for field, expected in (("version", version), ("target", target)):
        if payload.get(field) != expected:
            failures.append(f"OTA artifacts {field} mismatch: {path}")
    if source_sha is not None and payload.get("source_sha") != source_sha:
        failures.append(f"OTA artifacts source_sha mismatch: {path}")
    if source_run_id is not None and str(payload.get("source_run_id")) != str(source_run_id):
        failures.append(f"OTA artifacts source_run_id mismatch: {path}")
    subject_id = expected_release_subject_id(version, target, source_sha, source_run_id)
    if subject_id is not None and payload.get("subject_id") != subject_id:
        failures.append(f"OTA artifacts subject_id mismatch: {path}")
    policy = evidence_contract.ota_target_policy(target, EVIDENCE_CONTRACT)
    if policy.get("ota_capable") is not True:
        failures.append(f"OTA artifacts supplied for non-OTA target {target}: {path}")
    contract = payload.get("ota_contract")
    if not isinstance(contract, dict):
        failures.append(f"OTA artifacts ota_contract must be an object: {path}")
    else:
        for field in ("compatible", "boot_backend", "backend", "mark_good_policy", "rollback_storage"):
            if contract.get(field) != policy.get(field):
                failures.append(f"OTA artifacts ota_contract.{field} must match evidence contract: {path}")
        for field in ("slot_labels", "verity_devices", "health_checks"):
            if contract.get(field) != policy.get(field):
                failures.append(f"OTA artifacts ota_contract.{field} must match evidence contract: {path}")
    bundle = payload.get("bundle")
    if not isinstance(bundle, dict):
        failures.append(f"OTA artifacts bundle must be an object: {path}")
    else:
        expected_names = {
            str(item).format(version=version, target=target)
            for item in policy.get("bundle_artifacts", [])
            if isinstance(item, str) and item.endswith(".raucb")
        }
        if bundle.get("name") not in expected_names:
            failures.append(f"OTA artifacts bundle.name must be target-named by evidence contract: {path}")
        bundle_sha = bundle.get("sha256")
        if not isinstance(bundle_sha, str) or not SHA256_RE.fullmatch(bundle_sha) or bundle_sha == "0" * 64:
            failures.append(f"OTA artifacts bundle.sha256 must be a non-zero sha256: {path}")
        if not isinstance(bundle.get("bytes"), int) or bundle.get("bytes", 0) <= 0:
            failures.append(f"OTA artifacts bundle.bytes must be positive: {path}")
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        failures.append(f"OTA artifacts manifest must be an object: {path}")
    else:
        if manifest.get("name") != "suderra-os-update-manifest.json":
            failures.append(f"OTA artifacts manifest.name must be suderra-os-update-manifest.json: {path}")
        manifest_sha = manifest.get("sha256")
        if not isinstance(manifest_sha, str) or not SHA256_RE.fullmatch(manifest_sha) or manifest_sha == "0" * 64:
            failures.append(f"OTA artifacts manifest.sha256 must be a non-zero sha256: {path}")
        if not isinstance(manifest.get("bytes"), int) or manifest.get("bytes", 0) <= 0:
            failures.append(f"OTA artifacts manifest.bytes must be positive: {path}")
    roles = payload.get("signing_roles")
    if not isinstance(roles, list) or set(roles) != {"rauc-bundle", "os-update-manifest"}:
        failures.append(f"OTA artifacts signing_roles must require RAUC bundle and OS update manifest: {path}")
    return failures


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


def binding_artifact_refs_for_target(binding: dict[str, Any] | None, target: str) -> list[dict[str, Any]]:
    if not isinstance(binding, dict):
        return []
    artifacts = binding.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    return [
        item
        for item in artifacts
        if isinstance(item, dict)
        and item.get("target") == target
        and isinstance(item.get("sha256"), str)
        and SHA256_RE.fullmatch(item["sha256"])
    ]


def lab_artifact_binding(path: Path) -> tuple[str | None, int | None]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return None, None
    binding = payload.get("artifact_binding")
    if not isinstance(binding, dict):
        return None, None
    digest = binding.get("build_artifact_sha256")
    size = binding.get("build_artifact_bytes")
    return (
        digest if isinstance(digest, str) and SHA256_RE.fullmatch(digest) else None,
        size if isinstance(size, int) and size > 0 else None,
    )


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
    parser.add_argument("--require-evidence-ingress-signature", action="store_true")
    parser.add_argument("--evidence-ingress-certificate-identity")
    parser.add_argument("--evidence-ingress-certificate-oidc-issuer")
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
            if args.root is not None:
                ingress_args.extend(["--input-root", str(args.root)])
            if args.source_sha is not None:
                ingress_args.extend(["--expected-source-sha", args.source_sha])
            if args.require_ingress_signature:
                ingress_args.append("--require-signature")
                if args.ingress_certificate_identity:
                    ingress_args.extend(["--certificate-identity", args.ingress_certificate_identity])
                if args.ingress_certificate_oidc_issuer:
                    ingress_args.extend(["--certificate-oidc-issuer", args.ingress_certificate_oidc_issuer])
            if args.require_evidence_ingress_signature:
                ingress_args.append("--require-evidence-ingress-signature")
                if args.evidence_ingress_certificate_identity:
                    ingress_args.extend(
                        ["--evidence-ingress-certificate-identity", args.evidence_ingress_certificate_identity]
                    )
                if args.evidence_ingress_certificate_oidc_issuer:
                    ingress_args.extend(
                        [
                            "--evidence-ingress-certificate-oidc-issuer",
                            args.evidence_ingress_certificate_oidc_issuer,
                        ]
                    )
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
    elif governance.get("schema_version") != "suderra.github-governance-validation.v2":
        failures.append(f"governance policy validation must be suderra.github-governance-validation.v2: {governance_report}")

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
        station_event_ids_by_target: dict[str, set[str]] = {}
        station_acquisition_by_target: dict[str, dict[str, Any]] = {}
        station_registry_payload = read_json(station_registry)
        if not isinstance(station_registry_payload, dict):
            station_registry_payload = None
        registry_sha = sha256_file(station_registry) if station_registry.is_file() else None
        for target_dir in sorted(acquisition_root.iterdir()) if acquisition_root.is_dir() else []:
            if not target_dir.is_dir():
                continue
            acquisition = target_dir / "station-acquisition.json"
            acquisition_count += 1
            expected_artifact_sha, expected_artifact_bytes = lab_artifact_binding(target_dir / "lab.json")
            acquisition_args = [
                sys.executable,
                "scripts/evidence/station-acquisition.py",
                "validate",
                str(acquisition),
                "--expected-version",
                args.version,
                "--expected-target",
                target_dir.name,
            ]
            if bound_source_sha:
                acquisition_args.extend(["--expected-source-sha", bound_source_sha])
            if bound_source_run_id:
                acquisition_args.extend(["--expected-source-run-id", bound_source_run_id])
            if expected_artifact_sha:
                acquisition_args.extend(["--expected-artifact-sha256", expected_artifact_sha])
            if expected_artifact_bytes is not None:
                acquisition_args.extend(["--expected-artifact-bytes", str(expected_artifact_bytes)])
            if registry_sha:
                acquisition_args.extend(["--expected-registry-sha256", registry_sha])
            if station_registry.is_file():
                acquisition_args.extend(["--station-registry", str(station_registry)])
            if args.check_files:
                acquisition_args.append("--check-files")
            failures.extend(run(acquisition_args))
            acquisition_payload = read_json(acquisition)
            if isinstance(acquisition_payload, dict) and isinstance(acquisition_payload.get("events"), list):
                station_acquisition_by_target[target_dir.name] = acquisition_payload
                station_event_ids_by_target[target_dir.name] = {
                    str(event.get("event_id"))
                    for event in acquisition_payload["events"]
                    if isinstance(event, dict) and isinstance(event.get("event_id"), str)
                }
        if acquisition_count == 0:
            failures.append("production-candidate profile requires station-acquisition adapter evidence")

    matrix = load_matrix(args.matrix)
    if args.profile == "production-candidate":
        subject_graph = args.root / "release-subject-graph" / args.version / "release-subject-graph.json"
        failures.extend(
            validate_subject_graph(
                subject_graph,
                version=args.version,
                profile=args.profile,
                source_sha=bound_source_sha,
                source_run_id=bound_source_run_id,
                matrix=matrix,
                binding=binding,
                root=args.root,
                check_files=args.check_files,
            )
        )
        signing_root = args.root / "release-signing" / args.version
        signing_sessions = (
            sorted(path for path in signing_root.glob("*/*.json") if path.name != "signing-manifest.json")
            if signing_root.is_dir()
            else []
        )
        if not signing_sessions:
            failures.append("production-candidate profile requires release-signing HSM session evidence")
        for session in signing_sessions:
            payload = read_json(session)
            if not isinstance(payload, dict):
                failures.append(f"HSM signing session missing or invalid JSON: {session}")
                continue
            target = session.parent.name
            expected_sha256s = {
                str(item["sha256"])
                for item in binding_artifact_refs_for_target(binding, target)
            }
            validate_hsm_session_replay(
                session,
                payload,
                failures,
                expected_artifact_sha256s=expected_sha256s,
            )
        for row in matrix.get("defconfigs", []):
            target = str(row.get("target", ""))
            policy = evidence_contract.target_policy(target, EVIDENCE_CONTRACT)
            expected_sha256s = {
                str(item["sha256"])
                for item in binding_artifact_refs_for_target(binding, target)
            }
            ota_artifacts = args.root / "release-ota" / args.version / target / "ota-artifacts.json"
            ota_role_sha256s: dict[str, str] = {}
            if policy.get("ota_capable") is True and ota_artifacts.is_file():
                ota_role_sha256s = ota_signing_digest_expectations(ota_artifacts)
            if policy.get("signing_required") is True:
                manifest = args.root / "release-signing" / args.version / target / "signing-manifest.json"
                failures.extend(
                    validate_signing_manifest(
                        manifest,
                        version=args.version,
                        target=target,
                        source_sha=bound_source_sha,
                        source_run_id=bound_source_run_id,
                        expected_artifact_sha256s=expected_sha256s,
                        expected_role_output_sha256s=ota_role_sha256s,
                    )
                )
            if policy.get("hardware_required") is True:
                hardware_subject = args.root / "release-lab-input" / args.version / target / "hardware-subject.json"
                station_event_ids = station_event_ids_by_target.get(target)
                station_acquisition_payload = station_acquisition_by_target.get(target)
                if station_event_ids is None or station_acquisition_payload is None:
                    failures.append(f"production-candidate profile requires station-acquisition evidence for {target}")
                failures.extend(
                    validate_hardware_subject(
                        hardware_subject,
                        version=args.version,
                        target=target,
                        source_sha=bound_source_sha,
                        source_run_id=bound_source_run_id,
                        expected_artifact_sha256s=expected_sha256s,
                        station_event_ids=station_event_ids,
                        station_acquisition=station_acquisition_payload,
                        station_registry=station_registry_payload,
                    )
                )
            if policy.get("ota_capable") is True:
                failures.extend(
                    validate_ota_artifacts(
                        ota_artifacts,
                        version=args.version,
                        target=target,
                        source_sha=bound_source_sha,
                        source_run_id=bound_source_run_id,
                    )
                )
        role_bindings = args.root / "release-governance" / args.version / "role-bindings.json"
        failures.extend(validate_governance_role_bindings(role_bindings, version=args.version))
        retention_manifest = args.root / "release-retention" / args.version / "retention-manifest.json"
        failures.extend(
            validate_retention_manifest(
                retention_manifest,
                version=args.version,
                source_sha=bound_source_sha,
                source_run_id=bound_source_run_id,
            )
        )
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
                "--profile",
                "production-candidate",
                "--expected-version",
                args.version,
                "--expected-target",
                str(row["target"]),
            ]
            if bound_source_sha:
                runtime_args.extend(["--expected-source-sha", bound_source_sha])
            if bound_source_run_id:
                runtime_args.extend(["--expected-source-run-id", bound_source_run_id])
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
