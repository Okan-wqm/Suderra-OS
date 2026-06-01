#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate non-promotable RC evidence dry-run bundles.

This producer is deliberately not an evidence faker. It records the exact Image
Build binding, emits SSOT-derived plans, and preserves production gaps as first
class blockers. The resulting bundle must never authorize a release tag.
"""

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.rc-evidence-dry-run.v1"
BUNDLE_SCHEMA_VERSION = "suderra.rc-evidence-dry-run-bundle.v1"
PROFILE = "rc-evidence-dry-run"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_matrix(path: Path) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = module.load_matrix(path)
    if not isinstance(matrix, dict):
        raise RuntimeError(f"matrix loader returned non-object for {path}")
    return matrix


def load_matrix_with_module(path: Path) -> tuple[dict[str, Any], Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = module.load_matrix(path)
    if not isinstance(matrix, dict):
        raise RuntimeError(f"matrix loader returned non-object for {path}")
    return matrix, module


def load_validate_release_inputs_module() -> Any:
    script = ROOT / "scripts" / "evidence" / "validate-release-inputs.py"
    spec = importlib.util.spec_from_file_location("validate_release_inputs", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact_ref(binding: dict[str, Any], target: str, artifacts: list[str]) -> dict[str, Any] | None:
    items = binding.get("artifacts")
    if not isinstance(items, list):
        return None
    for name in artifacts:
        for item in items:
            if (
                isinstance(item, dict)
                and item.get("target") == target
                and item.get("artifact") == name
                and isinstance(item.get("sha256"), str)
                and SHA256_RE.fullmatch(item["sha256"])
                and item.get("bytes", 0) > 0
            ):
                return dict(item)
    return None


def file_record(base: Path, rel: str, *, role: str, schema_version: str | None = None) -> dict[str, Any]:
    rel_path = evidence_contract.safe_relative_path(rel)
    if rel_path is None:
        raise ValueError(f"{role} path must be safe and relative: {rel}")
    path = base / rel_path
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"{role} file is missing or empty: {path}")
    record = {
        "role": role,
        "path": rel_path.as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }
    if schema_version is not None:
        record["schema_version"] = schema_version
    return record


def verify_file_record(base: Path, record: Any, failures: list[str], prefix: str) -> Path | None:
    if not isinstance(record, dict):
        failures.append(f"{prefix}: must be an object")
        return None
    rel = evidence_contract.safe_relative_path(record.get("path"))
    if rel is None:
        failures.append(f"{prefix}.path: must be a safe relative path")
        return None
    path = base / rel
    if not path.is_file() or path.stat().st_size <= 0:
        failures.append(f"{prefix}.path: referenced file is missing or empty: {rel.as_posix()}")
        return None
    if record.get("bytes") != path.stat().st_size:
        failures.append(f"{prefix}.bytes: does not match referenced file size")
    expected_sha = record.get("sha256")
    if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha) or expected_sha == "0" * 64:
        failures.append(f"{prefix}.sha256: must be a non-zero sha256")
    elif sha256_file(path) != expected_sha:
        failures.append(f"{prefix}.sha256: does not match referenced file")
    return path


def read_json_file(path: Path, failures: list[str], prefix: str) -> Any:
    try:
        return read_json(path)
    except Exception as exc:
        failures.append(f"{prefix}: cannot read JSON: {exc}")
        return None


def check_common_identity(
    failures: list[str],
    prefix: str,
    payload: Any,
    *,
    version: str,
    source_sha: str,
    source_run_id: str,
    profile_required: bool = False,
) -> None:
    if not isinstance(payload, dict):
        failures.append(f"{prefix}: must be a JSON object")
        return
    if payload.get("version") != version:
        failures.append(f"{prefix}.version: must match {version}")
    if payload.get("source_sha") != source_sha:
        failures.append(f"{prefix}.source_sha: must match {source_sha}")
    if str(payload.get("source_run_id")) != source_run_id:
        failures.append(f"{prefix}.source_run_id: must match {source_run_id}")
    if profile_required and payload.get("profile") != PROFILE:
        failures.append(f"{prefix}.profile: must be {PROFILE}")


def validate_role_payload(
    failures: list[str],
    role: str,
    path: Path,
    *,
    schema_version: str | None,
    version: str,
    source_sha: str,
    source_run_id: str,
) -> None:
    payload = read_json_file(path, failures, f"{role}:{path}")
    if not isinstance(payload, dict):
        return
    if schema_version is not None and payload.get("schema_version") != schema_version:
        failures.append(f"{role}: schema_version must be {schema_version}")
    if role in {
        "retention-plan",
        "runtime-plan-gaps",
        "subject-plan",
        "image-build-artifact-digests",
        "production-gap-report",
        "release-subject-graph",
        "release-input-binding",
    }:
        check_common_identity(
            failures,
            role,
            payload,
            version=version,
            source_sha=source_sha,
            source_run_id=source_run_id,
            profile_required=role
            in {"output-tree-plan", "runtime-plan-gaps", "subject-plan", "production-gap-report", "release-subject-graph"},
        )
    if role == "output-tree-plan":
        if payload.get("version") != version:
            failures.append(f"output-tree-plan.version: must match {version}")
        if payload.get("profile") != PROFILE:
            failures.append(f"output-tree-plan.profile: must be {PROFILE}")
        if payload.get("release_authorizing") is not False or payload.get("publication_allowed") is not False:
            failures.append("output-tree-plan: must preserve non-promotable RC dry-run semantics")
    elif role == "runtime-plan-gaps":
        if payload.get("status") != "blocked_for_production":
            failures.append("runtime-plan-gaps: status must be blocked_for_production")
        if not isinstance(payload.get("runtime_targets"), list) or not payload["runtime_targets"]:
            failures.append("runtime-plan-gaps: must list runtime target blockers")
    elif role == "production-gap-report":
        if payload.get("production_ready") is not False or payload.get("status") != "blocked_for_production":
            failures.append("production-gap-report: must keep production_ready=false and blocked_for_production")
        if not isinstance(payload.get("gaps"), list) or not payload["gaps"]:
            failures.append("production-gap-report: must list remaining production evidence gaps")
    elif role == "image-build-artifact-digests":
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            failures.append("image-build-artifact-digests: artifacts must be a non-empty list")
    elif role == "subject-plan":
        if not isinstance(payload.get("subject_id"), str) or not payload["subject_id"]:
            failures.append("subject-plan: subject_id must be present")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, dict):
            failures.append("subject-plan: artifacts must be an object")
        else:
            for name in ("raw_image", "compressed_release_artifact"):
                item = artifacts.get(name)
                if not isinstance(item, dict):
                    failures.append(f"subject-plan: artifacts.{name} must be an object")
                    continue
                digest = item.get("sha256")
                if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
                    failures.append(f"subject-plan: artifacts.{name}.sha256 must be a non-zero sha256")
                if not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
                    failures.append(f"subject-plan: artifacts.{name}.bytes must be positive")
    elif role == "governance-snapshot-manifest":
        if payload.get("schema_version") != "suderra.github-governance-snapshot-manifest.v1":
            failures.append("governance-snapshot-manifest: schema_version is invalid")
        if payload.get("version") != version:
            failures.append(f"governance-snapshot-manifest: version must match {version}")
        if not isinstance(payload.get("files"), list) or not payload["files"]:
            failures.append("governance-snapshot-manifest: files must be a non-empty list")
        if payload.get("failures") not in ([], None):
            failures.append("governance-snapshot-manifest: failures must be empty")
    elif role == "governance-policy-validation":
        if payload.get("schema_version") != "suderra.github-governance-validation.v2":
            failures.append("governance-policy-validation: schema_version is invalid")
        if payload.get("status") != "passed":
            failures.append("governance-policy-validation: status must be passed")


def records_by_role(records: Any) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(records, list):
        return grouped
    for item in records:
        if isinstance(item, dict) and isinstance(item.get("role"), str):
            grouped.setdefault(str(item["role"]), []).append(item)
    return grouped


def _canonical_record(
    *,
    kind: str,
    record: Any,
    failures: list[str],
    prefix: str,
) -> tuple[str, str, str, str, str, str, str, str, int] | None:
    if not isinstance(record, dict):
        failures.append(f"{prefix}: must be an object")
        return None
    rel_path = evidence_contract.safe_relative_path(record.get("path"))
    if rel_path is None:
        failures.append(f"{prefix}.path: must be a safe relative non-placeholder path")
        return None
    digest = record.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
        failures.append(f"{prefix}.sha256: must be a non-zero sha256")
        return None
    size = record.get("bytes")
    if not isinstance(size, int) or size <= 0:
        failures.append(f"{prefix}.bytes: must be positive")
        return None
    return (
        kind,
        str(record.get("defconfig", "")),
        str(record.get("arch", "")),
        str(record.get("target", "")),
        str(record.get("role", "")),
        str(record.get("artifact", "")),
        rel_path.as_posix(),
        digest,
        size,
    )


def _canonical_record_set(payload: dict[str, Any], failures: list[str], prefix: str) -> set[tuple[str, str, str, str, str, str, str, str, int]]:
    records: set[tuple[str, str, str, str, str, str, str, str, int]] = set()
    for field, kind in (("artifacts", "artifact"), ("installers", "installer")):
        items = payload.get(field)
        if not isinstance(items, list):
            failures.append(f"{prefix}.{field}: must be a list")
            continue
        for idx, item in enumerate(items):
            record = _canonical_record(kind=kind, record=item, failures=failures, prefix=f"{prefix}.{field}[{idx}]")
            if record is None:
                continue
            if record in records:
                failures.append(f"{prefix}.{field}[{idx}]: duplicate canonical record")
            records.add(record)
    contract_record = payload.get("image_build_contract")
    if not isinstance(contract_record, dict):
        failures.append(f"{prefix}.image_build_contract: must be an object")
    else:
        record = _canonical_record(
            kind="image-build-contract",
            record=contract_record,
            failures=failures,
            prefix=f"{prefix}.image_build_contract",
        )
        if record is not None:
            records.add(record)
    return records


def replay_artifact_inventory(
    *,
    inventory_path: Path,
    binding: dict[str, Any],
    input_root: Path,
    failures: list[str],
) -> None:
    inventory = read_json_file(inventory_path, failures, "image-build-artifact-digests")
    if not isinstance(inventory, dict):
        return
    inventory_records = _canonical_record_set(inventory, failures, "image-build-artifact-digests")
    binding_records = _canonical_record_set(binding, failures, "release-input-binding")
    missing = sorted(binding_records - inventory_records)
    extra = sorted(inventory_records - binding_records)
    if missing:
        failures.append(
            "image-build-artifact-digests: missing binding records: "
            + ", ".join(f"{item[0]}:{item[5]}:{item[6]}" for item in missing)
        )
    if extra:
        failures.append(
            "image-build-artifact-digests: contains records not in binding: "
            + ", ".join(f"{item[0]}:{item[5]}:{item[6]}" for item in extra)
        )
    artifact_root = input_root / "build-artifacts"
    if artifact_root.is_dir():
        for record in sorted(inventory_records):
            rel_path = Path(record[6])
            path = artifact_root / rel_path
            if not path.is_file() or path.stat().st_size <= 0:
                failures.append(f"image-build-artifact-digests: referenced build artifact missing or empty: {rel_path.as_posix()}")
                continue
            if path.stat().st_size != record[8]:
                failures.append(f"image-build-artifact-digests: byte mismatch for {rel_path.as_posix()}")
            if sha256_file(path) != record[7]:
                failures.append(f"image-build-artifact-digests: sha256 mismatch for {rel_path.as_posix()}")


def replay_governance_snapshot(snapshot_path: Path, failures: list[str]) -> None:
    payload = read_json_file(snapshot_path, failures, "governance-snapshot-manifest")
    if not isinstance(payload, dict):
        return
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        failures.append("governance-snapshot-manifest: files must be a non-empty list")
        return
    seen: set[str] = set()
    for idx, item in enumerate(files):
        if not isinstance(item, dict):
            failures.append(f"governance-snapshot-manifest.files[{idx}]: must be an object")
            continue
        name = item.get("name")
        digest = item.get("sha256")
        if not isinstance(name, str) or not name or "/" in name or name == "snapshot-manifest.json":
            failures.append(f"governance-snapshot-manifest.files[{idx}].name: must be a single relative filename")
            continue
        if name in seen:
            failures.append(f"governance-snapshot-manifest.files[{idx}].name: duplicate file {name}")
        seen.add(name)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
            failures.append(f"governance-snapshot-manifest.files[{idx}].sha256: must be a non-zero sha256")
            continue
        actual = snapshot_path.parent / name
        if not actual.is_file() or actual.stat().st_size <= 0:
            failures.append(f"governance-snapshot-manifest: referenced file missing or empty: {name}")
            continue
        if sha256_file(actual) != digest:
            failures.append(f"governance-snapshot-manifest: sha256 mismatch for {name}")


def _graph_subjects_by_target(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    subjects = graph.get("subjects")
    if not isinstance(subjects, list):
        subjects = graph.get("subject_nodes")
    if not isinstance(subjects, list):
        subjects = graph.get("nodes")
    if not isinstance(subjects, list):
        return {}
    return {
        str(subject.get("target")): subject
        for subject in subjects
        if isinstance(subject, dict) and isinstance(subject.get("target"), str)
    }


def _graph_evidence_nodes_by_subject(graph: dict[str, Any], subject_id: str) -> list[dict[str, Any]]:
    nodes = graph.get("evidence_nodes")
    if not isinstance(nodes, list):
        return []
    return [node for node in nodes if isinstance(node, dict) and node.get("subject_id") == subject_id]


def _graph_edges_by_subject(graph: dict[str, Any], subject_id: str) -> list[dict[str, Any]]:
    edges = graph.get("evidence_edges")
    if not isinstance(edges, list):
        return []
    return [edge for edge in edges if isinstance(edge, dict) and edge.get("from") == subject_id]


def _edge_pairs(edges: Any) -> set[tuple[str, str, str, str]]:
    if not isinstance(edges, list):
        return set()
    return {
        (str(edge.get("from")), str(edge.get("to")), str(edge.get("relationship")), str(edge.get("role")))
        for edge in edges
        if isinstance(edge, dict)
        and isinstance(edge.get("from"), str)
        and isinstance(edge.get("to"), str)
        and isinstance(edge.get("relationship"), str)
        and isinstance(edge.get("role"), str)
    }


def _artifact_identity(artifacts: Any, name: str) -> tuple[str, int] | None:
    if not isinstance(artifacts, dict):
        return None
    item = artifacts.get(name)
    if not isinstance(item, dict):
        return None
    digest = item.get("sha256")
    size = item.get("bytes")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or digest == "0" * 64:
        return None
    if not isinstance(size, int) or size <= 0:
        return None
    return digest, size


def _canonical_evidence_node(
    node: Any,
    failures: list[str],
    prefix: str,
) -> tuple[str, str, str, str, str, str, bool, str, int | None] | None:
    if not isinstance(node, dict):
        failures.append(f"{prefix}: must be an object")
        return None
    rel_path = evidence_contract.safe_relative_path(node.get("path"))
    if rel_path is None:
        failures.append(f"{prefix}.path: must be a safe relative path")
        return None
    required = node.get("required")
    if not isinstance(required, bool):
        failures.append(f"{prefix}.required: must be a boolean")
        return None
    digest = node.get("sha256", "")
    if digest is None:
        digest = ""
    if not isinstance(digest, str):
        failures.append(f"{prefix}.sha256: must be a string when present")
        return None
    if digest and (not SHA256_RE.fullmatch(digest) or digest == "0" * 64):
        failures.append(f"{prefix}.sha256: must be a non-zero sha256 when present")
        return None
    size = node.get("bytes")
    if size is not None and (not isinstance(size, int) or size <= 0):
        failures.append(f"{prefix}.bytes: must be positive when present")
        return None
    return (
        str(node.get("subject_id", "")),
        str(node.get("target", "")),
        str(node.get("role", "")),
        rel_path.as_posix(),
        str(node.get("schema_role", "")),
        str(node.get("schema_version", "")),
        required,
        digest,
        size if isinstance(size, int) else None,
    )


def _canonical_evidence_node_set(
    nodes: Any,
    failures: list[str],
    prefix: str,
) -> set[tuple[str, str, str, str, str, str, bool, str, int | None]]:
    if not isinstance(nodes, list):
        failures.append(f"{prefix}: must be a list")
        return set()
    records: set[tuple[str, str, str, str, str, str, bool, str, int | None]] = set()
    seen_node_ids: set[str] = set()
    for idx, node in enumerate(nodes):
        if isinstance(node, dict) and isinstance(node.get("node_id"), str):
            if node["node_id"] in seen_node_ids:
                failures.append(f"{prefix}[{idx}].node_id: duplicate node id")
            seen_node_ids.add(str(node["node_id"]))
        record = _canonical_evidence_node(node, failures, f"{prefix}[{idx}]")
        if record is None:
            continue
        if record in records:
            failures.append(f"{prefix}[{idx}]: duplicate canonical evidence node")
        records.add(record)
    return records


def _canonical_edge_set(
    edges: Any,
    failures: list[str],
    prefix: str,
) -> set[tuple[str, str, str, str]]:
    if not isinstance(edges, list):
        failures.append(f"{prefix}: must be a list")
        return set()
    records: set[tuple[str, str, str, str]] = set()
    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            failures.append(f"{prefix}[{idx}]: must be an object")
            continue
        record = (
            str(edge.get("from", "")),
            str(edge.get("to", "")),
            str(edge.get("relationship", "")),
            str(edge.get("role", "")),
        )
        if not all(record):
            failures.append(f"{prefix}[{idx}]: from, to, relationship, and role are required")
            continue
        if record in records:
            failures.append(f"{prefix}[{idx}]: duplicate canonical evidence edge")
        records.add(record)
    return records


def _canonical_required_evidence_set(
    required_evidence: Any,
    *,
    subject_id: str,
    target: str,
    failures: list[str],
    prefix: str,
) -> set[tuple[str, str, str, str, bool]]:
    records: set[tuple[str, str, str, str, bool]] = set()
    if isinstance(required_evidence, dict):
        items = [
            {
                "role": str(role),
                "path": path,
                "required": True,
            }
            for role, path in required_evidence.items()
        ]
    elif isinstance(required_evidence, list):
        items = required_evidence
    else:
        failures.append(f"{prefix}: must be an object or list")
        return records
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            failures.append(f"{prefix}[{idx}]: must be an object")
            continue
        rel_path = evidence_contract.safe_relative_path(item.get("path"))
        if rel_path is None:
            failures.append(f"{prefix}[{idx}].path: must be a safe relative path")
            continue
        required = item.get("required")
        if required is None:
            required = True
        if not isinstance(required, bool):
            failures.append(f"{prefix}[{idx}].required: must be a boolean")
            continue
        records.add((subject_id, target, str(item.get("role", "")), rel_path.as_posix(), required))
    return records


def _required_evidence_from_nodes(nodes: list[dict[str, Any]]) -> set[tuple[str, str, str, str, bool]]:
    records: set[tuple[str, str, str, str, bool]] = set()
    for node in nodes:
        rel_path = evidence_contract.safe_relative_path(node.get("path"))
        if rel_path is None:
            continue
        records.add(
            (
                str(node.get("subject_id", "")),
                str(node.get("target", "")),
                str(node.get("role", "")),
                rel_path.as_posix(),
                bool(node.get("required")),
            )
        )
    return records


def _retention_closure_key(payload: Any) -> tuple[str, tuple[str, ...]] | None:
    if not isinstance(payload, dict):
        return None
    exports = payload.get("required_exports")
    if not isinstance(exports, list):
        return None
    return str(payload.get("policy_id", "")), tuple(sorted(str(item) for item in exports))


def subject_plan_from_graph_subject(
    *,
    graph: dict[str, Any],
    subject: dict[str, Any],
) -> dict[str, Any]:
    subject_id = str(subject["subject_id"])
    nodes = sorted(
        _graph_evidence_nodes_by_subject(graph, subject_id),
        key=lambda item: (str(item.get("role")), str(item.get("path")), str(item.get("node_id"))),
    )
    edges = sorted(
        _graph_edges_by_subject(graph, subject_id),
        key=lambda item: (str(item.get("role")), str(item.get("to"))),
    )
    return {
        "schema_version": graph.get("schema_version"),
        "subject_id": subject_id,
        "version": subject.get("version"),
        "profile": subject.get("profile"),
        "target": subject.get("target"),
        "defconfig": subject.get("defconfig"),
        "source_sha": subject.get("source_sha"),
        "source_run_id": subject.get("source_run_id"),
        "source_run_attempt": subject.get("source_run_attempt"),
        "matrix": {
            "production_ready": subject.get("target_policy", {}).get("production_ready")
            if isinstance(subject.get("target_policy"), dict)
            else None,
        },
        "artifacts": subject.get("artifacts"),
        "required_evidence": [
            {
                "node_id": node.get("node_id"),
                "role": node.get("role"),
                "path": node.get("path"),
                "schema_role": node.get("schema_role"),
                "schema_version": node.get("schema_version"),
                "required": node.get("required"),
            }
            for node in nodes
        ],
        "evidence_nodes": nodes,
        "evidence_edges": edges,
        "retention_closure": graph.get("retention_closure"),
        "producer": {
            "name": "rc-evidence-dry-run.py subject-plan",
            "source": "release-subject-graph",
        },
    }


def replay_subject_graph_against_plans(
    *,
    graph: dict[str, Any],
    subject_plan_paths: list[Path],
    failures: list[str],
) -> None:
    graph_subjects = _graph_subjects_by_target(graph)
    graph_retention_key = _retention_closure_key(graph.get("retention_closure"))
    if graph_retention_key is None:
        failures.append("release-subject-graph: retention_closure must contain policy_id and required_exports")

    seen_targets: set[str] = set()
    for subject_plan_path in subject_plan_paths:
        plan = read_json_file(subject_plan_path, failures, f"subject-plan:{subject_plan_path}")
        if not isinstance(plan, dict):
            continue
        target = str(plan.get("target", ""))
        seen_targets.add(target)
        subject_id = str(plan.get("subject_id", ""))
        graph_subject = graph_subjects.get(target)
        if not isinstance(graph_subject, dict):
            failures.append(f"release-subject-graph: missing graph subject for subject-plan target {target}")
            continue
        for field in ("subject_id", "target", "defconfig", "source_sha", "source_run_id"):
            if str(graph_subject.get(field)) != str(plan.get(field)):
                failures.append(f"release-subject-graph: {target} {field} must match subject-plan")
        for graph_field, plan_artifact in (
            ("raw_image", "raw_image"),
            ("compressed_release_artifact", "compressed_release_artifact"),
        ):
            graph_artifacts = graph_subject.get("artifacts")
            plan_artifacts = plan.get("artifacts")
            graph_identity = _artifact_identity(graph_artifacts, graph_field)
            plan_identity = _artifact_identity(plan_artifacts, plan_artifact)
            if graph_identity != plan_identity:
                failures.append(f"release-subject-graph: {target} artifacts.{graph_field} must match subject-plan")

        plan_retention_key = _retention_closure_key(plan.get("retention_closure"))
        if plan_retention_key is None:
            failures.append(f"subject-plan:{subject_plan_path}: retention_closure must contain policy_id and required_exports")
        elif graph_retention_key is not None and plan_retention_key != graph_retention_key:
            failures.append(f"release-subject-graph: {target} retention_closure must match subject-plan")

        graph_nodes = _graph_evidence_nodes_by_subject(graph, subject_id)
        graph_required = _required_evidence_from_nodes(graph_nodes)
        plan_required = _canonical_required_evidence_set(
            plan.get("required_evidence"),
            subject_id=subject_id,
            target=target,
            failures=failures,
            prefix=f"subject-plan:{subject_plan_path}:required_evidence",
        )
        if not plan_required:
            failures.append(f"subject-plan:{subject_plan_path}: required_evidence must be non-empty")
        if graph_required != plan_required:
            missing = sorted(graph_required - plan_required)
            extra = sorted(plan_required - graph_required)
            if missing:
                failures.append(
                    f"release-subject-graph: {target} required_evidence missing from subject-plan: "
                    + ", ".join(f"{item[2]}:{item[3]}" for item in missing)
                )
            if extra:
                failures.append(
                    f"release-subject-graph: {target} required_evidence not present in graph: "
                    + ", ".join(f"{item[2]}:{item[3]}" for item in extra)
                )

        plan_nodes = plan.get("evidence_nodes")
        if not isinstance(plan_nodes, list) or not plan_nodes:
            failures.append(f"subject-plan:{subject_plan_path}: evidence_nodes must be non-empty")
            plan_nodes = []
        graph_node_set = _canonical_evidence_node_set(graph_nodes, failures, f"release-subject-graph:{target}:evidence_nodes")
        plan_node_set = _canonical_evidence_node_set(plan_nodes, failures, f"subject-plan:{subject_plan_path}:evidence_nodes")
        if graph_node_set != plan_node_set:
            missing = sorted(graph_node_set - plan_node_set)
            extra = sorted(plan_node_set - graph_node_set)
            if missing:
                failures.append(
                    f"release-subject-graph: {target} evidence_nodes missing from subject-plan: "
                    + ", ".join(f"{item[2]}:{item[3]}" for item in missing)
                )
            if extra:
                failures.append(
                    f"release-subject-graph: {target} evidence_nodes not present in graph: "
                    + ", ".join(f"{item[2]}:{item[3]}" for item in extra)
                )

        graph_edge_set = _canonical_edge_set(
            _graph_edges_by_subject(graph, subject_id),
            failures,
            f"release-subject-graph:{target}:evidence_edges",
        )
        plan_edge_set = _canonical_edge_set(
            plan.get("evidence_edges"),
            failures,
            f"subject-plan:{subject_plan_path}:evidence_edges",
        )
        if graph_edge_set != plan_edge_set:
            missing = sorted(graph_edge_set - plan_edge_set)
            extra = sorted(plan_edge_set - graph_edge_set)
            if missing:
                failures.append(
                    f"release-subject-graph: {target} evidence_edges missing from subject-plan: "
                    + ", ".join(f"{item[3]}:{item[1]}" for item in missing)
                )
            if extra:
                failures.append(
                    f"release-subject-graph: {target} evidence_edges not present in graph: "
                    + ", ".join(f"{item[3]}:{item[1]}" for item in extra)
                )

    missing_targets = sorted(set(graph_subjects) - seen_targets)
    if missing_targets:
        failures.append("release-subject-graph: graph subjects missing subject-plans: " + ", ".join(missing_targets))
    extra_targets = sorted(seen_targets - set(graph_subjects))
    if extra_targets:
        failures.append("release-subject-graph: subject-plan targets missing from graph: " + ", ".join(extra_targets))


def replay_binding_and_subjects(
    *,
    failures: list[str],
    binding_path: Path,
    artifact_inventory_path: Path | None,
    subject_graph_path: Path,
    subject_plan_paths: list[Path],
    input_root: Path,
    version: str,
    source_sha: str,
    source_run_id: str,
) -> None:
    binding = read_json_file(binding_path, failures, "release-input-binding")
    if not isinstance(binding, dict):
        return
    if binding.get("schema_version") != "suderra.release-input-binding.v2":
        failures.append("release-input-binding: schema_version must be suderra.release-input-binding.v2")
    check_common_identity(
        failures,
        "release-input-binding",
        binding,
        version=version,
        source_sha=source_sha,
        source_run_id=source_run_id,
        profile_required=True,
    )
    matrix, matrix_module = load_matrix_with_module(DEFAULT_MATRIX)
    binding_failures = evidence_contract.validate_release_artifact_bindings(
        binding.get("artifacts"),
        evidence_contract.expected_release_artifact_map(matrix, matrix_module),
        artifact_root=input_root / "build-artifacts",
        file_hasher=sha256_file,
    )
    failures.extend(f"release-input-binding: {item}" for item in binding_failures)
    if artifact_inventory_path is not None:
        replay_artifact_inventory(
            inventory_path=artifact_inventory_path,
            binding=binding,
            input_root=input_root,
            failures=failures,
        )

    target_digests: dict[str, set[str]] = {}
    for item in binding.get("artifacts", []) if isinstance(binding.get("artifacts"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("target"), str) and isinstance(item.get("sha256"), str):
            target_digests.setdefault(str(item["target"]), set()).add(str(item["sha256"]))

    subject_ids: set[str] = set()
    for subject_plan_path in subject_plan_paths:
        payload = read_json_file(subject_plan_path, failures, f"subject-plan:{subject_plan_path}")
        if not isinstance(payload, dict):
            continue
        target = str(payload.get("target"))
        subject_id = payload.get("subject_id")
        if isinstance(subject_id, str):
            subject_ids.add(subject_id)
        artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
        for name in ("raw_image", "compressed_release_artifact"):
            artifact = artifacts.get(name) if isinstance(artifacts, dict) else None
            digest = artifact.get("sha256") if isinstance(artifact, dict) else None
            if not isinstance(digest, str) or digest not in target_digests.get(target, set()):
                failures.append(f"subject-plan:{subject_plan_path}: artifacts.{name}.sha256 must match release input binding")

    try:
        validate_inputs = load_validate_release_inputs_module()
        failures.extend(
            validate_inputs.validate_subject_graph(
                subject_graph_path,
                version=version,
                profile=PROFILE,
                source_sha=source_sha,
                source_run_id=source_run_id,
                matrix=matrix,
                binding=binding,
                root=input_root,
                check_files=False,
            )
        )
    except Exception as exc:
        failures.append(f"release-subject-graph: semantic replay failed: {exc}")

    graph = read_json_file(subject_graph_path, failures, "release-subject-graph")
    if isinstance(graph, dict):
        graph_subjects = {
            str(node.get("subject_id"))
            for node in graph.get("subjects", graph.get("subject_nodes", []))
            if isinstance(node, dict) and isinstance(node.get("subject_id"), str)
        }
        if not graph_subjects:
            graph_subjects = {
                str(node.get("subject_id"))
                for node in graph.get("nodes", [])
                if isinstance(node, dict) and isinstance(node.get("subject_id"), str)
            }
        missing_subjects = sorted(subject_ids - graph_subjects)
        if missing_subjects:
            failures.append("release-subject-graph: missing subject-plan subject IDs: " + ", ".join(missing_subjects))
        replay_subject_graph_against_plans(
            graph=graph,
            subject_plan_paths=subject_plan_paths,
            failures=failures,
        )


def release_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix.get("defconfigs", []) if isinstance(row, dict) and row.get("release") is True]


def production_gap_rows(matrix: dict[str, Any], contract: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for row in matrix.get("defconfigs", []):
        if not isinstance(row, dict):
            continue
        target = str(row.get("target", ""))
        policy = evidence_contract.target_policy(target, contract)
        if not policy:
            continue
        blockers: list[str] = []
        if row.get("production_ready") is not False and row.get("production_required"):
            blockers.append("production_ready must remain false for this RC dry-run")
        if policy.get("signing_required") is True:
            blockers.append("real HSM signing manifest and crypto replay are not provided by RC dry-run")
        if policy.get("release_image_scan_required") is True:
            blockers.append("scanner-native raw producer operational evidence is not provided by RC dry-run")
        if policy.get("hardware_required") is True:
            blockers.append("real station-acquisition hardware subject evidence is not provided by RC dry-run")
        if policy.get("runtime_required") is True:
            blockers.append("production QEMU runtime observations are not provided by RC dry-run")
        if policy.get("ota_capable") is True:
            blockers.append("OTA/RAUC/TPM production artifacts and monotonic rollback proof are not provided by RC dry-run")
        if policy.get("production_gate") is True:
            blockers.append("immutable retention archive restore/replay proof is not provided by RC dry-run")
        if blockers:
            gaps.append(
                {
                    "target": target,
                    "defconfig": row.get("name"),
                    "production_required": bool(row.get("production_required")),
                    "production_ready": bool(row.get("production_ready")),
                    "blocker": row.get("blocker"),
                    "missing_evidence": sorted(set(blockers)),
                }
            )
    return sorted(gaps, key=lambda item: str(item["target"]))


def runtime_plan_gap(matrix: dict[str, Any], contract: dict[str, Any], *, version: str, source_sha: str, source_run_id: str) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for row in matrix.get("defconfigs", []):
        if not isinstance(row, dict):
            continue
        target = str(row.get("target", ""))
        policy = evidence_contract.target_policy(target, contract)
        if not policy or policy.get("runtime_required") is not True:
            continue
        targets.append(
            {
                "target": target,
                "defconfig": row.get("name"),
                "subject_id": evidence_contract.release_subject_id(
                    version=version,
                    target=target,
                    source_sha=source_sha,
                    source_run_id=source_run_id,
                    contract=contract,
                ),
                "runtime_suite_targets": evidence_contract.runtime_suite_targets_for(target, contract),
                "required_scenarios": evidence_contract.runtime_required_scenarios(contract),
                "blocked_reason": (
                    "rc-evidence-dry-run records the runtime plan gap only; production runtime-plan "
                    "requires measured OVMF, swtpm, QMP, serial, and typed observation artifacts"
                ),
            }
        )
    return {
        "schema_version": "suderra.rc-runtime-plan-gap.v1",
        "version": version,
        "profile": PROFILE,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "status": "blocked_for_production",
        "runtime_targets": sorted(targets, key=lambda item: str(item["target"])),
    }


def create_command(args: argparse.Namespace) -> int:
    try:
        contract = evidence_contract.load_contract(args.contract)
        profile = evidence_contract.profile_policy(PROFILE, contract)
        if profile.get("release_authorizing") is not False or profile.get("publication_allowed") is not False:
            raise ValueError("rc-evidence-dry-run profile must be non-promotable")
        binding = read_json(args.binding_manifest)
        if not isinstance(binding, dict):
            raise ValueError(f"binding manifest must be a JSON object: {args.binding_manifest}")
        if binding.get("profile") != PROFILE:
            raise ValueError(f"binding manifest profile must be {PROFILE}")
        version = str(binding.get("version", ""))
        source_sha = str(binding.get("source_sha", ""))
        source_run_id = str(binding.get("source_run_id", ""))
        if "-" not in version:
            raise ValueError("rc-evidence-dry-run requires a prerelease SemVer version")
        if not SOURCE_SHA_RE.fullmatch(source_sha):
            raise ValueError("binding source_sha must be a lowercase git commit sha")
        matrix, matrix_module = load_matrix_with_module(args.matrix)
        binding_failures = evidence_contract.validate_release_artifact_bindings(
            binding.get("artifacts"),
            evidence_contract.expected_release_artifact_map(matrix, matrix_module),
            artifact_root=args.input_root / "build-artifacts",
            file_hasher=sha256_file,
        )
        if binding_failures:
            raise ValueError("; ".join(binding_failures))
        output_root = args.output_root / version
        plans_root = output_root / "plans"
        subject_plan_root = plans_root / "subject-plan"

        join_errors = evidence_contract.validate_matrix_join(matrix, contract)
        validate_join_text = (
            "validated evidence contract/build matrix join\n"
            if not join_errors
            else "ERRORS:\n" + "\n".join(join_errors) + "\n"
        )
        validate_join_path = plans_root / "validate-join.txt"
        validate_join_path.parent.mkdir(parents=True, exist_ok=True)
        validate_join_path.write_text(validate_join_text, encoding="utf-8")
        if join_errors:
            raise ValueError("evidence contract/build matrix join failed")

        write_json(
            plans_root / "output-tree-plan.json",
            evidence_contract.output_tree_plan(version=version, profile=PROFILE, contract=contract),
        )
        write_json(
            plans_root / "retention-plan.json",
            evidence_contract.retention_plan(version=version, source_sha=source_sha, source_run_id=source_run_id, contract=contract),
        )
        write_json(
            plans_root / "runtime-plan" / "gaps.json",
            runtime_plan_gap(matrix, contract, version=version, source_sha=source_sha, source_run_id=source_run_id),
        )

        subject_graph_path = args.input_root / f"release-subject-graph/{version}/release-subject-graph.json"
        subject_graph = read_json(subject_graph_path)
        if not isinstance(subject_graph, dict):
            raise ValueError(f"release subject graph must be a JSON object: {subject_graph_path}")
        if subject_graph.get("schema_version") != evidence_contract.schema_version("release_subject_graph", contract):
            raise ValueError("release subject graph schema_version does not match evidence contract")
        if subject_graph.get("version") != version or subject_graph.get("profile") != PROFILE:
            raise ValueError("release subject graph must match the rc-evidence-dry-run binding identity")
        if subject_graph.get("source_sha") != source_sha or str(subject_graph.get("source_run_id")) != source_run_id:
            raise ValueError("release subject graph must match the source SHA and Image Build run")

        subject_plans: list[dict[str, Any]] = []
        subject_plan_paths: list[str] = []
        graph_subjects = subject_graph.get("subjects")
        if not isinstance(graph_subjects, list) or not graph_subjects:
            raise ValueError("release subject graph must contain subjects")
        for subject in sorted(graph_subjects, key=lambda item: str(item.get("target", "")) if isinstance(item, dict) else ""):
            if not isinstance(subject, dict) or not isinstance(subject.get("target"), str):
                raise ValueError("release subject graph subjects must be objects with target")
            target = str(subject["target"])
            artifacts = subject.get("artifacts")
            raw_identity = _artifact_identity(artifacts, "raw_image")
            compressed_identity = _artifact_identity(artifacts, "compressed_release_artifact")
            if raw_identity is None or compressed_identity is None:
                raise ValueError(f"release subject graph subject {target} must have non-null raw/compressed artifact identity")
            subject_plan = subject_plan_from_graph_subject(graph=subject_graph, subject=subject)
            subject_plan_path = subject_plan_root / f"{target}.json"
            write_json(subject_plan_path, subject_plan)
            subject_plans.append(subject_plan)
            subject_plan_paths.append(subject_plan_path.relative_to(output_root).as_posix())

        artifact_digest_inventory = {
            "schema_version": "suderra.rc-image-build-artifact-digests.v1",
            "version": version,
            "source_sha": source_sha,
            "source_run_id": source_run_id,
            "artifacts": binding.get("artifacts", []),
            "installers": binding.get("installers", []),
            "image_build_contract": binding.get("image_build_contract"),
        }
        write_json(output_root / "digests" / "image-build-artifacts.json", artifact_digest_inventory)

        gaps = {
            "schema_version": "suderra.rc-production-gap-report.v1",
            "version": version,
            "source_sha": source_sha,
            "source_run_id": source_run_id,
            "profile": PROFILE,
            "production_ready": False,
            "status": "blocked_for_production",
            "gaps": production_gap_rows(matrix, contract),
        }
        write_json(output_root / "gaps.json", gaps)

        bundle_members = [
            file_record(
                output_root,
                "plans/validate-join.txt",
                role="validate-join",
            ),
            file_record(
                output_root,
                "plans/output-tree-plan.json",
                role="output-tree-plan",
                schema_version="suderra.profile-output-tree-plan.v1",
            ),
            file_record(
                output_root,
                "plans/retention-plan.json",
                role="retention-plan",
                schema_version=evidence_contract.retention_policy(contract)["manifest_schema_version"],
            ),
            file_record(
                output_root,
                "plans/runtime-plan/gaps.json",
                role="runtime-plan-gaps",
                schema_version="suderra.rc-runtime-plan-gap.v1",
            ),
            file_record(
                output_root,
                "digests/image-build-artifacts.json",
                role="image-build-artifact-digests",
                schema_version="suderra.rc-image-build-artifact-digests.v1",
            ),
            file_record(
                output_root,
                "gaps.json",
                role="production-gap-report",
                schema_version="suderra.rc-production-gap-report.v1",
            ),
        ]
        for rel in subject_plan_paths:
            bundle_members.append(
                file_record(
                    output_root,
                    rel,
                    role="subject-plan",
                    schema_version=evidence_contract.schema_version("release_subject_graph", contract),
                )
            )
        try:
            binding_rel = args.binding_manifest.resolve().relative_to(args.input_root.resolve()).as_posix()
        except ValueError:
            if args.binding_manifest.is_absolute():
                raise ValueError("--binding-manifest must be under --input-root for canonical dry-run replay")
            binding_rel = args.binding_manifest.as_posix()
        external_refs = [
            file_record(
                args.input_root,
                binding_rel,
                role="release-input-binding",
                schema_version="suderra.release-input-binding.v2",
            ),
            file_record(
                args.input_root,
                f"release-subject-graph/{version}/release-subject-graph.json",
                role="release-subject-graph",
                schema_version=evidence_contract.schema_version("release_subject_graph", contract),
            ),
            file_record(
                args.input_root,
                f"release-governance/{version}/snapshot-manifest.json",
                role="governance-snapshot-manifest",
                schema_version="suderra.github-governance-snapshot-manifest.v1",
            ),
            file_record(
                args.input_root,
                f"release-governance/{version}/governance-policy-validation.json",
                role="governance-policy-validation",
                schema_version="suderra.github-governance-validation.v2",
            ),
        ]
        bundle_manifest = {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "version": version,
            "profile": PROFILE,
            "source_sha": source_sha,
            "source_run_id": source_run_id,
            "source_run_attempt": str(binding.get("source_run_attempt")),
            "status": "non_promotable",
            "production_ready": False,
            "release_authorizing": False,
            "publication_allowed": False,
            "members": sorted(bundle_members, key=lambda item: (str(item["role"]), str(item["path"]))),
            "external_refs": sorted(external_refs, key=lambda item: (str(item["role"]), str(item["path"]))),
            "producer": {
                "name": "rc-evidence-dry-run.py create",
                "source": "ci/evidence-contract.yml",
            },
        }
        write_json(output_root / "bundle-manifest.json", bundle_manifest)
        bundle_manifest_record = file_record(
            output_root,
            "bundle-manifest.json",
            role="bundle-manifest",
            schema_version=BUNDLE_SCHEMA_VERSION,
        )

        report = {
            "schema_version": SCHEMA_VERSION,
            "version": version,
            "profile": PROFILE,
            "source_sha": source_sha,
            "source_run_id": source_run_id,
            "source_run_attempt": str(binding.get("source_run_attempt")),
            "generated_at": now_utc(),
            "status": "non_promotable",
            "production_ready": False,
            "release_authorizing": False,
            "publication_allowed": False,
            "bundle_manifest": bundle_manifest_record,
            "subject_count": len(subject_plans),
            "producer": {
                "name": "rc-evidence-dry-run.py create",
                "source": "ci/evidence-contract.yml",
            },
        }
        write_json(output_root / "dry-run-report.json", report)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"wrote RC evidence dry-run bundle: {output_root}")
    return 0


def validate_bundle_manifest(bundle_manifest_path: Path, *, input_root: Path | None, failures: list[str]) -> dict[str, Any] | None:
    root = bundle_manifest_path.parent
    resolved_input_root = input_root if input_root is not None else root.parent.parent
    bundle_manifest = read_json_file(bundle_manifest_path, failures, "$.bundle_manifest")
    if not isinstance(bundle_manifest, dict):
        return None
    if bundle_manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        failures.append(f"bundle-manifest schema_version must be {BUNDLE_SCHEMA_VERSION}")
    if bundle_manifest.get("profile") != PROFILE:
        failures.append("bundle-manifest profile must be rc-evidence-dry-run")
    version = str(bundle_manifest.get("version"))
    source_sha = str(bundle_manifest.get("source_sha"))
    source_run_id = str(bundle_manifest.get("source_run_id"))
    if "-" not in version:
        failures.append("bundle-manifest version must be prerelease SemVer")
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("bundle-manifest source_sha must be a lowercase git commit sha")
    if bundle_manifest.get("production_ready") is not False:
        failures.append("bundle-manifest production_ready must be false")
    if bundle_manifest.get("status") != "non_promotable":
        failures.append("bundle-manifest status must be non_promotable")
    if bundle_manifest.get("release_authorizing") is not False or bundle_manifest.get("publication_allowed") is not False:
        failures.append("bundle-manifest must be non release-authorizing and non-publishing")

    member_paths_by_role: dict[str, list[Path]] = {}
    members = bundle_manifest.get("members")
    if not isinstance(members, list) or not members:
        failures.append("bundle-manifest members must be a non-empty list")
        members = []
    member_roles = records_by_role(members)
    for role in (
        "validate-join",
        "output-tree-plan",
        "retention-plan",
        "runtime-plan-gaps",
        "subject-plan",
        "image-build-artifact-digests",
        "production-gap-report",
    ):
        if role not in member_roles:
            failures.append(f"bundle-manifest must include member role {role}")
    for idx, item in enumerate(members):
        member_path = verify_file_record(root, item, failures, f"bundle-manifest.members[{idx}]")
        if member_path is None or not isinstance(item, dict):
            continue
        role = str(item.get("role"))
        member_paths_by_role.setdefault(role, []).append(member_path)
        if role != "validate-join":
            validate_role_payload(
                failures,
                role,
                member_path,
                schema_version=item.get("schema_version") if isinstance(item.get("schema_version"), str) else None,
                version=version,
                source_sha=source_sha,
                source_run_id=source_run_id,
            )

    external_paths_by_role: dict[str, Path] = {}
    external_refs = bundle_manifest.get("external_refs")
    if not isinstance(external_refs, list) or not external_refs:
        failures.append("bundle-manifest external_refs must be a non-empty list")
        external_refs = []
    external_roles = records_by_role(external_refs)
    for role in ("release-input-binding", "release-subject-graph", "governance-snapshot-manifest", "governance-policy-validation"):
        if role not in external_roles:
            failures.append(f"bundle-manifest must include external ref role {role}")
        elif len(external_roles[role]) != 1:
            failures.append(f"bundle-manifest must include exactly one external ref role {role}")
    for idx, item in enumerate(external_refs):
        external_path = verify_file_record(resolved_input_root, item, failures, f"bundle-manifest.external_refs[{idx}]")
        if external_path is None or not isinstance(item, dict):
            continue
        role = str(item.get("role"))
        external_paths_by_role[role] = external_path
        validate_role_payload(
            failures,
            role,
            external_path,
            schema_version=item.get("schema_version") if isinstance(item.get("schema_version"), str) else None,
            version=version,
            source_sha=source_sha,
            source_run_id=source_run_id,
        )

    gap_paths = member_paths_by_role.get("production-gap-report", [])
    if gap_paths:
        gaps = read_json_file(gap_paths[0], failures, "production-gap-report")
        if not isinstance(gaps, dict) or gaps.get("status") != "blocked_for_production":
            failures.append("gaps.json must be blocked_for_production")
        elif not isinstance(gaps.get("gaps"), list) or not gaps["gaps"]:
            failures.append("gaps.json must list remaining production evidence gaps")
    snapshot_path = external_paths_by_role.get("governance-snapshot-manifest")
    if snapshot_path is not None:
        replay_governance_snapshot(snapshot_path, failures)
    binding_path = external_paths_by_role.get("release-input-binding")
    subject_graph_path = external_paths_by_role.get("release-subject-graph")
    if binding_path is not None and subject_graph_path is not None:
        replay_binding_and_subjects(
            failures=failures,
            binding_path=binding_path,
            artifact_inventory_path=member_paths_by_role.get("image-build-artifact-digests", [None])[0],
            subject_graph_path=subject_graph_path,
            subject_plan_paths=member_paths_by_role.get("subject-plan", []),
            input_root=resolved_input_root,
            version=version,
            source_sha=source_sha,
            source_run_id=source_run_id,
        )
    return bundle_manifest


def validate_report(report_path: Path, *, input_root: Path | None, failures: list[str]) -> None:
    report = read_json_file(report_path, failures, "dry-run-report")
    if not isinstance(report, dict):
        return
    if report.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"report schema_version must be {SCHEMA_VERSION}")
    for legacy_field in ("binding_manifest", "subject_graph", "governance_refs", "plans", "digests", "gap_report"):
        if legacy_field in report:
            failures.append(f"dry-run-report.{legacy_field}: must not duplicate bundle-manifest state")
    for field, expected in (
        ("profile", PROFILE),
        ("status", "non_promotable"),
        ("production_ready", False),
        ("release_authorizing", False),
        ("publication_allowed", False),
    ):
        matches = report.get(field) is expected if isinstance(expected, bool) else report.get(field) == expected
        if not matches:
            failures.append(f"dry-run-report.{field}: must be {expected!r}")
    bundle_manifest_path = None
    if isinstance(report.get("bundle_manifest"), dict):
        bundle_manifest_path = verify_file_record(report_path.parent, report["bundle_manifest"], failures, "$.bundle_manifest")
    else:
        failures.append("$.bundle_manifest: must be a digest-bound file record")
    if bundle_manifest_path is None:
        return
    bundle_manifest = validate_bundle_manifest(bundle_manifest_path, input_root=input_root, failures=failures)
    if not isinstance(bundle_manifest, dict):
        return
    for field in ("version", "source_sha", "source_run_id", "source_run_attempt", "status"):
        if str(bundle_manifest.get(field)) != str(report.get(field)):
            failures.append(f"dry-run-report.{field}: must match bundle-manifest")
    members = bundle_manifest.get("members")
    if isinstance(members, list):
        subject_count = sum(1 for item in members if isinstance(item, dict) and item.get("role") == "subject-plan")
        if report.get("subject_count") != subject_count:
            failures.append("dry-run-report.subject_count: must match bundle-manifest subject-plan members")


def validate_command(args: argparse.Namespace) -> int:
    failures: list[str] = []
    try:
        payload = read_json(args.path)
    except Exception as exc:
        print(f"ERROR: cannot read RC dry-run input: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("ERROR: RC dry-run input must be a JSON object", file=sys.stderr)
        return 1
    schema = payload.get("schema_version")
    if schema == BUNDLE_SCHEMA_VERSION:
        validate_bundle_manifest(args.path, input_root=args.input_root, failures=failures)
        label = "bundle manifest"
    elif schema == SCHEMA_VERSION:
        validate_report(args.path, input_root=args.input_root, failures=failures)
        label = "report"
    else:
        failures.append(f"input schema_version must be {BUNDLE_SCHEMA_VERSION} or {SCHEMA_VERSION}")
        label = "input"
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated RC evidence dry-run {label}: {args.path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--binding-manifest", type=Path, required=True)
    create.add_argument("--output-root", type=Path, default=Path("release-dry-run"))
    create.add_argument("--input-root", type=Path, default=Path("."))
    create.add_argument("--contract", type=Path, default=evidence_contract.DEFAULT_CONTRACT)
    create.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate")
    validate.add_argument("path", type=Path)
    validate.add_argument("--input-root", type=Path)
    validate.set_defaults(func=validate_command)

    validate_report_parser = subparsers.add_parser("validate-report")
    validate_report_parser.add_argument("path", type=Path)
    validate_report_parser.add_argument("--input-root", type=Path)
    validate_report_parser.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
