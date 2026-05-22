#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate immutable USB installer base manifests."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA_VERSION = "suderra.usb-installer-base.v1"
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


def file_record(path: Path, role: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise SystemExit(f"required {role} file missing or empty: {path}")
    return {
        "role": role,
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def canonical_payload(payload: dict[str, Any]) -> bytes:
    material = dict(payload)
    material.pop("identity_digest", None)
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def identity_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(payload)).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create(args: argparse.Namespace) -> None:
    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        raise SystemExit("--source-sha must be a lowercase 40-character git SHA")
    base_dir = args.base_dir
    source_identity_sha = sha256_file(args.source_identity)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "defconfig": args.defconfig,
        "target": args.target,
        "source_sha": args.source_sha,
        "workflow": {
            "name": args.workflow_name,
            "path": args.workflow_path,
            "ref": args.workflow_ref,
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
        },
        "matrix": {
            "path": args.matrix_path.as_posix(),
            "sha256": sha256_file(args.matrix_path),
        },
        "builder": {
            "image": args.builder_image,
        },
        "source_date_epoch": str(args.source_date_epoch),
        "buildroot_source_identity": {
            "path": args.source_identity.name,
            "sha256": source_identity_sha,
        },
        "genimage_base": {
            "path": args.genimage_cfg.as_posix(),
            "sha256": sha256_file(args.genimage_cfg),
        },
        "installer_payload_public_key": {
            "path": args.public_key.name,
            "sha256": sha256_file(args.public_key),
        },
        "build_evidence": {
            "path": args.build_evidence.name,
            "sha256": sha256_file(args.build_evidence),
        },
        "files": [
            file_record(base_dir / "boot.vfat", "boot-vfat"),
            file_record(base_dir / "rootfs.ext4", "rootfs-ext4"),
        ],
        "generated_at": utc_now(),
    }
    payload["identity_digest"] = identity_digest(payload)
    write_json(args.output, payload)
    if args.digest_output is not None:
        args.digest_output.write_text(payload["identity_digest"] + "\n", encoding="utf-8")


def key(args: argparse.Namespace) -> None:
    print(sha256_file(args.public_key))


def validate_payload(payload: dict[str, Any], path: Path, args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    digest = payload.get("identity_digest")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        failures.append("identity_digest must be a sha256")
    elif identity_digest(payload) != digest:
        failures.append("identity_digest does not match canonical manifest")
    source_sha = payload.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("source_sha must be a lowercase git SHA")
    if args.expect_source_sha and source_sha != args.expect_source_sha:
        failures.append("source_sha does not match expected source")
    workflow = payload.get("workflow")
    if not isinstance(workflow, dict):
        failures.append("workflow must be an object")
    else:
        if args.workflow_path and workflow.get("path") != args.workflow_path:
            failures.append("workflow.path does not match expected workflow")
        for field in ("run_id", "run_attempt"):
            value = workflow.get(field)
            if not isinstance(value, str) or not value.isdigit() or int(value) <= 0:
                failures.append(f"workflow.{field} must be a positive integer string")
    files = payload.get("files")
    expected_roles = {"boot-vfat": "boot.vfat", "rootfs-ext4": "rootfs.ext4"}
    if not isinstance(files, list):
        failures.append("files must be a list")
    else:
        by_role = {item.get("role"): item for item in files if isinstance(item, dict)}
        for role, name in expected_roles.items():
            item = by_role.get(role)
            if not isinstance(item, dict):
                failures.append(f"files missing {role}")
                continue
            if item.get("path") != name:
                failures.append(f"{role}.path must be {name}")
            digest_value = item.get("sha256")
            if not isinstance(digest_value, str) or not SHA256_RE.fullmatch(digest_value):
                failures.append(f"{role}.sha256 must be a sha256")
            if not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
                failures.append(f"{role}.bytes must be positive")
            if args.base_dir is not None:
                candidate = args.base_dir / name
                if not candidate.is_file():
                    failures.append(f"base file missing: {candidate}")
                else:
                    if candidate.stat().st_size != item.get("bytes"):
                        failures.append(f"base file size mismatch: {candidate}")
                    if isinstance(digest_value, str) and sha256_file(candidate) != digest_value:
                        failures.append(f"base file sha mismatch: {candidate}")
    pubkey = payload.get("installer_payload_public_key")
    if not isinstance(pubkey, dict) or not isinstance(pubkey.get("sha256"), str):
        failures.append("installer_payload_public_key.sha256 is required")
    elif args.public_key is not None and sha256_file(args.public_key) != pubkey["sha256"]:
        failures.append("installer payload public key does not match base manifest")
    source_identity = payload.get("buildroot_source_identity")
    if args.source_identity is not None:
        if not isinstance(source_identity, dict) or sha256_file(args.source_identity) != source_identity.get("sha256"):
            failures.append("Buildroot source identity does not match base manifest")
    return failures


def validate(args: argparse.Namespace) -> None:
    try:
        payload = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid base manifest JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("base manifest must be a JSON object")
    failures = validate_payload(payload, args.manifest, args)
    if failures:
        raise SystemExit("\n".join(failures))
    print(payload["identity_digest"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--defconfig", required=True)
    create_parser.add_argument("--target", required=True)
    create_parser.add_argument("--source-sha", required=True)
    create_parser.add_argument("--workflow-name", default="Image Build")
    create_parser.add_argument("--workflow-path", default=".github/workflows/image-build.yml")
    create_parser.add_argument("--workflow-ref", required=True)
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument("--run-attempt", required=True)
    create_parser.add_argument("--matrix-path", type=Path, default=Path("ci/build-matrix.yml"))
    create_parser.add_argument("--builder-image", default="suderra-builder:latest")
    create_parser.add_argument("--source-date-epoch", required=True)
    create_parser.add_argument("--source-identity", type=Path, required=True)
    create_parser.add_argument("--genimage-cfg", type=Path, required=True)
    create_parser.add_argument("--public-key", type=Path, required=True)
    create_parser.add_argument("--build-evidence", type=Path, required=True)
    create_parser.add_argument("--base-dir", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--digest-output", type=Path)
    create_parser.set_defaults(func=create)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.add_argument("--base-dir", type=Path)
    validate_parser.add_argument("--public-key", type=Path)
    validate_parser.add_argument("--source-identity", type=Path)
    validate_parser.add_argument("--expect-source-sha")
    validate_parser.add_argument("--workflow-path")
    validate_parser.set_defaults(func=validate)

    key_parser = subparsers.add_parser("key")
    key_parser.add_argument("--public-key", type=Path, required=True)
    key_parser.set_defaults(func=key)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
