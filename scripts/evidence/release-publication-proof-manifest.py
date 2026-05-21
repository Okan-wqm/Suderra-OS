#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate the post-publication proof manifest.

The base release-publication-manifest.json is immutable after signing. This
second-stage manifest closes the public-release cycle by referencing the base
manifest digest plus the public post-publication proof files that are created
after the GitHub Release asset set is re-downloaded.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


SCHEMA_VERSION = "suderra.release-publication-proof-manifest.v1"
BASE_MANIFEST = "release-publication-manifest.json"
PROOF_RECORD = "release-post-publication-verification.json"
PROOF_SIGNATURE = f"{PROOF_RECORD}.sig"
PROOF_CERTIFICATE = f"{PROOF_RECORD}.cert"
SELF_NAME = "release-publication-proof-manifest.json"


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_ref(root: Path, name: str) -> dict[str, Any]:
    path = root / name
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"missing non-empty proof file: {name}")
    return {"path": name, "sha256": sha256_file(path), "bytes": path.stat().st_size}


def raw_attestation_refs(root: Path, proof_payload: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    assets = proof_payload.get("assets")
    if not isinstance(assets, list):
        return refs
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        attestation = asset.get("attestation")
        if not isinstance(attestation, dict):
            continue
        rel = attestation.get("path")
        if not isinstance(rel, str) or Path(rel).name != rel or rel in seen:
            continue
        seen.add(rel)
        path = root / rel
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"missing raw attestation JSON referenced by proof: {rel}")
        refs.append({"path": rel, "sha256": sha256_file(path), "bytes": path.stat().st_size})
    return sorted(refs, key=lambda item: item["path"])


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_manifest(args: argparse.Namespace) -> dict[str, Any]:
    release_dir = args.release_dir
    proof_dir = args.proof_dir
    proof_payload = read_json(proof_dir / PROOF_RECORD)
    version = args.version or proof_payload.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("version must be supplied or present in post-publication proof")
    proof_files = [
        file_ref(proof_dir, PROOF_RECORD),
        file_ref(proof_dir, PROOF_SIGNATURE),
        file_ref(proof_dir, PROOF_CERTIFICATE),
    ]
    raw_refs = raw_attestation_refs(proof_dir, proof_payload)
    material = "\n".join(
        f"{item['path']} {item['sha256']}"
        for item in sorted(proof_files + raw_refs, key=lambda value: value["path"])
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "generated_at": now_utc(),
        "base_publication_manifest": file_ref(release_dir, BASE_MANIFEST),
        "post_publication_proof": {
            "files": proof_files,
            "raw_attestations": raw_refs,
            "proof_set_sha256": hashlib.sha256(material.encode("utf-8")).hexdigest(),
        },
    }


def validate_file_ref(root: Path, value: Any, path: str, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append(f"{path} must be an object")
        return
    rel = value.get("path")
    if not isinstance(rel, str) or Path(rel).name != rel:
        failures.append(f"{path}.path must be a safe file name")
        return
    actual = root / rel
    if not actual.is_file() or actual.stat().st_size <= 0:
        failures.append(f"{path}.path references missing or empty file: {rel}")
        return
    if value.get("sha256") != sha256_file(actual):
        failures.append(f"{path}.sha256 does not match {rel}")
    if value.get("bytes") != actual.stat().st_size:
        failures.append(f"{path}.bytes does not match {rel}")


def validate_manifest(path: Path, *, release_dir: Path, proof_dir: Path, expected_version: str | None) -> list[str]:
    failures: list[str] = []
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot read proof manifest: {exc}"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    if expected_version is not None and payload.get("version") != expected_version:
        failures.append(f"version must be {expected_version}")
    validate_file_ref(release_dir, payload.get("base_publication_manifest"), "base_publication_manifest", failures)
    proof = payload.get("post_publication_proof")
    if not isinstance(proof, dict):
        failures.append("post_publication_proof must be an object")
        return failures
    files = proof.get("files")
    if not isinstance(files, list) or not files:
        failures.append("post_publication_proof.files must be a non-empty list")
        files = []
    for idx, item in enumerate(files):
        validate_file_ref(proof_dir, item, f"post_publication_proof.files[{idx}]", failures)
    raw = proof.get("raw_attestations")
    if not isinstance(raw, list):
        failures.append("post_publication_proof.raw_attestations must be a list")
        raw = []
    for idx, item in enumerate(raw):
        validate_file_ref(proof_dir, item, f"post_publication_proof.raw_attestations[{idx}]", failures)
    material = "\n".join(
        f"{item.get('path')} {item.get('sha256')}"
        for item in sorted([*files, *raw], key=lambda value: str(value.get("path")) if isinstance(value, dict) else "")
        if isinstance(item, dict)
    )
    expected_set = hashlib.sha256(material.encode("utf-8")).hexdigest()
    if proof.get("proof_set_sha256") != expected_set:
        failures.append("post_publication_proof.proof_set_sha256 does not match proof files")
    return failures


def create_command(args: argparse.Namespace) -> int:
    try:
        payload = create_manifest(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    write_json(args.output, payload)
    print(f"wrote publication proof manifest: {args.output}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    failures = validate_manifest(
        args.input,
        release_dir=args.release_dir,
        proof_dir=args.proof_dir,
        expected_version=args.expected_version,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated publication proof manifest: {args.input}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--version")
    create.add_argument("--release-dir", type=Path, required=True)
    create.add_argument("--proof-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--release-dir", type=Path, required=True)
    validate.add_argument("--proof-dir", type=Path, required=True)
    validate.add_argument("--expected-version")
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
