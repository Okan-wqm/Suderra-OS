#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate post-publication release verification evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "suderra.post-publication-verification.v2"
LEGACY_SCHEMA_VERSIONS = {"suderra.post-publication-verification.v1"}
PLACEHOLDERS = {"", "not_collected", "NOT_COLLECTED", "TO_BE_COLLECTED", "pending", "PENDING"}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_placeholder(value: Any) -> bool:
    return not isinstance(value, str) or value.strip() in PLACEHOLDERS


def load_script(name: str, rel: str) -> Any:
    script = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} top-level JSON value must be an object")
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def subject_set(subjects: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        (str(subject.get("name")), str(subject.get("sha256")))
        for subject in subjects
        if isinstance(subject, dict)
    }


def create_record(args: argparse.Namespace) -> dict[str, Any]:
    publication = load_script(
        "release_publication_manifest",
        "scripts/evidence/release-publication-manifest.py",
    )
    machine = load_script(
        "machine_verification_record",
        "scripts/evidence/machine-verification-record.py",
    )

    manifest_path = args.release_dir / "release-publication-manifest.json"
    failures = publication.validate_manifest(
        manifest_path,
        release_dir=args.release_dir,
        expected_version=args.version,
        require_self_sidecars=True,
        require_asset_sidecars=True,
    )
    if failures:
        raise ValueError("; ".join(failures))
    manifest = read_json(manifest_path)

    identity = args.identity or os.environ.get("COSIGN_IDENTITY")
    issuer = args.issuer or "https://token.actions.githubusercontent.com"
    source = {
        "repository": args.repository or os.environ.get("GITHUB_REPOSITORY"),
        "workflow": args.workflow or os.environ.get("GITHUB_WORKFLOW"),
        "run_id": args.run_id or os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT"),
        "ref": args.ref or os.environ.get("GITHUB_REF"),
        "source_sha": args.source_sha or os.environ.get("GITHUB_SHA"),
    }
    for field, value in (("identity", identity), ("issuer", issuer), *source.items()):
        if is_placeholder(value):
            raise ValueError(f"{field} must be collected before creating post-publication verification")

    assets: list[dict[str, Any]] = []
    for item in manifest.get("files", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or name.endswith((".sig", ".cert")):
            continue
        asset_path = args.release_dir / name
        sig_path = args.release_dir / f"{name}.sig"
        cert_path = args.release_dir / f"{name}.cert"
        attestation_path = args.attestation_json_dir / f"{name}.json"
        if not asset_path.is_file():
            raise ValueError(f"published asset is missing: {name}")
        for sidecar in (sig_path, cert_path, attestation_path):
            if not sidecar.is_file() or sidecar.stat().st_size <= 0:
                raise ValueError(f"published verification material is missing or empty: {sidecar}")

        attestation_payload = json.loads(attestation_path.read_text(encoding="utf-8"))
        verified_subjects: dict[tuple[str, str], dict[str, str]] = {}
        provenance: list[dict[str, Any]] = []
        for statement in machine.iter_attestation_statements(attestation_payload):
            subjects = machine.subjects_from_statement(statement)
            for subject in subjects:
                verified_subjects[machine.subject_identity(subject)] = {
                    "name": subject["name"],
                    "sha256": subject["sha256"],
                }
            if subjects:
                context, provenance_failures = machine.provenance_context(
                    statement,
                    expected_repository=str(source["repository"]),
                    expected_ref=str(source["ref"]),
                    expected_run_id=str(source["run_id"]),
                    expected_run_attempt=str(source["run_attempt"]),
                    expected_source_sha=str(source["source_sha"]),
                )
                if provenance_failures:
                    raise ValueError(
                        f"attestation provenance for {name} does not match publication context: "
                        + "; ".join(provenance_failures)
                    )
                provenance.append(context)
        expected_subject = (name, sha256_file(asset_path))
        if expected_subject not in verified_subjects:
            actual = sorted(f"{item[0]}@{item[1]}" for item in verified_subjects)
            raise ValueError(f"attestation subjects for {name} do not include published digest; actual={actual}")

        assets.append(
            {
                "name": name,
                "role": item.get("role"),
                "sha256": expected_subject[1],
                "bytes": asset_path.stat().st_size,
                "signature": {
                    "path": sig_path.name,
                    "sha256": sha256_file(sig_path),
                    "bytes": sig_path.stat().st_size,
                },
                "certificate": {
                    "path": cert_path.name,
                    "sha256": sha256_file(cert_path),
                    "bytes": cert_path.stat().st_size,
                },
                "attestation": {
                    "path": attestation_path.name,
                    "sha256": sha256_file(attestation_path),
                    "bytes": attestation_path.stat().st_size,
                    "subjects": sorted(verified_subjects.values(), key=lambda value: (value["name"], value["sha256"])),
                    "provenance": provenance,
                },
            }
        )

    if not assets:
        raise ValueError("post-publication verification found no public assets")
    asset_set_material = "\n".join(f"{item['name']} {item['sha256']}" for item in sorted(assets, key=lambda value: value["name"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "version": args.version,
        "status": "passed",
        "generated_at": now_utc(),
        "identity": identity,
        "issuer": issuer,
        "source": source,
        "publication_manifest": {
            "path": manifest_path.name,
            "sha256": sha256_file(manifest_path),
            "bytes": manifest_path.stat().st_size,
        },
        "asset_set_sha256": hashlib.sha256(asset_set_material.encode("utf-8")).hexdigest(),
        "assets": assets,
    }


def validate_subjects(value: Any, path: str, failures: list[str]) -> None:
    if not isinstance(value, list) or not value:
        failures.append(f"{path} must be a non-empty list")
        return
    for idx, item in enumerate(value):
        item_path = f"{path}[{idx}]"
        if not isinstance(item, dict):
            failures.append(f"{item_path} must be an object")
            continue
        name = item.get("name")
        sha = item.get("sha256")
        if is_placeholder(name) or Path(str(name)).name != name:
            failures.append(f"{item_path}.name must be a safe file name")
        if not isinstance(sha, str) or len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            failures.append(f"{item_path}.sha256 must be lowercase sha256")


def validate_file_ref(value: Any, path: str, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append(f"{path} must be an object")
        return
    rel = value.get("path")
    if is_placeholder(rel) or Path(str(rel)).name != rel:
        failures.append(f"{path}.path must be a safe file name")
    sha = value.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
        failures.append(f"{path}.sha256 must be lowercase sha256")
    if not isinstance(value.get("bytes"), int) or value["bytes"] <= 0:
        failures.append(f"{path}.bytes must be positive")


def validate_record(payload: dict[str, Any], *, expected_version: str | None = None) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") not in LEGACY_SCHEMA_VERSIONS | {SCHEMA_VERSION}:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    if expected_version is not None and payload.get("version") != expected_version:
        failures.append(f"version must be {expected_version}")
    if payload.get("status") != "passed":
        failures.append("status must be passed")
    for field in ("identity", "issuer", "generated_at", "asset_set_sha256"):
        if is_placeholder(payload.get(field)):
            failures.append(f"{field} must be non-placeholder")
    source = payload.get("source")
    if not isinstance(source, dict):
        failures.append("source must be an object")
    else:
        for field in ("repository", "workflow", "run_id", "run_attempt", "ref"):
            if is_placeholder(source.get(field)):
                failures.append(f"source.{field} must be non-placeholder")
        if payload.get("schema_version") == SCHEMA_VERSION and is_placeholder(source.get("source_sha")):
            failures.append("source.source_sha must be non-placeholder")
    validate_file_ref(payload.get("publication_manifest"), "publication_manifest", failures)
    assets = payload.get("assets")
    if not isinstance(assets, list) or not assets:
        failures.append("assets must be a non-empty list")
        return failures
    seen: set[str] = set()
    for idx, asset in enumerate(assets):
        path = f"assets[{idx}]"
        if not isinstance(asset, dict):
            failures.append(f"{path} must be an object")
            continue
        name = asset.get("name")
        sha = asset.get("sha256")
        if is_placeholder(name) or Path(str(name)).name != name:
            failures.append(f"{path}.name must be a safe file name")
        elif name in seen:
            failures.append(f"{path}.name is duplicated")
        else:
            seen.add(name)
        if not isinstance(sha, str) or len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            failures.append(f"{path}.sha256 must be lowercase sha256")
        if not isinstance(asset.get("bytes"), int) or asset["bytes"] <= 0:
            failures.append(f"{path}.bytes must be positive")
        validate_file_ref(asset.get("signature"), f"{path}.signature", failures)
        validate_file_ref(asset.get("certificate"), f"{path}.certificate", failures)
        attestation = asset.get("attestation")
        validate_file_ref(attestation, f"{path}.attestation", failures)
        if isinstance(attestation, dict):
            validate_subjects(attestation.get("subjects"), f"{path}.attestation.subjects", failures)
            if payload.get("schema_version") == SCHEMA_VERSION:
                provenance = attestation.get("provenance")
                if not isinstance(provenance, list) or not provenance:
                    failures.append(f"{path}.attestation.provenance must be a non-empty list")
            if isinstance(name, str) and isinstance(sha, str):
                subjects = attestation.get("subjects")
                if isinstance(subjects, list) and (name, sha) not in subject_set(subjects):
                    failures.append(f"{path}.attestation.subjects must include published asset digest")
    return failures


def create_command(args: argparse.Namespace) -> int:
    try:
        payload = create_record(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    write_json(args.output, payload)
    print(f"wrote post-publication verification: {args.output}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    try:
        payload = read_json(args.input)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read post-publication verification: {exc}", file=sys.stderr)
        return 1
    failures = validate_record(payload, expected_version=args.expected_version)
    if args.release_dir is not None and args.attestation_json_dir is not None:
        create_args = argparse.Namespace(
            version=payload.get("version"),
            release_dir=args.release_dir,
            attestation_json_dir=args.attestation_json_dir,
            output=args.input,
            identity=payload.get("identity"),
            issuer=payload.get("issuer"),
            repository=payload.get("source", {}).get("repository") if isinstance(payload.get("source"), dict) else None,
            workflow=payload.get("source", {}).get("workflow") if isinstance(payload.get("source"), dict) else None,
            run_id=payload.get("source", {}).get("run_id") if isinstance(payload.get("source"), dict) else None,
            run_attempt=payload.get("source", {}).get("run_attempt") if isinstance(payload.get("source"), dict) else None,
            ref=payload.get("source", {}).get("ref") if isinstance(payload.get("source"), dict) else None,
            source_sha=payload.get("source", {}).get("source_sha") if isinstance(payload.get("source"), dict) else None,
        )
        try:
            expected = create_record(create_args)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            failures.append(f"cannot replay post-publication verification: {exc}")
        else:
            for field in ("publication_manifest", "asset_set_sha256", "assets"):
                if payload.get(field) != expected.get(field):
                    failures.append(f"{field} does not match replayed published byte set")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated post-publication verification: {args.input}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--version", required=True)
    create.add_argument("--release-dir", type=Path, required=True)
    create.add_argument("--attestation-json-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--identity")
    create.add_argument("--issuer")
    create.add_argument("--repository")
    create.add_argument("--workflow")
    create.add_argument("--run-id")
    create.add_argument("--run-attempt")
    create.add_argument("--ref")
    create.add_argument("--source-sha")
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--expected-version")
    validate.add_argument("--release-dir", type=Path)
    validate.add_argument("--attestation-json-dir", type=Path)
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
