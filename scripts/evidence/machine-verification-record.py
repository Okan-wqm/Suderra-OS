#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate structured release machine-verification records."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


SCHEMA_VERSION = "suderra.machine-verification.v2"
PLACEHOLDERS = {"", "not_collected", "NOT_COLLECTED", "TO_BE_COLLECTED", "pending", "PENDING"}
SIDE_SUFFIXES = (".sig", ".cert")


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


def release_files(release_dir: Path) -> list[Path]:
    return sorted((path for path in release_dir.iterdir() if path.is_file()), key=lambda item: item.name)


def sha256sum_subjects(release_dir: Path) -> list[dict[str, Any]]:
    sums = release_dir / "SHA256SUMS"
    subjects: list[dict[str, Any]] = []
    for line in sums.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"invalid SHA256SUMS line: {line!r}")
        digest, name = parts
        name = name.lstrip("*")
        path = release_dir / name
        if not path.is_file():
            raise ValueError(f"SHA256SUMS references missing file: {name}")
        actual = sha256_file(path)
        if actual != digest:
            raise ValueError(f"SHA256SUMS digest mismatch for {name}")
        subjects.append({"name": name, "sha256": actual, "bytes": path.stat().st_size})
    if not subjects:
        raise ValueError("SHA256SUMS contains no subjects")
    return subjects


def signed_subjects(release_dir: Path) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for path in release_files(release_dir):
        if path.name.startswith("machine-verification"):
            continue
        if path.name.endswith(SIDE_SUFFIXES):
            continue
        sig = release_dir / f"{path.name}.sig"
        cert = release_dir / f"{path.name}.cert"
        if not sig.is_file() or sig.stat().st_size <= 0:
            raise ValueError(f"missing signature sidecar for {path.name}")
        if not cert.is_file() or cert.stat().st_size <= 0:
            raise ValueError(f"missing certificate sidecar for {path.name}")
        subjects.append(
            {
                "name": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "signature": sig.name,
                "certificate": cert.name,
            }
        )
    if not subjects:
        raise ValueError("no signed release subjects found")
    return subjects


def attested_subjects(release_dir: Path) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for path in release_files(release_dir):
        if path.name.startswith("machine-verification"):
            continue
        if path.name.endswith(SIDE_SUFFIXES):
            continue
        subjects.append({"name": path.name, "sha256": sha256_file(path), "bytes": path.stat().st_size})
    if not subjects:
        raise ValueError("no attested release subjects found")
    return subjects


def subject_identity(subject: dict[str, Any]) -> tuple[str, str]:
    return (str(subject["name"]), str(subject["sha256"]))


def minimal_subjects(subjects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"name": str(subject["name"]), "sha256": str(subject["sha256"])}
        for subject in sorted(subjects, key=subject_identity)
    ]


def subject_set(subjects: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {subject_identity(subject) for subject in subjects}


def decode_dsse_payload(value: str) -> Any | None:
    try:
        raw = base64.b64decode(value, validate=False)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def iter_attestation_statements(value: Any) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            statements.extend(iter_attestation_statements(item))
        return statements
    if not isinstance(value, dict):
        return statements

    if isinstance(value.get("subject"), list) and (
        isinstance(value.get("_type"), str) or isinstance(value.get("predicateType"), str)
    ):
        statements.append(value)

    for key in ("payload", "dssePayload"):
        payload = value.get(key)
        if isinstance(payload, str):
            decoded = decode_dsse_payload(payload)
            if decoded is not None:
                statements.extend(iter_attestation_statements(decoded))

    for key in (
        "statement",
        "attestation",
        "bundle",
        "dsseEnvelope",
        "envelope",
        "verificationResult",
        "verifiedAttestation",
        "verified_attestation",
        "result",
        "results",
        "attestations",
    ):
        if key in value:
            statements.extend(iter_attestation_statements(value[key]))
    return statements


def subjects_from_statement(statement: dict[str, Any]) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    raw_subjects = statement.get("subject")
    if not isinstance(raw_subjects, list):
        return subjects
    for raw in raw_subjects:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        digest = raw.get("digest")
        sha256 = digest.get("sha256") if isinstance(digest, dict) else None
        if isinstance(name, str) and isinstance(sha256, str):
            subjects.append({"name": Path(name).name, "sha256": sha256.lower()})
    return subjects


def load_verified_attestation_subjects(attestation_paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    verified: dict[tuple[str, str], dict[str, Any]] = {}
    materials: list[dict[str, Any]] = []
    for path in sorted(attestation_paths, key=lambda item: item.name):
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"attestation JSON is missing or empty: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid attestation JSON {path}: {exc}") from exc
        path_subjects: list[dict[str, Any]] = []
        for statement in iter_attestation_statements(payload):
            path_subjects.extend(subjects_from_statement(statement))
        if not path_subjects:
            raise ValueError(f"attestation JSON has no DSSE subjects: {path}")
        for subject in path_subjects:
            verified[subject_identity(subject)] = subject
        materials.append(
            {
                "path": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "subjects": minimal_subjects(path_subjects),
            }
        )
    return [verified[key] for key in sorted(verified)], materials


def subjects_for(name: str, release_dir: Path) -> list[dict[str, Any]]:
    if name == "sha256sums":
        return sha256sum_subjects(release_dir)
    if name == "cosign":
        return signed_subjects(release_dir)
    if name == "attestations":
        return attested_subjects(release_dir)
    raise ValueError(f"unsupported machine verification name: {name}")


def create_record(args: argparse.Namespace) -> dict[str, Any]:
    log = args.log
    if not log.is_file() or log.stat().st_size <= 0:
        raise ValueError(f"machine verification log is missing or empty: {log}")
    identity = args.identity or os.environ.get("COSIGN_IDENTITY")
    issuer = args.issuer or "https://token.actions.githubusercontent.com"
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID")
    run_attempt = args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT")
    workflow = args.workflow or os.environ.get("GITHUB_WORKFLOW")
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY")
    ref = args.ref or os.environ.get("GITHUB_REF")
    for field, value in (
        ("identity", identity),
        ("issuer", issuer),
        ("run_id", run_id),
        ("run_attempt", run_attempt),
        ("workflow", workflow),
        ("repository", repository),
        ("ref", ref),
    ):
        if is_placeholder(value):
            raise ValueError(f"{field} must be collected before creating machine verification")
    subjects = subjects_for(args.name, args.release_dir)
    record = {
        "schema_version": SCHEMA_VERSION,
        "name": args.name,
        "status": "passed",
        "generated_at": now_utc(),
        "identity": identity,
        "issuer": issuer,
        "source": {
            "repository": repository,
            "workflow": workflow,
            "run_id": str(run_id),
            "run_attempt": str(run_attempt),
            "ref": ref,
        },
        "log": {
            "path": log.name,
            "sha256": sha256_file(log),
            "bytes": log.stat().st_size,
        },
        "subjects": subjects,
    }
    if args.name == "attestations":
        if args.attestation_json_dir is None:
            raise ValueError("attestations record requires --attestation-json-dir")
        attestation_paths = sorted(args.attestation_json_dir.glob("*.json"))
        if not attestation_paths:
            raise ValueError(f"no attestation JSON files found in {args.attestation_json_dir}")
        verified_subjects, materials = load_verified_attestation_subjects(attestation_paths)
        if subject_set(minimal_subjects(subjects)) != subject_set(verified_subjects):
            expected = sorted(f"{name}@{sha}" for name, sha in subject_set(minimal_subjects(subjects)))
            actual = sorted(f"{name}@{sha}" for name, sha in subject_set(verified_subjects))
            raise ValueError(
                "attestation DSSE subjects do not match release subjects; "
                f"expected={expected} actual={actual}"
            )
        record["verified_subjects"] = minimal_subjects(verified_subjects)
        record["verification_material"] = {
            "kind": "github-artifact-attestation-dsse",
            "files": materials,
        }
    return record


def validate_subjects(value: Any, path: str, failures: list[str], *, require_safe_name: bool = True) -> None:
    if not isinstance(value, list) or not value:
        failures.append(f"{path} must be a non-empty list")
        return
    seen: set[str] = set()
    for idx, subject in enumerate(value):
        subject_path = f"{path}[{idx}]"
        if not isinstance(subject, dict):
            failures.append(f"{subject_path} must be an object")
            continue
        name = subject.get("name")
        if is_placeholder(name) or (require_safe_name and Path(str(name)).name != name):
            failures.append(f"{subject_path}.name must be a safe file name")
            continue
        key = f"{name}@{subject.get('sha256')}"
        if key in seen:
            failures.append(f"{subject_path} is duplicated")
        seen.add(key)
        sha = subject.get("sha256")
        if not isinstance(sha, str) or len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            failures.append(f"{subject_path}.sha256 must be lowercase sha256")
        if "bytes" in subject and (not isinstance(subject.get("bytes"), int) or subject["bytes"] <= 0):
            failures.append(f"{subject_path}.bytes must be positive")


def validate_record(payload: dict[str, Any], *, expected_name: str | None = None) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    if expected_name is not None and payload.get("name") != expected_name:
        failures.append(f"name must be {expected_name}")
    if payload.get("status") != "passed":
        failures.append("status must be passed")
    for field in ("identity", "issuer", "generated_at"):
        if is_placeholder(payload.get(field)):
            failures.append(f"{field} must be non-placeholder")
    source = payload.get("source")
    if not isinstance(source, dict):
        failures.append("source must be an object")
    else:
        for field in ("repository", "workflow", "run_id", "run_attempt", "ref"):
            if is_placeholder(source.get(field)):
                failures.append(f"source.{field} must be non-placeholder")
    log = payload.get("log")
    if not isinstance(log, dict):
        failures.append("log must be an object")
    else:
        for field in ("path", "sha256"):
            if is_placeholder(log.get(field)):
                failures.append(f"log.{field} must be non-placeholder")
        if not isinstance(log.get("bytes"), int) or log["bytes"] <= 0:
            failures.append("log.bytes must be positive")
    subjects = payload.get("subjects")
    validate_subjects(subjects, "subjects", failures)
    if payload.get("name") == "attestations":
        verified_subjects = payload.get("verified_subjects")
        validate_subjects(verified_subjects, "verified_subjects", failures)
        if isinstance(subjects, list) and isinstance(verified_subjects, list):
            if subject_set(minimal_subjects(subjects)) != subject_set(verified_subjects):
                failures.append("verified_subjects must exactly match attested release subjects")
        material = payload.get("verification_material")
        if not isinstance(material, dict):
            failures.append("verification_material must be an object")
        else:
            if material.get("kind") != "github-artifact-attestation-dsse":
                failures.append("verification_material.kind must be github-artifact-attestation-dsse")
            files = material.get("files")
            if not isinstance(files, list) or not files:
                failures.append("verification_material.files must be a non-empty list")
            else:
                for idx, item in enumerate(files):
                    file_path = f"verification_material.files[{idx}]"
                    if not isinstance(item, dict):
                        failures.append(f"{file_path} must be an object")
                        continue
                    for field in ("path", "sha256"):
                        if is_placeholder(item.get(field)):
                            failures.append(f"{file_path}.{field} must be non-placeholder")
                    if not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
                        failures.append(f"{file_path}.bytes must be positive")
                    validate_subjects(item.get("subjects"), f"{file_path}.subjects", failures)
    return failures


def create_command(args: argparse.Namespace) -> int:
    try:
        payload = create_record(args)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


def validate_command(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read machine verification: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("ERROR: top-level JSON value must be an object", file=sys.stderr)
        return 1
    failures = validate_record(payload, expected_name=args.name)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated machine verification: {args.input}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--name", choices=("sha256sums", "cosign", "attestations"), required=True)
    create.add_argument("--release-dir", type=Path, required=True)
    create.add_argument("--log", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--identity")
    create.add_argument("--issuer")
    create.add_argument("--repository")
    create.add_argument("--workflow")
    create.add_argument("--run-id")
    create.add_argument("--run-attempt")
    create.add_argument("--ref")
    create.add_argument("--attestation-json-dir", type=Path)
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--name", choices=("sha256sums", "cosign", "attestations"))
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
