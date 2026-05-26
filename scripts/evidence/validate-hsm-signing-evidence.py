#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate production HSM/PKCS#11 signing session evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA_VERSION = "suderra.hsm-signing-session.v2"
LEGACY_SCHEMA_VERSIONS = {"suderra.hsm-signing-session.v1"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PKCS11_KEY_URI_RE = re.compile(r"^pkcs11:.*(?:object|id)=")
PLACEHOLDERS = {"", "not_collected", "NOT_COLLECTED", "TO_BE_COLLECTED", "pending", "PENDING"}
SOFTHSM_MARKERS = ("softhsm", "soft-hsm", "software hsm")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_placeholder(value: Any) -> bool:
    return not isinstance(value, str) or value.strip() in PLACEHOLDERS


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def validate(
    payload: dict[str, Any],
    *,
    pkcs11_uri: str,
    certificate: Path,
    require_production: bool,
    artifact_role: str | None = None,
    artifact_sha256: str | None = None,
) -> list[str]:
    failures: list[str] = []
    schema_version = payload.get("schema_version")
    if schema_version not in LEGACY_SCHEMA_VERSIONS | {SCHEMA_VERSION}:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    if require_production and schema_version != SCHEMA_VERSION:
        failures.append(f"production HSM evidence requires {SCHEMA_VERSION}")
    if not PKCS11_KEY_URI_RE.search(pkcs11_uri):
        failures.append("pkcs11_uri must be a pkcs11: key URI containing object= or id=")
    if payload.get("pkcs11_uri") != pkcs11_uri:
        failures.append("pkcs11_uri must match requested signing key URI")
    if not certificate.is_file() or certificate.stat().st_size <= 0:
        failures.append(f"certificate is missing or empty: {certificate}")
    else:
        expected_cert_sha = sha256_file(certificate)
        if payload.get("certificate_sha256") != expected_cert_sha:
            failures.append("certificate_sha256 must match SUDERRA_RAUC_SIGNING_CERT")
    for field in (
        "provider",
        "hsm_serial",
        "key_label",
        "key_id",
        "ceremony_id",
        "operator",
        "issuer",
        "started_at",
        "expires_at",
    ):
        if is_placeholder(payload.get(field)):
            failures.append(f"{field} must be non-placeholder")
    for field in ("started_at", "expires_at"):
        if parse_utc(payload.get(field)) is None:
            failures.append(f"{field} must be an ISO-8601 UTC timestamp")
    expires = parse_utc(payload.get("expires_at"))
    if expires is not None and expires <= datetime.now(timezone.utc):
        failures.append("expires_at must be in the future")
    if payload.get("hardware_backed") is not True:
        failures.append("hardware_backed must be true")
    provider = str(payload.get("provider", "")).lower()
    if require_production and any(marker in provider for marker in SOFTHSM_MARKERS):
        failures.append("production HSM evidence must not use SoftHSM or software tokens")
    if require_production and payload.get("mode") != "production":
        failures.append("mode must be production")
    audit = payload.get("audit")
    if not isinstance(audit, dict):
        failures.append("audit must be an object")
    else:
        for field in ("log_sha256", "transcript_sha256"):
            value = audit.get(field)
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                failures.append(f"audit.{field} must be a non-zero sha256")
    if schema_version == SCHEMA_VERSION:
        token = payload.get("token")
        if not isinstance(token, dict):
            failures.append("token must be an object")
        else:
            for field in ("label", "manufacturer", "model", "serial", "module_sha256"):
                value = token.get(field)
                if field == "module_sha256":
                    if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                        failures.append("token.module_sha256 must be a non-zero sha256")
                elif is_placeholder(value):
                    failures.append(f"token.{field} must be non-placeholder")
            token_provider = " ".join(str(token.get(field, "")) for field in ("label", "manufacturer", "model")).lower()
            if require_production and any(marker in token_provider for marker in SOFTHSM_MARKERS):
                failures.append("production HSM token metadata must not identify SoftHSM")
            if token.get("serial") != payload.get("hsm_serial"):
                failures.append("token.serial must match hsm_serial")
        key = payload.get("key")
        if not isinstance(key, dict):
            failures.append("key must be an object")
        else:
            if key.get("uri") != pkcs11_uri:
                failures.append("key.uri must match requested signing key URI")
            if key.get("id") != payload.get("key_id"):
                failures.append("key.id must match key_id")
            for field in ("label", "id", "type"):
                if is_placeholder(key.get(field)):
                    failures.append(f"key.{field} must be non-placeholder")
            if key.get("extractable") is not False:
                failures.append("key.extractable must be false")
            if key.get("private") is not True:
                failures.append("key.private must be true")
            usages = key.get("usages")
            if not isinstance(usages, list) or "sign" not in usages:
                failures.append("key.usages must include sign")
        challenge = payload.get("challenge")
        if not isinstance(challenge, dict):
            failures.append("challenge must be an object")
        else:
            for field in ("nonce", "request_sha256", "signature_sha256", "transcript_sha256", "algorithm"):
                value = challenge.get(field)
                if field.endswith("sha256"):
                    if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                        failures.append(f"challenge.{field} must be a non-zero sha256")
                elif is_placeholder(value):
                    failures.append(f"challenge.{field} must be non-placeholder")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            failures.append("artifacts must be a non-empty list")
        else:
            matching_role = False
            matching_sha = artifact_sha256 is None
            matching_artifact = artifact_role is None or artifact_sha256 is None
            for idx, artifact in enumerate(artifacts):
                if not isinstance(artifact, dict):
                    failures.append(f"artifacts[{idx}] must be an object")
                    continue
                role = artifact.get("role")
                if artifact_role is not None and role == artifact_role:
                    matching_role = True
                sha = artifact.get("sha256")
                if artifact_role is not None and artifact_sha256 is not None and role == artifact_role and sha == artifact_sha256:
                    matching_artifact = True
                for field in ("role", "name", "sha256"):
                    value = artifact.get(field)
                    if field == "sha256":
                        if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                            failures.append(f"artifacts[{idx}].sha256 must be a non-zero sha256")
                        elif artifact_sha256 is not None and value == artifact_sha256:
                            matching_sha = True
                    elif is_placeholder(value):
                        failures.append(f"artifacts[{idx}].{field} must be non-placeholder")
                if not isinstance(artifact.get("bytes"), int) or artifact.get("bytes", 0) <= 0:
                    failures.append(f"artifacts[{idx}].bytes must be positive")
            if artifact_role is not None and not matching_role:
                failures.append(f"artifacts must include requested role {artifact_role}")
            if artifact_sha256 is not None and not matching_sha:
                failures.append("artifacts must include requested artifact sha256")
            if artifact_role is not None and artifact_sha256 is not None and not matching_artifact:
                failures.append("artifacts must bind requested role to requested artifact sha256 in the same record")
    return failures


def validate_command(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read HSM evidence: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("ERROR: HSM evidence must be a JSON object", file=sys.stderr)
        return 1
    failures = validate(
        payload,
        pkcs11_uri=args.pkcs11_uri,
        certificate=args.certificate,
        require_production=args.require_production,
        artifact_role=args.artifact_role,
        artifact_sha256=args.artifact_sha256,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated HSM signing evidence: {args.evidence}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("evidence", type=Path)
    validate_parser.add_argument("--pkcs11-uri", required=True)
    validate_parser.add_argument("--certificate", type=Path, required=True)
    validate_parser.add_argument("--require-production", action="store_true")
    validate_parser.add_argument("--artifact-role")
    validate_parser.add_argument("--artifact-sha256")
    validate_parser.set_defaults(func=validate_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
