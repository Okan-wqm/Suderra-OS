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


SCHEMA_VERSION = "suderra.hsm-signing-session.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {"", "not_collected", "NOT_COLLECTED", "TO_BE_COLLECTED", "pending", "PENDING"}


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


def validate(payload: dict[str, Any], *, pkcs11_uri: str, certificate: Path, require_production: bool) -> list[str]:
    failures: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
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
    validate_parser.set_defaults(func=validate_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
