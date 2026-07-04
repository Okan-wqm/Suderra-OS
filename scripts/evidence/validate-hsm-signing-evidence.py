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
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402

EVIDENCE_CONTRACT = evidence_contract.load_contract()
SCHEMA_VERSION = evidence_contract.schema_version("hsm_signing_session", EVIDENCE_CONTRACT)

# Approved production HSM provider/model allowlist (SSOT: evidence-contract.yml
# signing.replay_requirements). Rejecting SoftHSM is necessary but not
# sufficient — production signing must run on a vetted hardware token, so under
# --require-production the provider/token identity must match this allowlist.
_SIGNING_REPLAY = EVIDENCE_CONTRACT.get("signing", {}).get("replay_requirements", {})
APPROVED_PROVIDER_ALLOWLIST = tuple(
    str(entry).lower() for entry in _SIGNING_REPLAY.get("approved_provider_allowlist", [])
)
APPROVED_PROVIDER_ALLOWLIST_ENFORCED = bool(
    _SIGNING_REPLAY.get("approved_provider_allowlist_enforced", False)
)
LEGACY_SCHEMA_VERSIONS = {"suderra.hsm-signing-session.v1"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PKCS11_KEY_URI_RE = re.compile(r"^pkcs11:.*(?:object|id)=")
PLACEHOLDERS = {"", "not_collected", "NOT_COLLECTED", "TO_BE_COLLECTED", "pending", "PENDING"}
SOFTHSM_MARKERS = (
    "softhsm",
    "soft-hsm",
    "software hsm",
    "software token",
    "file-backed",
    "file backed",
    "filehsm",
)


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


def safe_relative_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    return rel


def resolve_ref(base: Path, value: Any) -> Path | None:
    rel = safe_relative_path(value)
    if rel is None:
        return None
    return base / rel


def require_digest_bound_file(
    failures: list[str],
    *,
    base: Path,
    field_path: str,
    value: Any,
    expected_sha256: Any,
    expected_bytes: Any | None = None,
) -> Path | None:
    path = resolve_ref(base, value)
    if path is None:
        failures.append(f"{field_path} must be a safe relative path")
        return None
    if not path.is_file() or path.stat().st_size <= 0:
        failures.append(f"{field_path} is missing or empty: {path}")
        return path
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256) or expected_sha256 == "0" * 64:
        failures.append(f"{field_path}_sha256 must be a non-zero sha256")
    elif sha256_file(path) != expected_sha256:
        failures.append(f"{field_path}_sha256 must match referenced file")
    if expected_bytes is not None:
        if not isinstance(expected_bytes, int) or expected_bytes <= 0:
            failures.append(f"{field_path}_bytes must be positive")
        elif path.stat().st_size != expected_bytes:
            failures.append(f"{field_path}_bytes must match referenced file")
    return path


def extract_certificate_public_key(certificate: Path) -> tuple[Path | None, str | None]:
    with tempfile.NamedTemporaryFile(prefix="suderra-hsm-cert-pubkey-", suffix=".pem", delete=False) as handle:
        pubkey = Path(handle.name)
    result = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        pubkey.unlink(missing_ok=True)
        return None, result.stderr.decode("utf-8", errors="replace").strip() or "cannot extract certificate public key"
    pubkey.write_bytes(result.stdout)
    return pubkey, None


def verify_signature(public_key: Path, data: Path, signature: Path, algorithm: str) -> str | None:
    lowered = algorithm.lower()
    if "ed25519" in lowered or "raw" in lowered:
        command = [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key),
            "-sigfile",
            str(signature),
            "-in",
            str(data),
        ]
    else:
        command = [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(data),
        ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or "signature verification failed"
    return None


def validate_crypto_replay(
    payload: dict[str, Any],
    *,
    evidence_path: Path,
    certificate: Path,
    failures: list[str],
) -> None:
    base = evidence_path.parent
    pubkey, error = extract_certificate_public_key(certificate)
    if pubkey is None:
        failures.append(f"certificate public key replay failed: {error}")
        return
    try:
        challenge = payload.get("challenge")
        if not isinstance(challenge, dict):
            return
        request = require_digest_bound_file(
            failures,
            base=base,
            field_path="challenge.request_path",
            value=challenge.get("request_path"),
            expected_sha256=challenge.get("request_sha256"),
        )
        signature = require_digest_bound_file(
            failures,
            base=base,
            field_path="challenge.signature_path",
            value=challenge.get("signature_path"),
            expected_sha256=challenge.get("signature_sha256"),
        )
        transcript = require_digest_bound_file(
            failures,
            base=base,
            field_path="challenge.transcript_path",
            value=challenge.get("transcript_path"),
            expected_sha256=challenge.get("transcript_sha256"),
        )
        algorithm = str(challenge.get("algorithm", "openssl-dgst-sha256"))
        if request is not None and signature is not None and request.is_file() and signature.is_file():
            verify_error = verify_signature(pubkey, request, signature, algorithm)
            if verify_error is not None:
                failures.append(f"challenge signature replay failed: {verify_error}")
        if transcript is not None and transcript.is_file() and isinstance(challenge.get("transcript_sha256"), str):
            audit = payload.get("audit") if isinstance(payload.get("audit"), dict) else {}
            if audit.get("transcript_sha256") != challenge.get("transcript_sha256"):
                failures.append("audit.transcript_sha256 must match challenge transcript replay")
        artifacts = payload.get("artifacts")
        if isinstance(artifacts, list):
            for idx, artifact in enumerate(artifacts):
                if not isinstance(artifact, dict):
                    continue
                artifact_path = require_digest_bound_file(
                    failures,
                    base=base,
                    field_path=f"artifacts[{idx}].path",
                    value=artifact.get("path"),
                    expected_sha256=artifact.get("sha256"),
                    expected_bytes=artifact.get("bytes"),
                )
                signature_path = require_digest_bound_file(
                    failures,
                    base=base,
                    field_path=f"artifacts[{idx}].signature_path",
                    value=artifact.get("signature_path"),
                    expected_sha256=artifact.get("signature_sha256") or artifact.get("artifact_signature_sha256"),
                )
                artifact_algorithm = str(artifact.get("signature_algorithm", algorithm))
                if (
                    artifact_path is not None
                    and signature_path is not None
                    and artifact_path.is_file()
                    and signature_path.is_file()
                ):
                    verify_error = verify_signature(pubkey, artifact_path, signature_path, artifact_algorithm)
                    if verify_error is not None:
                        failures.append(f"artifacts[{idx}] signature replay failed: {verify_error}")
    finally:
        pubkey.unlink(missing_ok=True)


def validate(
    payload: dict[str, Any],
    *,
    evidence_path: Path,
    pkcs11_uri: str,
    certificate: Path,
    require_production: bool,
    replay_crypto: bool = False,
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
        "signed_at",
        "expires_at",
    ):
        if is_placeholder(payload.get(field)):
            failures.append(f"{field} must be non-placeholder")
    for field in ("started_at", "signed_at", "expires_at"):
        if parse_utc(payload.get(field)) is None:
            failures.append(f"{field} must be an ISO-8601 UTC timestamp")
    started = parse_utc(payload.get("started_at"))
    signed = parse_utc(payload.get("signed_at"))
    expires = parse_utc(payload.get("expires_at"))
    if started is not None and signed is not None and signed < started:
        failures.append("signed_at must be at or after started_at")
    if signed is not None and expires is not None and signed > expires:
        failures.append("signed_at must be at or before expires_at")
    if require_production and signed is None:
        failures.append("production HSM evidence must preserve signed_at for historical replay")
    if payload.get("hardware_backed") is not True:
        failures.append("hardware_backed must be true")
    provider = str(payload.get("provider", "")).lower()
    if require_production and any(marker in provider for marker in SOFTHSM_MARKERS):
        failures.append("production HSM evidence must not use SoftHSM or software tokens")
    # Approved provider/model allowlist (positive control on top of the SoftHSM
    # negative control): the provider or token manufacturer/model must name a
    # vetted production HSM. Composed here so it works for both schema versions.
    if require_production and APPROVED_PROVIDER_ALLOWLIST_ENFORCED and APPROVED_PROVIDER_ALLOWLIST:
        token_obj = payload.get("token") if isinstance(payload.get("token"), dict) else {}
        identity = " ".join(
            str(value) for value in (
                provider,
                token_obj.get("manufacturer", ""),
                token_obj.get("model", ""),
                token_obj.get("label", ""),
            )
        ).lower()
        if not any(approved in identity for approved in APPROVED_PROVIDER_ALLOWLIST):
            failures.append(
                "production HSM provider/model is not in the approved allowlist "
                "(evidence-contract.yml signing.replay_requirements.approved_provider_allowlist)"
            )
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
            if require_production:
                for field in ("request_path", "signature_path", "transcript_path"):
                    if safe_relative_path(challenge.get(field)) is None:
                        failures.append(f"challenge.{field} must be a safe relative path for production replay")
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
                if require_production:
                    for field in ("path", "signature_path"):
                        if safe_relative_path(artifact.get(field)) is None:
                            failures.append(f"artifacts[{idx}].{field} must be a safe relative path for production replay")
                    sig_sha = artifact.get("signature_sha256") or artifact.get("artifact_signature_sha256")
                    if not isinstance(sig_sha, str) or not SHA256_RE.fullmatch(sig_sha) or sig_sha == "0" * 64:
                        failures.append(f"artifacts[{idx}].signature_sha256 must be a non-zero sha256")
            if artifact_role is not None and not matching_role:
                failures.append(f"artifacts must include requested role {artifact_role}")
            if artifact_sha256 is not None and not matching_sha:
                failures.append("artifacts must include requested artifact sha256")
            if artifact_role is not None and artifact_sha256 is not None and not matching_artifact:
                failures.append("artifacts must bind requested role to requested artifact sha256 in the same record")
    if (require_production or replay_crypto) and not failures:
        validate_crypto_replay(payload, evidence_path=evidence_path, certificate=certificate, failures=failures)
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
        evidence_path=args.evidence,
        pkcs11_uri=args.pkcs11_uri,
        certificate=args.certificate,
        require_production=args.require_production,
        replay_crypto=args.replay_crypto,
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
    validate_parser.add_argument("--replay-crypto", action="store_true")
    validate_parser.add_argument("--artifact-role")
    validate_parser.add_argument("--artifact-sha256")
    validate_parser.set_defaults(func=validate_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
