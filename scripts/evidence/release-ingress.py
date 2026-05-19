#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate release ingress manifests.

The ingress manifest records the exact Build workflow artifact bytes that a
release preflight accepted. The tag workflow promotes those bytes instead of
rebuilding images.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = "suderra.release-ingress.v1"
BINDING_SCHEMA_VERSION = "suderra.release-input-binding.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {"TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING", ""}
SCHEMA_ROLES = {
    "binding_manifest": BINDING_SCHEMA_VERSION,
    "approval": "suderra.release-approval.v2",
    "qemu_input": "suderra.qemu-acceptance.v3",
    "lab_input": "suderra.lab-evidence.v3",
    "release_evidence": "suderra.release-evidence.v3",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_utc(value: Any, path: str, failures: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        failures.append(f"{path}: must be an ISO-8601 UTC timestamp ending in Z")
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        failures.append(f"{path}: must be an ISO-8601 UTC timestamp")
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check_string(failures: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip() or value.strip() in PLACEHOLDERS:
        failures.append(f"{path}: must be a non-placeholder string")


def check_sha256(failures: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        failures.append(f"{path}: must be a lowercase sha256 digest")
    elif value == "0" * 64:
        failures.append(f"{path}: must not be the all-zero sha256 digest")


def check_relative_path(failures: list[str], path: str, value: Any) -> Path | None:
    check_string(failures, path, value)
    if not isinstance(value, str):
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        failures.append(f"{path}: must be relative and must not contain '..'")
        return None
    return rel


def role_for_artifact(artifact: str) -> str:
    if artifact.endswith(".log"):
        return "build-log"
    if artifact.endswith(".warnings.json"):
        return "warning-classifier-evidence"
    if artifact.endswith(".img.xz") or artifact.endswith(".img"):
        return "release-image"
    if artifact == "MANIFEST.txt" or artifact.endswith(".manifest.txt"):
        return "checksum"
    if artifact == "manifest.json" or artifact.endswith(".payload-manifest.json"):
        return "payload-manifest"
    if artifact == "manifest.sig" or artifact.endswith(".payload-manifest.sig"):
        return "payload-signature"
    return "build-artifact"


def create_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    binding = read_json(args.binding_manifest)
    if not isinstance(binding, dict):
        return {}, [f"binding manifest must be a JSON object: {args.binding_manifest}"]
    if binding.get("schema_version") != BINDING_SCHEMA_VERSION:
        failures.append(f"binding schema_version must be {BINDING_SCHEMA_VERSION}")
    generated_at = now_utc()
    expires_at = generated_at + timedelta(days=args.expires_days)
    producer = {
        "provider": "github-actions",
        "repository": args.repository,
        "workflow": args.workflow,
        "run_id": str(args.run_id),
        "run_attempt": str(args.run_attempt),
        "actor": args.actor,
    }
    files: list[dict[str, Any]] = []
    artifact_root = args.artifact_root
    for collection, default_source in (
        (binding.get("artifacts", []), "build-artifact"),
        (binding.get("build_evidence", []), "build-evidence"),
        (binding.get("installers", []), "installer-artifact"),
    ):
        if not isinstance(collection, list):
            failures.append(f"binding {default_source} collection must be a list")
            continue
        for idx, artifact in enumerate(collection):
            if not isinstance(artifact, dict):
                failures.append(f"binding {default_source}[{idx}] must be an object")
                continue
            rel = artifact.get("path")
            rel_path = check_relative_path(failures, f"binding {default_source}[{idx}].path", rel)
            if rel_path is None:
                continue
            path = artifact_root / rel_path
            if not path.is_file() or path.stat().st_size <= 0:
                failures.append(f"ingress artifact missing or empty: {rel}")
                continue
            digest = sha256_file(path)
            bound_digest = artifact.get("sha256")
            if digest != bound_digest:
                failures.append(f"ingress artifact sha mismatch for {rel}: binding {bound_digest}, got {digest}")
            files.append(
                {
                    "source": default_source,
                    "role": artifact.get("role") or role_for_artifact(str(artifact.get("artifact", ""))),
                    "defconfig": artifact.get("defconfig") or f"installer-{artifact.get('arch')}",
                    "target": artifact.get("target") or artifact.get("arch"),
                    "artifact": artifact.get("artifact"),
                    "path": rel_path.as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest,
                }
            )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": binding.get("version"),
        "profile": binding.get("profile"),
        "source_sha": binding.get("source_sha"),
        "source_run_id": str(binding.get("source_run_id")),
        "source_run_attempt": str(binding.get("source_run_attempt")),
        "build_workflow_name": binding.get("build_workflow_name"),
        "matrix_sha256": binding.get("matrix_sha256"),
        "buildroot_index_sha": binding.get("buildroot_index_sha"),
        "buildroot_patchset_sha256": binding.get("buildroot_patchset_sha256"),
        "buildroot_patch_files": binding.get("buildroot_patch_files"),
        "buildroot_effective_source_id": binding.get("buildroot_effective_source_id"),
        "buildroot_applied_diff_sha256": binding.get("buildroot_applied_diff_sha256"),
        "buildroot_expected_patched": binding.get("buildroot_expected_patched"),
        "producer": producer,
        "generated_at": format_utc(generated_at),
        "expires_at": format_utc(expires_at),
        "schema_roles": SCHEMA_ROLES,
        "files": sorted(files, key=lambda item: (str(item["defconfig"]), str(item["artifact"]))),
    }
    return manifest, failures


def verify_manifest_signature(
    manifest_path: Path,
    certificate_identity: str | None,
    certificate_oidc_issuer: str | None,
) -> list[str]:
    signature = manifest_path.with_name(f"{manifest_path.name}.sig")
    certificate = manifest_path.with_name(f"{manifest_path.name}.cert")
    failures = []
    for sidecar in (signature, certificate):
        if not sidecar.is_file() or sidecar.stat().st_size <= 0:
            failures.append(f"{sidecar}: missing ingress manifest signature sidecar")
    if failures:
        return failures
    if not certificate_identity or not certificate_oidc_issuer:
        failures.append("ingress signature verification requires certificate identity and OIDC issuer")
        return failures
    result = subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--certificate",
            str(certificate),
            "--certificate-identity",
            certificate_identity,
            "--certificate-oidc-issuer",
            certificate_oidc_issuer,
            "--signature",
            str(signature),
            str(manifest_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        failures.append(result.stderr.strip() or result.stdout.strip() or "cosign ingress signature verification failed")
    return failures


def validate_manifest(
    manifest_path: Path,
    artifact_root: Path | None,
    expected_version: str | None = None,
    expected_source_sha: str | None = None,
    require_signature: bool = False,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> list[str]:
    failures: list[str] = []
    try:
        manifest = read_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{manifest_path}: cannot read ingress manifest: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{manifest_path}: ingress manifest must be a JSON object"]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"$.schema_version: must be {SCHEMA_VERSION}")
    for field in (
        "version",
        "profile",
        "source_sha",
        "source_run_id",
        "source_run_attempt",
        "build_workflow_name",
        "matrix_sha256",
        "buildroot_index_sha",
        "buildroot_patchset_sha256",
        "buildroot_effective_source_id",
    ):
        check_string(failures, f"$.{field}", manifest.get(field))
    if expected_version is not None and manifest.get("version") != expected_version:
        failures.append(f"$.version: must match {expected_version}")
    source_sha = manifest.get("source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("$.source_sha: must be a lowercase git commit sha")
    elif expected_source_sha is not None and source_sha != expected_source_sha:
        failures.append(f"$.source_sha: must match {expected_source_sha}")
    check_sha256(failures, "$.matrix_sha256", manifest.get("matrix_sha256"))
    buildroot_index_sha = manifest.get("buildroot_index_sha")
    if not isinstance(buildroot_index_sha, str) or not SOURCE_SHA_RE.fullmatch(buildroot_index_sha):
        failures.append("$.buildroot_index_sha: must be a lowercase git commit sha")
    check_sha256(failures, "$.buildroot_patchset_sha256", manifest.get("buildroot_patchset_sha256"))
    check_sha256(failures, "$.buildroot_effective_source_id", manifest.get("buildroot_effective_source_id"))
    if manifest.get("buildroot_applied_diff_sha256") is not None:
        check_sha256(failures, "$.buildroot_applied_diff_sha256", manifest.get("buildroot_applied_diff_sha256"))
    if not isinstance(manifest.get("buildroot_expected_patched"), bool):
        failures.append("$.buildroot_expected_patched: must be a boolean")
    patch_files = manifest.get("buildroot_patch_files")
    if not isinstance(patch_files, list):
        failures.append("$.buildroot_patch_files: must be a list")
    else:
        seen_patch_paths: set[str] = set()
        for idx, patch in enumerate(patch_files):
            patch_path = f"$.buildroot_patch_files[{idx}]"
            if not isinstance(patch, dict):
                failures.append(f"{patch_path}: must be an object")
                continue
            rel_path = check_relative_path(failures, f"{patch_path}.path", patch.get("path"))
            if rel_path is not None:
                rel = rel_path.as_posix()
                if rel in seen_patch_paths:
                    failures.append(f"{patch_path}.path: must be unique")
                seen_patch_paths.add(rel)
            check_sha256(failures, f"{patch_path}.sha256", patch.get("sha256"))
            if not isinstance(patch.get("bytes"), int) or patch.get("bytes", 0) <= 0:
                failures.append(f"{patch_path}.bytes: must be a positive integer")
    parse_utc(manifest.get("generated_at"), "$.generated_at", failures)
    expires_at = parse_utc(manifest.get("expires_at"), "$.expires_at", failures)
    if expires_at is not None and expires_at <= now_utc():
        failures.append("$.expires_at: must be in the future")
    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        failures.append("$.producer: must be an object")
    else:
        for field in ("provider", "repository", "workflow", "run_id", "run_attempt", "actor"):
            check_string(failures, f"$.producer.{field}", producer.get(field))
    schema_roles = manifest.get("schema_roles")
    if not isinstance(schema_roles, dict):
        failures.append("$.schema_roles: must be an object")
    else:
        for role, expected in SCHEMA_ROLES.items():
            if schema_roles.get(role) != expected:
                failures.append(f"$.schema_roles.{role}: must be {expected}")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        failures.append("$.files: must be a non-empty list")
        files = []
    seen_paths: set[str] = set()
    for idx, item in enumerate(files):
        path = f"$.files[{idx}]"
        if not isinstance(item, dict):
            failures.append(f"{path}: must be an object")
            continue
        for field in ("role", "defconfig", "target", "artifact"):
            check_string(failures, f"{path}.{field}", item.get(field))
        source = item.get("source")
        if source not in {"build-artifact", "build-evidence", "installer-artifact"}:
            failures.append(f"{path}.source: must be build-artifact, build-evidence, or installer-artifact")
        rel_path = check_relative_path(failures, f"{path}.path", item.get("path"))
        check_sha256(failures, f"{path}.sha256", item.get("sha256"))
        if not isinstance(item.get("bytes"), int) or item.get("bytes", 0) <= 0:
            failures.append(f"{path}.bytes: must be a positive integer")
        if rel_path is not None:
            rel = rel_path.as_posix()
            if rel in seen_paths:
                failures.append(f"{path}.path: must be unique")
            seen_paths.add(rel)
            if artifact_root is not None:
                actual = artifact_root / rel_path
                if not actual.is_file() or actual.stat().st_size <= 0:
                    failures.append(f"{path}.path: referenced artifact is missing or empty: {rel}")
                else:
                    if actual.stat().st_size != item.get("bytes"):
                        failures.append(f"{path}.bytes: does not match artifact file size")
                    if sha256_file(actual) != item.get("sha256"):
                        failures.append(f"{path}.sha256: does not match artifact file sha256")
    if require_signature:
        failures.extend(verify_manifest_signature(manifest_path, certificate_identity, certificate_oidc_issuer))
    return failures


def create_command(args: argparse.Namespace) -> int:
    manifest, failures = create_manifest(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote release ingress manifest: {args.output}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    failures = validate_manifest(
        args.manifest,
        args.artifact_root,
        args.expected_version,
        args.expected_source_sha,
        args.require_signature,
        args.certificate_identity,
        args.certificate_oidc_issuer,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated release ingress manifest: {args.manifest}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create an ingress manifest from a binding and artifacts")
    create.add_argument("--binding-manifest", type=Path, required=True)
    create.add_argument("--artifact-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--workflow", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", required=True)
    create.add_argument("--actor", required=True)
    create.add_argument("--expires-days", type=int, default=30)
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate", help="validate an ingress manifest")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--artifact-root", type=Path)
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-source-sha")
    validate.add_argument("--require-signature", action="store_true")
    validate.add_argument("--certificate-identity")
    validate.add_argument("--certificate-oidc-issuer")
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
