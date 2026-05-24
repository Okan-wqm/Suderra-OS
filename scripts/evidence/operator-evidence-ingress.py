#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Stage and validate operator release evidence ingress bundles."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "suderra.operator-evidence-ingress.v1"
AUDIT_SCHEMA_VERSION = "suderra.audit-log-snapshot.v1"
STATION_REGISTRY_SCHEMA_VERSION = "suderra.lab-station-registry.v1"
QEMU_SCHEMA_VERSION = "suderra.qemu-acceptance.v4"
LAB_SCHEMA_VERSION = "suderra.lab-evidence.v3"
APPROVAL_SCHEMA_VERSION = "suderra.release-approval.v2"
REPRODUCIBILITY_SCHEMA_VERSION = "suderra.reproducibility.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$")
ALLOWED_INPUT_DIRS = (
    "release-lab-input",
    "release-approvals",
    "release-reproducibility",
    "release-governance",
)
FORBIDDEN_INPUT_DIRS = (
    "build-artifacts",
    "release-inputs",
    "release-security",
    "release-evidence-generated",
    "signed-release",
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_version_source(failures: list[str], version: str, source_sha: str) -> None:
    if not SEMVER_RE.fullmatch(version):
        failures.append("version must be a SemVer tag such as v0.1.0-rc.1")
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("source_sha must be a lowercase git commit sha")


def check_positive_int(failures: list[str], path: str, value: Any) -> None:
    try:
        if int(str(value)) <= 0:
            raise ValueError
    except (TypeError, ValueError):
        failures.append(f"{path}: must be a positive integer")


def check_sha256(failures: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        failures.append(f"{path}: must be a lowercase sha256 digest")
    elif value == "0" * 64:
        failures.append(f"{path}: must not be the all-zero sha256 digest")


def safe_rel_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    return rel


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


def release_rows(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in matrix.get("defconfigs", []) if row.get("release")]


def release_targets_requiring_hardware(matrix: dict[str, Any]) -> set[str]:
    targets: set[str] = set()
    for row in release_rows(matrix):
        target = str(row.get("target", ""))
        acceptance = str(row.get("acceptance", ""))
        if row.get("production_required") or "hardware" in acceptance:
            targets.add(target)
    return targets


def required_evidence_paths(version: str, matrix_path: Path) -> set[str]:
    matrix = load_matrix(matrix_path)
    required: set[str] = {
        f"release-governance/{version}/audit-log.json",
        f"release-governance/{version}/station-registry.json",
    }
    hardware_targets = release_targets_requiring_hardware(matrix)
    for row in release_rows(matrix):
        target = str(row["target"])
        if row.get("qemu_test"):
            required.add(f"release-lab-input/{version}/{target}/qemu.json")
        if target in hardware_targets:
            required.add(f"release-lab-input/{version}/{target}/lab.json")
        required.add(f"release-approvals/{version}/{target}.json")
        required.add(f"release-reproducibility/{version}/{target}.json")
    return required


def role_for_path(rel: Path) -> str:
    parts = rel.parts
    if len(parts) >= 3 and parts[0] == "release-governance" and rel.name == "audit-log.json":
        return "governance-audit-log"
    if len(parts) >= 3 and parts[0] == "release-governance" and rel.name == "station-registry.json":
        return "station-registry"
    if parts and parts[0] == "release-governance":
        return "governance-input"
    if parts and parts[0] == "release-approvals":
        return "release-approval"
    if parts and parts[0] == "release-reproducibility":
        return "reproducibility-report"
    if parts and parts[0] == "release-lab-input" and rel.name == "qemu.json":
        return "qemu-input"
    if parts and parts[0] == "release-lab-input" and rel.name == "lab.json":
        return "lab-input"
    if parts and parts[0] == "release-lab-input" and rel.name == "station-bundle.json":
        return "lab-station-bundle"
    if parts and parts[0] == "release-lab-input" and rel.name == "station-bundle.json.sig":
        return "lab-station-signature"
    if parts and parts[0] == "release-lab-input" and rel.name == "station-public.pem":
        return "lab-station-public-key"
    if parts and parts[0] == "release-lab-input":
        return "lab-supporting-evidence"
    return "operator-evidence"


def required_schema_version_for_path(rel: Path) -> str | None:
    if len(rel.parts) >= 3 and rel.parts[0] == "release-governance" and rel.name == "audit-log.json":
        return AUDIT_SCHEMA_VERSION
    if len(rel.parts) >= 3 and rel.parts[0] == "release-governance" and rel.name == "station-registry.json":
        return STATION_REGISTRY_SCHEMA_VERSION
    if rel.parts and rel.parts[0] == "release-lab-input" and rel.name == "qemu.json":
        return QEMU_SCHEMA_VERSION
    if rel.parts and rel.parts[0] == "release-lab-input" and rel.name == "lab.json":
        return LAB_SCHEMA_VERSION
    if rel.parts and rel.parts[0] == "release-approvals":
        return APPROVAL_SCHEMA_VERSION
    if rel.parts and rel.parts[0] == "release-reproducibility":
        return REPRODUCIBILITY_SCHEMA_VERSION
    return None


def validate_allowed_version_path(failures: list[str], rel: Path, version: str) -> None:
    if not rel.parts:
        failures.append("empty evidence path")
        return
    if rel.parts[0] not in ALLOWED_INPUT_DIRS:
        failures.append(f"{rel.as_posix()}: top-level directory is not allowed in operator evidence ingress")
        return
    if len(rel.parts) < 2 or rel.parts[1] != version:
        failures.append(f"{rel.as_posix()}: evidence path must be scoped to {version}")


def scan_evidence_files(input_root: Path, version: str) -> tuple[list[dict[str, Any]], list[str]]:
    failures: list[str] = []
    records: list[dict[str, Any]] = []
    for dirname in ALLOWED_INPUT_DIRS:
        root = input_root / dirname
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            failures.append(f"{dirname}: must be a directory and must not be a symlink")
            continue
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                failures.append(f"{path.relative_to(input_root).as_posix()}: symlinks are not allowed")
                continue
            if not path.is_file():
                continue
            rel = path.relative_to(input_root)
            validate_allowed_version_path(failures, rel, version)
            if path.stat().st_size <= 0:
                failures.append(f"{rel.as_posix()}: evidence file must be non-empty")
                continue
            records.append(
                {
                    "source": "operator-evidence",
                    "role": role_for_path(rel),
                    "path": rel.as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return sorted(records, key=lambda item: item["path"]), failures


def validate_core_files(input_root: Path, version: str, matrix: Path, files: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    paths = {str(item.get("path")) for item in files if isinstance(item, dict)}
    required = required_evidence_paths(version, matrix)
    missing = sorted(required - paths)
    if missing:
        failures.append("operator evidence ingress missing required files: " + ", ".join(missing))

    audit_path = input_root / "release-governance" / version / "audit-log.json"
    try:
        audit = read_json(audit_path)
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{audit_path}: missing or invalid audit log JSON: {exc}")
    else:
        if not isinstance(audit, dict):
            failures.append(f"{audit_path}: audit log must be a JSON object")
        else:
            if audit.get("schema_version") != AUDIT_SCHEMA_VERSION:
                failures.append(f"{audit_path}: schema_version must be {AUDIT_SCHEMA_VERSION}")
            if audit.get("status") != "collected":
                failures.append(f"{audit_path}: status must be collected")
            check_sha256(failures, f"{audit_path}: events_sha256", audit.get("events_sha256"))
            if audit.get("unapproved_governance_changes"):
                failures.append(f"{audit_path}: unapproved governance changes must be false")

    registry_path = input_root / "release-governance" / version / "station-registry.json"
    try:
        registry = read_json(registry_path)
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{registry_path}: missing or invalid station registry JSON: {exc}")
    else:
        if not isinstance(registry, dict):
            failures.append(f"{registry_path}: station registry must be a JSON object")
        elif registry.get("schema_version") != STATION_REGISTRY_SCHEMA_VERSION:
            failures.append(f"{registry_path}: schema_version must be {STATION_REGISTRY_SCHEMA_VERSION}")

    for required_path in sorted(required):
        path = input_root / required_path
        if path.is_file():
            try:
                payload = read_json(path)
            except (OSError, json.JSONDecodeError) as exc:
                failures.append(f"{path}: required evidence must be valid JSON: {exc}")
            else:
                if not isinstance(payload, dict):
                    failures.append(f"{path}: required evidence must be a JSON object")
                else:
                    expected_schema = required_schema_version_for_path(Path(required_path))
                    if expected_schema is not None and payload.get("schema_version") != expected_schema:
                        failures.append(f"{path}: schema_version must be {expected_schema}")
    return failures


def create_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    version = args.version
    source_sha = args.source_sha
    validate_version_source(failures, version, source_sha)
    check_positive_int(failures, "--source-image-build-run-id", args.source_image_build_run_id)
    check_positive_int(failures, "--source-image-build-run-attempt", args.source_image_build_run_attempt)
    files, scan_failures = scan_evidence_files(args.input_root, version)
    failures.extend(scan_failures)
    failures.extend(validate_core_files(args.input_root, version, args.matrix, files))
    generated_at = now_utc()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "source_sha": source_sha,
        "source_image_build_run_id": str(args.source_image_build_run_id),
        "source_image_build_run_attempt": str(args.source_image_build_run_attempt),
        "producer": {
            "provider": "github-actions",
            "repository": args.repository,
            "workflow": args.workflow,
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
            "actor": args.actor,
        },
        "generated_at": format_utc(generated_at),
        "expires_at": format_utc(generated_at + timedelta(days=args.expires_days)),
        "required_paths": sorted(required_evidence_paths(version, args.matrix)),
        "files": files,
    }
    return manifest, failures


def verify_manifest_signature(
    manifest_path: Path,
    certificate_identity: str | None,
    certificate_oidc_issuer: str | None,
) -> list[str]:
    signature = manifest_path.with_name(f"{manifest_path.name}.sig")
    certificate = manifest_path.with_name(f"{manifest_path.name}.cert")
    failures: list[str] = []
    for sidecar in (signature, certificate):
        if not sidecar.is_file() or sidecar.stat().st_size <= 0:
            failures.append(f"{sidecar}: missing evidence ingress signature sidecar")
    if failures:
        return failures
    if not certificate_identity or not certificate_oidc_issuer:
        return ["evidence ingress signature verification requires certificate identity and OIDC issuer"]
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
        failures.append(result.stderr.strip() or result.stdout.strip() or "cosign evidence ingress verification failed")
    return failures


def validate_manifest(args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    try:
        manifest = read_json(args.manifest)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{args.manifest}: cannot read evidence ingress manifest: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{args.manifest}: evidence ingress manifest must be a JSON object"]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"$.schema_version: must be {SCHEMA_VERSION}")
    version = manifest.get("version")
    source_sha = manifest.get("source_sha")
    if isinstance(version, str) and isinstance(source_sha, str):
        validate_version_source(failures, version, source_sha)
    else:
        failures.append("$.version and $.source_sha must be strings")
    if args.expected_version is not None and manifest.get("version") != args.expected_version:
        failures.append(f"$.version: must match {args.expected_version}")
    if args.expected_source_sha is not None and manifest.get("source_sha") != args.expected_source_sha:
        failures.append(f"$.source_sha: must match {args.expected_source_sha}")
    if (
        args.expected_source_image_build_run_id is not None
        and str(manifest.get("source_image_build_run_id")) != str(args.expected_source_image_build_run_id)
    ):
        failures.append("$.source_image_build_run_id: must match expected Image Build run")
    if (
        args.expected_source_image_build_run_attempt is not None
        and str(manifest.get("source_image_build_run_attempt")) != str(args.expected_source_image_build_run_attempt)
    ):
        failures.append("$.source_image_build_run_attempt: must match expected Image Build run attempt")
    check_positive_int(failures, "$.source_image_build_run_id", manifest.get("source_image_build_run_id"))
    check_positive_int(failures, "$.source_image_build_run_attempt", manifest.get("source_image_build_run_attempt"))
    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        failures.append("$.producer: must be an object")
    else:
        for field in ("provider", "repository", "workflow", "run_id", "run_attempt", "actor"):
            if not isinstance(producer.get(field), str) or not producer.get(field):
                failures.append(f"$.producer.{field}: must be a non-empty string")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        failures.append("$.files: must be a non-empty list")
        files = []
    seen_paths: set[str] = set()
    for idx, item in enumerate(files):
        item_path = f"$.files[{idx}]"
        if not isinstance(item, dict):
            failures.append(f"{item_path}: must be an object")
            continue
        if item.get("source") != "operator-evidence":
            failures.append(f"{item_path}.source: must be operator-evidence")
        rel_path = safe_rel_path(item.get("path"))
        if rel_path is None:
            failures.append(f"{item_path}.path: must be relative and must not contain '..'")
            continue
        validate_allowed_version_path(failures, rel_path, str(manifest.get("version", "")))
        rel = rel_path.as_posix()
        if rel in seen_paths:
            failures.append(f"{item_path}.path: must be unique")
        seen_paths.add(rel)
        if item.get("role") != role_for_path(rel_path):
            failures.append(f"{item_path}.role: does not match evidence path role")
        if not isinstance(item.get("bytes"), int) or item.get("bytes", 0) <= 0:
            failures.append(f"{item_path}.bytes: must be a positive integer")
        check_sha256(failures, f"{item_path}.sha256", item.get("sha256"))
        if args.input_root is not None:
            actual = args.input_root / rel_path
            if not actual.is_file() or actual.stat().st_size <= 0:
                failures.append(f"{item_path}.path: referenced evidence file is missing or empty: {rel}")
            else:
                if actual.stat().st_size != item.get("bytes"):
                    failures.append(f"{item_path}.bytes: does not match referenced file")
                if sha256_file(actual) != item.get("sha256"):
                    failures.append(f"{item_path}.sha256: does not match referenced file")

    if isinstance(manifest.get("required_paths"), list):
        expected_required = required_evidence_paths(str(manifest.get("version", "")), args.matrix)
        actual_required = {str(item) for item in manifest["required_paths"] if isinstance(item, str)}
        if actual_required != expected_required:
            failures.append("$.required_paths: must match matrix-derived operator evidence contract")
        missing_required_records = sorted(expected_required - seen_paths)
        if missing_required_records:
            failures.append(
                "operator evidence manifest missing required file records: "
                + ", ".join(missing_required_records)
            )
    else:
        failures.append("$.required_paths: must be a list")

    if args.input_root is not None:
        scanned, scan_failures = scan_evidence_files(args.input_root, str(manifest.get("version", "")))
        failures.extend(scan_failures)
        scanned_paths = {item["path"] for item in scanned}
        missing_from_manifest = sorted(scanned_paths - seen_paths)
        missing_on_disk = sorted(seen_paths - scanned_paths)
        if missing_from_manifest:
            failures.append("operator evidence manifest omits files present in artifact: " + ", ".join(missing_from_manifest))
        if missing_on_disk:
            failures.append("operator evidence manifest lists files missing from artifact: " + ", ".join(missing_on_disk))
        for dirname in FORBIDDEN_INPUT_DIRS:
            forbidden = args.input_root / dirname
            if forbidden.exists() and not getattr(args, "allow_preflight_context", False):
                failures.append(f"{dirname}: must not be supplied through operator evidence ingress")
        final_ingress = args.input_root / "release-ingress" / str(manifest.get("version", "")) / "ingress-manifest.json"
        if final_ingress.exists() and not getattr(args, "allow_preflight_context", False):
            failures.append("release-ingress/<version>/ingress-manifest.json must be produced only by Release Preflight")
        failures.extend(validate_core_files(args.input_root, str(manifest.get("version", "")), args.matrix, list(files)))

    if args.require_signature:
        failures.extend(
            verify_manifest_signature(
                args.manifest,
                args.certificate_identity,
                args.certificate_oidc_issuer,
            )
        )
    return failures


def safe_extract(bundle: Path, destination: Path) -> None:
    try:
        archive = tarfile.open(bundle, mode="r:*")
    except tarfile.TarError as exc:
        raise RuntimeError(f"operator bundle must be a tar archive readable by Python tarfile: {exc}") from exc
    with archive:
        for member in archive.getmembers():
            rel = safe_rel_path(member.name)
            if rel is None:
                raise RuntimeError(f"unsafe bundle member path: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"bundle member links are not allowed: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError(f"bundle member type is not allowed: {member.name}")
        archive.extractall(destination)


def find_payload_root(root: Path) -> Path:
    if any((root / dirname).exists() for dirname in ALLOWED_INPUT_DIRS):
        return root
    children = [child for child in root.iterdir() if child.is_dir()]
    if len(children) == 1 and any((children[0] / dirname).exists() for dirname in ALLOWED_INPUT_DIRS):
        return children[0]
    return root


def copy_allowed_trees(source_root: Path, output_root: Path) -> list[str]:
    failures: list[str] = []
    for dirname in FORBIDDEN_INPUT_DIRS:
        if (source_root / dirname).exists():
            failures.append(f"{dirname}: must not be present in operator evidence bundle")
    for dirname in ALLOWED_INPUT_DIRS:
        source = source_root / dirname
        if not source.exists():
            continue
        if source.is_symlink() or not source.is_dir():
            failures.append(f"{dirname}: must be a directory and must not be a symlink")
            continue
        destination = output_root / dirname
        if destination.exists():
            failures.append(f"{dirname}: output tree already exists; refusing to merge evidence")
            continue
        for path in source.rglob("*"):
            if path.is_symlink():
                failures.append(f"{path.relative_to(source_root).as_posix()}: symlinks are not allowed")
        if failures:
            continue
        shutil.copytree(source, destination, copy_function=shutil.copy2)
    if not any((output_root / dirname).is_dir() for dirname in ALLOWED_INPUT_DIRS):
        failures.append("operator evidence bundle did not contain any allowed evidence trees")
    return failures


def create_command(args: argparse.Namespace) -> int:
    manifest, failures = create_manifest(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote operator evidence ingress manifest: {args.output}")
    return 0


def stage_command(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="suderra-operator-evidence-") as tmp:
        extracted = Path(tmp) / "extracted"
        extracted.mkdir(parents=True)
        try:
            safe_extract(args.bundle, extracted)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        source_root = find_payload_root(extracted)
        failures = copy_allowed_trees(source_root, args.output_root)
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
    create_args = argparse.Namespace(**vars(args))
    create_args.input_root = args.output_root
    create_args.output = args.output_root / "release-ingress" / args.version / "evidence-ingress-manifest.json"
    return create_command(create_args)


def validate_command(args: argparse.Namespace) -> int:
    failures = validate_manifest(args)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated operator evidence ingress manifest: {args.manifest}")
    return 0


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-image-build-run-id", required=True)
    parser.add_argument("--source-image-build-run-attempt", required=True)
    parser.add_argument("--matrix", type=Path, default=ROOT / "ci" / "build-matrix.yml")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--expires-days", type=int, default=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create an evidence ingress manifest from staged trees")
    add_common(create)
    create.add_argument("--input-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)

    stage = subparsers.add_parser("stage", help="safely extract an operator bundle and create a manifest")
    add_common(stage)
    stage.add_argument("--bundle", type=Path, required=True)
    stage.add_argument("--output-root", type=Path, required=True)
    stage.set_defaults(func=stage_command)

    validate = subparsers.add_parser("validate", help="validate an evidence ingress manifest")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--input-root", type=Path)
    validate.add_argument("--matrix", type=Path, default=ROOT / "ci" / "build-matrix.yml")
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-source-sha")
    validate.add_argument("--expected-source-image-build-run-id")
    validate.add_argument("--expected-source-image-build-run-attempt")
    validate.add_argument("--require-signature", action="store_true")
    validate.add_argument("--certificate-identity")
    validate.add_argument("--certificate-oidc-issuer")
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
