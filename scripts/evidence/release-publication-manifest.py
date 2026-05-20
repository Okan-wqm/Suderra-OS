#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate the final GitHub Release publication manifest."""

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
SCHEMA_VERSION = "suderra.release-publication-manifest.v1"
MANIFEST_NAME = "release-publication-manifest.json"
SELF_SIDECARS = {
    "release-publication-manifest.json.sig",
    "release-publication-manifest.json.cert",
}
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


def load_release_evidence_module() -> Any:
    script = ROOT / "scripts" / "evidence" / "release-evidence.py"
    spec = importlib.util.spec_from_file_location("release_evidence", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def classify_asset(name: str) -> str:
    return str(load_release_evidence_module().classify_release_asset(name))


def release_files(release_dir: Path) -> list[Path]:
    return sorted((path for path in release_dir.iterdir() if path.is_file()), key=lambda item: item.name)


def file_entry(path: Path) -> dict[str, Any]:
    return {
        "name": path.name,
        "role": classify_asset(path.name),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def create_manifest(args: argparse.Namespace) -> dict[str, Any]:
    release_dir = args.release_dir
    files = [
        file_entry(path)
        for path in release_files(release_dir)
        if path.name != MANIFEST_NAME and path.name not in SELF_SIDECARS
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "version": args.version,
        "generated_at": now_utc(),
        "source": {
            "repository": args.repository or os.environ.get("GITHUB_REPOSITORY", "not_collected"),
            "workflow": args.workflow or os.environ.get("GITHUB_WORKFLOW", "not_collected"),
            "run_id": args.run_id or os.environ.get("GITHUB_RUN_ID", "not_collected"),
            "run_attempt": args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "not_collected"),
        },
        "scope": {
            "directory": str(release_dir),
            "self_included": False,
            "self_sidecars_included": False,
            "self_sidecars": sorted(SELF_SIDECARS),
        },
        "files": files,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest top-level JSON value must be an object")
    return payload


def validate_manifest(
    manifest_path: Path,
    *,
    release_dir: Path,
    expected_version: str | None,
    require_self_sidecars: bool,
    require_asset_sidecars: bool,
) -> list[str]:
    failures: list[str] = []
    try:
        manifest = read_manifest(manifest_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot read publication manifest: {exc}"]
    if manifest.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    if expected_version is not None and manifest.get("version") != expected_version:
        failures.append(f"version must be {expected_version}")
    source = manifest.get("source")
    if not isinstance(source, dict):
        failures.append("source must be an object")
    else:
        for field in ("repository", "workflow", "run_id", "run_attempt"):
            if is_placeholder(source.get(field)):
                failures.append(f"source.{field} must be a non-placeholder string")
    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        failures.append("scope must be an object")
    else:
        if scope.get("self_included") is not False:
            failures.append("scope.self_included must be false")
        if scope.get("self_sidecars_included") is not False:
            failures.append("scope.self_sidecars_included must be false")
        if sorted(scope.get("self_sidecars", [])) != sorted(SELF_SIDECARS):
            failures.append("scope.self_sidecars must list the publication manifest signature sidecars")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        failures.append("files must be a non-empty list")
        return failures
    seen: set[str] = set()
    manifest_names: set[str] = set()
    for index, item in enumerate(files):
        path = f"files[{index}]"
        if not isinstance(item, dict):
            failures.append(f"{path} must be an object")
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or Path(name).name != name:
            failures.append(f"{path}.name must be a safe file name")
            continue
        if name in seen:
            failures.append(f"{path}.name is duplicated: {name}")
        seen.add(name)
        manifest_names.add(name)
        if name == MANIFEST_NAME or name in SELF_SIDECARS:
            failures.append(f"{path}.name must not include manifest self files: {name}")
        file_path = release_dir / name
        if not file_path.is_file():
            failures.append(f"{path}.name references missing file: {name}")
            continue
        if require_asset_sidecars and not name.endswith((".sig", ".cert")):
            for suffix in (".sig", ".cert"):
                sidecar = release_dir / f"{name}{suffix}"
                if not sidecar.is_file() or sidecar.stat().st_size <= 0:
                    failures.append(f"{path}.name missing non-empty sidecar: {name}{suffix}")
        if item.get("role") != classify_asset(name):
            failures.append(f"{path}.role does not match release asset classifier for {name}")
        if item.get("bytes") != file_path.stat().st_size:
            failures.append(f"{path}.bytes does not match {name}")
        if item.get("sha256") != sha256_file(file_path):
            failures.append(f"{path}.sha256 does not match {name}")

    public_names = {
        path.name
        for path in release_files(release_dir)
        if path.name != MANIFEST_NAME and path.name not in SELF_SIDECARS
    }
    missing = sorted(public_names - manifest_names)
    extra = sorted(manifest_names - public_names)
    if missing:
        failures.append("manifest is missing release files: " + ", ".join(missing))
    if extra:
        failures.append("manifest references extra release files: " + ", ".join(extra))
    if require_self_sidecars:
        for sidecar in sorted(SELF_SIDECARS):
            sidecar_path = release_dir / sidecar
            if not sidecar_path.is_file() or sidecar_path.stat().st_size <= 0:
                failures.append(f"missing non-empty publication manifest sidecar: {sidecar}")
    version = str(manifest.get("version", ""))
    required = {
        f"release-evidence-{version}.tar.zst",
        f"release-evidence-{version}.tar.zst.sig",
        f"release-evidence-{version}.tar.zst.cert",
    }
    missing_required = sorted(required - manifest_names)
    if missing_required:
        failures.append("publication manifest missing final evidence bytes: " + ", ".join(missing_required))
    return failures


def create_command(args: argparse.Namespace) -> int:
    write_json(args.output, create_manifest(args))
    print(f"wrote publication manifest: {args.output}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    failures = validate_manifest(
        args.manifest,
        release_dir=args.release_dir,
        expected_version=args.expected_version,
        require_self_sidecars=args.require_self_sidecars,
        require_asset_sidecars=args.require_asset_sidecars,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated publication manifest: {args.manifest}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--version", required=True)
    create.add_argument("--release-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--repository")
    create.add_argument("--workflow")
    create.add_argument("--run-id")
    create.add_argument("--run-attempt")
    create.set_defaults(func=create_command)

    validate = subparsers.add_parser("validate")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--release-dir", type=Path, required=True)
    validate.add_argument("--expected-version")
    validate.add_argument("--require-self-sidecars", action="store_true")
    validate.add_argument("--require-asset-sidecars", action="store_true")
    validate.set_defaults(func=validate_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
