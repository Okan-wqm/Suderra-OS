#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate digest-bound USB installer payload input manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "suderra.payload-inputs.v1"
DEFCONFIG_RE = re.compile(r"^[A-Za-z0-9_+-]+_defconfig$")
ARTIFACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(inputs: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        sorted(inputs, key=lambda item: (item["source_defconfig"], item["artifact"])),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def parse_input(value: str) -> tuple[str, str, Path]:
    parts = value.split(":", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("--input must be DEFCONFIG:ARTIFACT:PATH")
    source_defconfig, artifact, path = parts
    if not DEFCONFIG_RE.fullmatch(source_defconfig):
        raise argparse.ArgumentTypeError(f"unsafe source defconfig: {source_defconfig}")
    if not ARTIFACT_RE.fullmatch(artifact):
        raise argparse.ArgumentTypeError(f"unsafe artifact name: {artifact}")
    return source_defconfig, artifact, Path(path)


def create(args: argparse.Namespace) -> None:
    if not DEFCONFIG_RE.fullmatch(args.defconfig):
        raise SystemExit(f"unsafe defconfig: {args.defconfig}")
    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        raise SystemExit("--source-sha must be a 40-character git commit SHA")
    if not args.inputs:
        raise SystemExit("at least one --input is required")

    inputs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source_defconfig, artifact, path in args.inputs:
        key = (source_defconfig, artifact)
        if key in seen:
            raise SystemExit(f"duplicate payload input: {source_defconfig}:{artifact}")
        seen.add(key)
        if not path.is_file():
            raise SystemExit(f"payload input missing: {path}")
        stat = path.stat()
        if stat.st_size <= 0:
            raise SystemExit(f"payload input is empty: {path}")
        inputs.append(
            {
                "source_defconfig": source_defconfig,
                "source_artifact_name": f"{source_defconfig}-image",
                "artifact": artifact,
                "artifact_path": f"{source_defconfig}-image/{artifact}",
                "sha256": sha256_file(path),
                "bytes": stat.st_size,
            }
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "defconfig": args.defconfig,
        "source_sha": args.source_sha,
        "source_run_id": str(args.run_id),
        "source_run_attempt": str(args.run_attempt),
        "generated_at": utc_now(),
        "inputs": sorted(inputs, key=lambda item: (item["source_defconfig"], item["artifact"])),
    }
    payload["inputs_sha256"] = canonical_digest(payload["inputs"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_payload(path: Path) -> list[str]:
    failures: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid JSON: {exc}"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append("schema_version must be suderra.payload-inputs.v1")
    if not DEFCONFIG_RE.fullmatch(str(payload.get("defconfig", ""))):
        failures.append("defconfig must be a safe Buildroot defconfig name")
    if not SOURCE_SHA_RE.fullmatch(str(payload.get("source_sha", ""))):
        failures.append("source_sha must be a 40-character lowercase git commit SHA")
    if not str(payload.get("source_run_id", "")).isdigit():
        failures.append("source_run_id must be numeric")
    if not str(payload.get("source_run_attempt", "")).isdigit():
        failures.append("source_run_attempt must be numeric")
    inputs = payload.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        failures.append("inputs must be a non-empty list")
        return failures
    seen: set[tuple[str, str]] = set()
    normalized: list[dict[str, Any]] = []
    for idx, item in enumerate(inputs):
        path_prefix = f"inputs[{idx}]"
        if not isinstance(item, dict):
            failures.append(f"{path_prefix} must be an object")
            continue
        source_defconfig = str(item.get("source_defconfig", ""))
        artifact = str(item.get("artifact", ""))
        if not DEFCONFIG_RE.fullmatch(source_defconfig):
            failures.append(f"{path_prefix}.source_defconfig is unsafe")
        if not ARTIFACT_RE.fullmatch(artifact):
            failures.append(f"{path_prefix}.artifact is unsafe")
        key = (source_defconfig, artifact)
        if key in seen:
            failures.append(f"{path_prefix} duplicates {source_defconfig}:{artifact}")
        seen.add(key)
        if item.get("source_artifact_name") != f"{source_defconfig}-image":
            failures.append(f"{path_prefix}.source_artifact_name does not match source_defconfig")
        if item.get("artifact_path") != f"{source_defconfig}-image/{artifact}":
            failures.append(f"{path_prefix}.artifact_path must be source artifact relative path")
        if not SHA256_RE.fullmatch(str(item.get("sha256", ""))):
            failures.append(f"{path_prefix}.sha256 must be lowercase sha256")
        if not isinstance(item.get("bytes"), int) or item["bytes"] <= 0:
            failures.append(f"{path_prefix}.bytes must be a positive integer")
        normalized.append(item)
    if not failures and payload.get("inputs_sha256") != canonical_digest(normalized):
        failures.append("inputs_sha256 does not match canonical inputs")
    return failures


def validate(args: argparse.Namespace) -> None:
    failures = validate_payload(args.path)
    if failures:
        raise SystemExit("\n".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--defconfig", required=True)
    create_parser.add_argument("--source-sha", required=True)
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument("--run-attempt", required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--input", dest="inputs", type=parse_input, action="append", default=[])
    create_parser.set_defaults(func=create)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("path", type=Path)
    validate_parser.set_defaults(func=validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
