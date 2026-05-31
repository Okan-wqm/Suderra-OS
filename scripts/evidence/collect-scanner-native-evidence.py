#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Create and validate scanner-native v2 release security evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
REPORT_SCHEMA_VERSION = "suderra.release-security-report.v2"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_matrix(path: Path) -> dict[str, Any]:
    script = ROOT / "scripts" / "ci" / "validate-build-matrix.py"
    spec = importlib.util.spec_from_file_location("validate_build_matrix", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = module.load_matrix(path)
    if not isinstance(matrix, dict):
        raise RuntimeError(f"matrix loader returned non-object for {path}")
    return matrix


def load_replay_module() -> Any:
    script = ROOT / "scripts" / "evidence" / "security-raw-replay.py"
    spec = importlib.util.spec_from_file_location("security_raw_replay", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_env_sha256(env: dict[str, Any]) -> str:
    return sha256_bytes(json.dumps(env, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def canonical_replay_sha256(raw_sha256: str, severity_counts: dict[str, int]) -> str:
    payload = {
        "raw_sha256": raw_sha256,
        "severity_counts": severity_counts,
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def subject_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if not SHA256_RE.fullmatch(args.subject_sha256) or args.subject_sha256 == "0" * 64:
        raise ValueError("--subject-sha256 must be a non-zero sha256")
    if args.subject_bytes <= 0:
        raise ValueError("--subject-bytes must be positive")
    subject = {
        "subject_id": args.subject_id,
        "name": args.subject_name,
        "role": args.subject_role,
        "path": args.subject_path,
        "sha256": args.subject_sha256,
        "bytes": args.subject_bytes,
        "scan_mode": args.scan_mode,
    }
    for field, value in subject.items():
        if field != "bytes" and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"--{field.replace('_', '-')} must be non-empty")
    return subject


def create_command(args: argparse.Namespace) -> int:
    try:
        if not SOURCE_SHA_RE.fullmatch(args.source_sha):
            raise ValueError("--source-sha must be a lowercase git commit sha")
        if not args.raw_json.is_file() or args.raw_json.stat().st_size <= 0:
            raise ValueError(f"--raw-json is missing or empty: {args.raw_json}")
        raw_sha = sha256_file(args.raw_json)
        raw_bytes = args.raw_json.stat().st_size
        raw_payload = read_json(args.raw_json)
        replay = load_replay_module()
        severity_counts = replay.count_severities(raw_payload, args.tool.lower())
        env = read_json(args.env_json) if args.env_json is not None else {}
        if not isinstance(env, dict):
            raise ValueError("--env-json must contain a JSON object")
        argv = read_json(args.argv_json) if args.argv_json is not None else args.argv
        if not isinstance(argv, list) or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("scanner argv must be a non-empty string list")
        scanner_binary: dict[str, Any] = {
            "name": args.tool,
            "version": args.tool_version,
            "sha256": args.scanner_binary_sha256,
        }
        if args.scanner_binary is not None:
            if not args.scanner_binary.is_file() or args.scanner_binary.stat().st_size <= 0:
                raise ValueError(f"--scanner-binary missing or empty: {args.scanner_binary}")
            scanner_binary["path"] = args.scanner_binary.as_posix()
            scanner_binary["sha256"] = sha256_file(args.scanner_binary)
            scanner_binary["bytes"] = args.scanner_binary.stat().st_size
        if not SHA256_RE.fullmatch(str(scanner_binary.get("sha256", ""))) or scanner_binary["sha256"] == "0" * 64:
            raise ValueError("--scanner-binary-sha256 must be a non-zero sha256 when --scanner-binary is not provided")
        scanner_db_digest = args.scanner_db_digest
        if scanner_db_digest.startswith("sha256:"):
            scanner_db_sha = scanner_db_digest.removeprefix("sha256:")
        else:
            scanner_db_sha = scanner_db_digest
            scanner_db_digest = f"sha256:{scanner_db_digest}"
        if not SHA256_RE.fullmatch(scanner_db_sha) or scanner_db_sha == "0" * 64:
            raise ValueError("--scanner-db-digest must be sha256:<digest> or a non-zero sha256")
        if not args.subject_graph.is_file() or args.subject_graph.stat().st_size <= 0:
            raise ValueError(f"--subject-graph missing or empty: {args.subject_graph}")
        subject_graph = {
            "path": args.subject_graph.as_posix(),
            "sha256": sha256_file(args.subject_graph),
            "bytes": args.subject_graph.stat().st_size,
        }
        replay_output_sha = canonical_replay_sha256(raw_sha, severity_counts)
        raw_rel = args.raw_path
        if raw_rel is None:
            raw_rel = args.raw_json.as_posix()
            try:
                raw_rel = args.raw_json.relative_to(args.output_root).as_posix()
            except ValueError:
                pass
        payload: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "version": args.version,
            "source_sha": args.source_sha,
            "source_run_id": str(args.source_run_id),
            "source_run_attempt": str(args.source_run_attempt),
            "scan": args.scan,
            "status": "passed",
            "generated_at": now_utc(),
            "tool": args.tool,
            "tool_version": args.tool_version,
            "subject_id": args.subject_id,
            "subject_graph_sha256": subject_graph["sha256"],
            "subject_graph": subject_graph,
            "scanner_binary": scanner_binary,
            "invocation": {
                "argv": argv,
                "env": env,
                "env_sha256": canonical_env_sha256(env),
                "working_dir_policy": args.working_dir_policy,
            },
            "scanner_db": {
                "type": args.scanner_db_type,
                "version": args.scanner_db_version,
                "created_at": args.scanner_db_created_at,
                "digest": scanner_db_digest,
                "archive_sha256": scanner_db_sha,
                "auto_update_disabled": True,
            },
            "subjects": [subject_from_args(args)],
            "raw": {
                "path": raw_rel,
                "sha256": raw_sha,
                "bytes": raw_bytes,
            },
            "severity_counts": severity_counts,
            "replay": {
                "status": "passed",
                "raw_sha256": raw_sha,
                "severity_counts": severity_counts,
                "output_sha256": replay_output_sha,
            },
            "sbom": {
                "path": args.sbom_path,
                "sha256": args.sbom_sha256,
            },
            "vex": {
                "path": args.vex_path,
                "sha256": args.vex_sha256,
            },
        }
        out = args.output or args.output_root / args.version / f"{args.scan}.json"
        write_json(out, payload)
        failures = replay.validate_report(out, raw_root=args.raw_root, check_files=args.check_files)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote scanner-native security report: {out}")
    return 0


def validate_directory_command(args: argparse.Namespace) -> int:
    try:
        matrix = load_matrix(args.matrix)
        replay = load_replay_module()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    failures: list[str] = []
    for scan in matrix.get("security_scans", []):
        report = args.root / args.version / f"{scan}.json"
        if not report.is_file():
            failures.append(f"missing scanner-native v2 report for {scan}: {report}")
            continue
        failures.extend(replay.validate_report(report, raw_root=args.raw_root, check_files=args.check_files))
        payload = read_json(report)
        if isinstance(payload, dict):
            if payload.get("schema_version") != REPORT_SCHEMA_VERSION:
                failures.append(f"{report}: schema_version must be {REPORT_SCHEMA_VERSION}")
            if payload.get("source_sha") != args.source_sha:
                failures.append(f"{report}: source_sha mismatch")
            if str(payload.get("source_run_id")) != str(args.source_run_id):
                failures.append(f"{report}: source_run_id mismatch")
            if payload.get("scan") != scan:
                failures.append(f"{report}: scan mismatch")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"validated scanner-native security reports under {args.root / args.version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--version", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--source-run-id", required=True)
    create.add_argument("--source-run-attempt", default="1")
    create.add_argument("--scan", required=True)
    create.add_argument("--tool", required=True)
    create.add_argument("--tool-version", required=True)
    create.add_argument("--raw-json", type=Path, required=True)
    create.add_argument("--raw-path")
    create.add_argument("--raw-root", type=Path)
    create.add_argument("--scanner-binary", type=Path)
    create.add_argument("--scanner-binary-sha256", default="0" * 64)
    create.add_argument("--scanner-db-type", required=True)
    create.add_argument("--scanner-db-version", required=True)
    create.add_argument("--scanner-db-created-at", required=True)
    create.add_argument("--scanner-db-digest", required=True)
    create.add_argument("--subject-id", required=True)
    create.add_argument("--subject-name", required=True)
    create.add_argument("--subject-role", required=True)
    create.add_argument("--subject-path", required=True)
    create.add_argument("--subject-sha256", required=True)
    create.add_argument("--subject-bytes", type=int, required=True)
    create.add_argument("--scan-mode", required=True)
    create.add_argument("--argv", nargs="+", default=None)
    create.add_argument("--argv-json", type=Path)
    create.add_argument("--env-json", type=Path)
    create.add_argument("--subject-graph", type=Path, required=True)
    create.add_argument("--sbom-path", required=True)
    create.add_argument("--sbom-sha256", required=True)
    create.add_argument("--vex-path", required=True)
    create.add_argument("--vex-sha256", required=True)
    create.add_argument("--working-dir-policy", default="repo-root")
    create.add_argument("--output-root", type=Path, default=Path("release-security"))
    create.add_argument("--output", type=Path)
    create.add_argument("--check-files", action="store_true")
    create.set_defaults(func=create_command)

    validate_directory = subparsers.add_parser("validate-directory")
    validate_directory.add_argument("--version", required=True)
    validate_directory.add_argument("--source-sha", required=True)
    validate_directory.add_argument("--source-run-id", required=True)
    validate_directory.add_argument("--root", type=Path, default=Path("release-security"))
    validate_directory.add_argument("--raw-root", type=Path, default=Path("release-security"))
    validate_directory.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate_directory.add_argument("--check-files", action="store_true")
    validate_directory.set_defaults(func=validate_directory_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
