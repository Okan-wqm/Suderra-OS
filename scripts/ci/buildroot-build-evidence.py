#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Collect and validate Buildroot build performance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "suderra.buildroot-build-performance.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_build_time_log(source: Path, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_file():
        shutil.copyfile(source, destination)
        return {
            "present": True,
            "path": str(destination),
            "source_path": str(source),
            "sha256": sha256_file(destination),
            "bytes": destination.stat().st_size,
        }

    message = f"# Buildroot build-time.log missing: {source}\n"
    destination.write_text(message, encoding="utf-8")
    return {
        "present": False,
        "path": str(destination),
        "source_path": str(source),
        "sha256": sha256_file(destination),
        "bytes": destination.stat().st_size,
        "reason": "missing",
    }


def parse_build_time_log(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "status": "missing",
            "total_seconds": 0.0,
            "event_count": 0,
            "completed_step_count": 0,
            "unmatched_start_count": 0,
            "unmatched_end_count": 0,
            "top_packages": [],
            "top_steps": [],
        }

    starts: dict[tuple[str, str], float] = {}
    package_seconds: defaultdict[str, float] = defaultdict(float)
    step_seconds: defaultdict[str, float] = defaultdict(float)
    completed = 0
    unmatched_end = 0
    event_count = 0
    first_ts: float | None = None
    last_ts: float | None = None

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = raw.split(":", 3)
        if len(parts) != 4:
            continue
        try:
            timestamp = float(parts[0])
        except ValueError:
            continue
        state = parts[1].strip()
        step = parts[2].strip()
        package = parts[3].strip()
        if not step or not package:
            continue
        event_count += 1
        first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
        last_ts = timestamp if last_ts is None else max(last_ts, timestamp)
        key = (package, step)
        if state == "start":
            starts[key] = timestamp
        elif state == "end":
            start = starts.pop(key, None)
            if start is None:
                unmatched_end += 1
                continue
            duration = max(0.0, timestamp - start)
            package_seconds[package] += duration
            step_seconds[step] += duration
            completed += 1

    def top(mapping: dict[str, float]) -> list[dict[str, Any]]:
        return [
            {"name": name, "seconds": round(seconds, 3)}
            for name, seconds in sorted(mapping.items(), key=lambda item: (-item[1], item[0]))[:20]
        ]

    total_seconds = 0.0
    if first_ts is not None and last_ts is not None:
        total_seconds = max(0.0, last_ts - first_ts)

    return {
        "status": "collected",
        "total_seconds": round(total_seconds, 3),
        "event_count": event_count,
        "completed_step_count": completed,
        "unmatched_start_count": len(starts),
        "unmatched_end_count": unmatched_end,
        "top_packages": top(package_seconds),
        "top_steps": top(step_seconds),
    }


def directory_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "present": False,
            "path": str(path),
            "file_count": 0,
            "total_bytes": 0,
        }

    file_count = 0
    total_bytes = 0
    for root, _, files in os.walk(path):
        for name in files:
            candidate = Path(root) / name
            try:
                stat = candidate.stat()
            except OSError:
                continue
            file_count += 1
            total_bytes += stat.st_size
    return {
        "present": True,
        "path": str(path),
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def ccache_stats(path: Path) -> dict[str, Any]:
    stats = directory_stats(path)
    ccache = shutil.which("ccache")
    stats["ccache_command_available"] = ccache is not None
    if ccache is None:
        return stats
    env = dict(os.environ)
    env["CCACHE_DIR"] = str(path)
    try:
        raw = subprocess.check_output(
            [ccache, "--show-stats", "--json"],
            env=env,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
        stats["ccache_json"] = json.loads(raw)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        stats["ccache_json_error"] = str(exc)
    return stats


def collect(args: argparse.Namespace) -> None:
    build_time_log = args.build_time_log
    build_time_copy = args.build_time_copy
    copied = copy_build_time_log(build_time_log, build_time_copy)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "defconfig": args.defconfig,
        "generated_at": utc_now(),
        "build_time_log": copied,
        "timing": parse_build_time_log(build_time_log),
        "ccache": ccache_stats(args.ccache_dir),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_payload(path: Path) -> list[str]:
    failures: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid JSON: {exc}"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append("schema_version must be suderra.buildroot-build-performance.v1")
    if not isinstance(payload.get("defconfig"), str) or not payload["defconfig"]:
        failures.append("defconfig must be a non-empty string")
    build_time = payload.get("build_time_log")
    if not isinstance(build_time, dict):
        failures.append("build_time_log must be an object")
    else:
        if not isinstance(build_time.get("present"), bool):
            failures.append("build_time_log.present must be boolean")
        digest = build_time.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            failures.append("build_time_log.sha256 must be a sha256 hex string")
        if not isinstance(build_time.get("bytes"), int) or build_time["bytes"] <= 0:
            failures.append("build_time_log.bytes must be positive")
    timing = payload.get("timing")
    if not isinstance(timing, dict):
        failures.append("timing must be an object")
    elif timing.get("status") not in {"collected", "missing"}:
        failures.append("timing.status must be collected or missing")
    ccache = payload.get("ccache")
    if not isinstance(ccache, dict):
        failures.append("ccache must be an object")
    elif not isinstance(ccache.get("total_bytes"), int) or not isinstance(ccache.get("file_count"), int):
        failures.append("ccache total_bytes and file_count must be integers")
    return failures


def validate(args: argparse.Namespace) -> None:
    failures = validate_payload(args.path)
    if failures:
        raise SystemExit("\n".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--defconfig", required=True)
    collect_parser.add_argument("--build-time-log", type=Path, required=True)
    collect_parser.add_argument("--build-time-copy", type=Path, required=True)
    collect_parser.add_argument("--ccache-dir", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.set_defaults(func=collect)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("path", type=Path)
    validate_parser.set_defaults(func=validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
