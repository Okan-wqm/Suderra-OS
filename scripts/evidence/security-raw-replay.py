#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Replay scanner-native raw security evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


REPORT_SCHEMA_VERSION = "suderra.release-security-report.v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {"", "TO_BE_COLLECTED", "NOT_COLLECTED", "not_collected", "pending", "PENDING"}
HIGH_SEVERITIES = {"HIGH", "CRITICAL"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_placeholder(value: Any) -> bool:
    return not isinstance(value, str) or value.strip() in PLACEHOLDERS


def count_severities(payload: Any, tool: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}

    def add(value: Any) -> None:
        if not isinstance(value, str):
            counts["unknown"] += 1
            return
        normalized = value.upper()
        if normalized == "CRITICAL":
            counts["critical"] += 1
        elif normalized == "HIGH":
            counts["high"] += 1
        elif normalized == "MEDIUM":
            counts["medium"] += 1
        elif normalized == "LOW":
            counts["low"] += 1
        else:
            counts["unknown"] += 1

    if tool == "trivy":
        for result in payload.get("Results", []) if isinstance(payload, dict) else []:
            if not isinstance(result, dict):
                continue
            for vuln in result.get("Vulnerabilities", []) or []:
                if isinstance(vuln, dict):
                    add(vuln.get("Severity"))
            for misconf in result.get("Misconfigurations", []) or []:
                if isinstance(misconf, dict):
                    add(misconf.get("Severity"))
            for secret in result.get("Secrets", []) or []:
                if isinstance(secret, dict):
                    add(secret.get("Severity"))
    elif tool == "grype":
        for match in payload.get("matches", []) if isinstance(payload, dict) else []:
            if not isinstance(match, dict):
                continue
            vuln = match.get("vulnerability")
            add(vuln.get("severity") if isinstance(vuln, dict) else None)
    elif tool == "gitleaks":
        findings = payload if isinstance(payload, list) else payload.get("findings", []) if isinstance(payload, dict) else []
        for finding in findings:
            if isinstance(finding, dict):
                # Gitleaks findings do not carry CVSS severity. Any finding is
                # release blocking and represented as high.
                add("HIGH")
    elif tool in {"cargo-audit", "cargo-deny"}:
        advisories = payload.get("vulnerabilities", {}).get("list", []) if isinstance(payload, dict) else []
        for advisory in advisories:
            if isinstance(advisory, dict):
                cvss = advisory.get("cvss")
                score = cvss.get("score") if isinstance(cvss, dict) else None
                add("HIGH" if isinstance(score, (int, float)) and score >= 7 else "MEDIUM")
    return counts


def validate_report(report_path: Path, *, raw_root: Path | None = None, check_files: bool = False) -> list[str]:
    errors: list[str] = []
    try:
        report = read_json(report_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{report_path}: cannot read security report: {exc}"]
    if not isinstance(report, dict):
        return [f"{report_path}: security report must be a JSON object"]
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        errors.append(f"{report_path}: schema_version must be {REPORT_SCHEMA_VERSION}")
    for field in ("version", "source_sha", "source_run_id", "scan", "tool", "tool_version", "generated_at"):
        if is_placeholder(report.get(field)):
            errors.append(f"{report_path}: {field} must be a non-placeholder string")
    subjects = report.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        errors.append(f"{report_path}: subjects must be a non-empty list")
    else:
        for idx, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                errors.append(f"{report_path}: subjects[{idx}] must be an object")
                continue
            for field in ("name", "role", "path", "sha256", "scan_mode"):
                if field == "sha256":
                    value = subject.get(field)
                    if not isinstance(value, str) or not SHA256_RE.fullmatch(value) or value == "0" * 64:
                        errors.append(f"{report_path}: subjects[{idx}].sha256 must be a non-zero sha256")
                elif is_placeholder(subject.get(field)):
                    errors.append(f"{report_path}: subjects[{idx}].{field} must be non-placeholder")
            if not isinstance(subject.get("bytes"), int) or subject.get("bytes", 0) <= 0:
                errors.append(f"{report_path}: subjects[{idx}].bytes must be positive")
    scanner_db = report.get("scanner_db")
    if not isinstance(scanner_db, dict):
        errors.append(f"{report_path}: scanner_db must be an object")
    else:
        for field in ("type", "version", "created_at", "digest"):
            if is_placeholder(scanner_db.get(field)):
                errors.append(f"{report_path}: scanner_db.{field} must be non-placeholder")
        if scanner_db.get("auto_update_disabled") is not True:
            errors.append(f"{report_path}: scanner_db.auto_update_disabled must be true")
    raw = report.get("raw")
    if not isinstance(raw, dict):
        errors.append(f"{report_path}: raw must be an object")
        return errors
    raw_path_value = raw.get("path")
    raw_sha = raw.get("sha256")
    raw_bytes = raw.get("bytes")
    if is_placeholder(raw_path_value):
        errors.append(f"{report_path}: raw.path must be non-placeholder")
        return errors
    raw_rel = Path(str(raw_path_value))
    if raw_rel.is_absolute() or ".." in raw_rel.parts:
        errors.append(f"{report_path}: raw.path must be relative and confined")
        return errors
    if not isinstance(raw_sha, str) or not SHA256_RE.fullmatch(raw_sha) or raw_sha == "0" * 64:
        errors.append(f"{report_path}: raw.sha256 must be a non-zero sha256")
    if not isinstance(raw_bytes, int) or raw_bytes <= 0:
        errors.append(f"{report_path}: raw.bytes must be positive")
    if not check_files:
        return errors
    raw_base = raw_root if raw_root is not None else report_path.parent.parent
    raw_path = raw_base / raw_rel
    if not raw_path.is_file() and isinstance(raw_sha, str):
        raw_dir = report_path.parent / "raw"
        if raw_dir.is_dir():
            matches = [
                candidate
                for candidate in raw_dir.iterdir()
                if candidate.is_file() and candidate.name.startswith(f"{raw_sha}-")
            ]
            if len(matches) == 1:
                raw_path = matches[0]
    if not raw_path.is_file():
        errors.append(f"{report_path}: raw evidence missing: {raw_path}")
        return errors
    if raw_path.stat().st_size != raw_bytes:
        errors.append(f"{report_path}: raw evidence byte size mismatch")
    if sha256_file(raw_path) != raw_sha:
        errors.append(f"{report_path}: raw evidence sha256 mismatch")
    try:
        raw_payload = read_json(raw_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{report_path}: raw scanner evidence must be JSON: {exc}")
        return errors
    tool = str(report.get("tool", report.get("scan", ""))).lower()
    recomputed = count_severities(raw_payload, tool)
    reported = report.get("severity_counts")
    if not isinstance(reported, dict):
        errors.append(f"{report_path}: severity_counts must be an object")
        return errors
    for severity, value in recomputed.items():
        if reported.get(severity, 0) != value:
            errors.append(f"{report_path}: severity_counts.{severity} must replay from raw evidence")
    if recomputed["critical"] > 0 or recomputed["high"] > 0:
        errors.append(f"{report_path}: raw scanner evidence contains high/critical findings")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--check-files", action="store_true")
    args = parser.parse_args()
    errors = validate_report(args.report, raw_root=args.raw_root, check_files=args.check_files)
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated scanner raw replay: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
