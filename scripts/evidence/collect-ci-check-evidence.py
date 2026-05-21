#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Collect release security evidence from GitHub Actions check runs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.release-security-report.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RAW_EVIDENCE_BYTES = 10 * 1024 * 1024

CHECKS_BY_SCAN = {
    "actionlint": ("GitHub Actions Lint",),
    "shellcheck": ("ShellCheck",),
    "yamllint": ("YAML Lint",),
    "markdownlint": ("Markdown Lint",),
    "hadolint": ("Hadolint",),
    "gitleaks": ("Secret Scan (gitleaks)", "Gitleaks (secret scan)"),
    "rust-fmt": ("Format + Clippy + Test",),
    "rust-clippy": ("Format + Clippy + Test",),
    "rust-test": ("Format + Clippy + Test",),
    "cargo-deny": ("Security (audit + deny)",),
    "trivy": ("Trivy (filesystem)", "Trivy (config / Dockerfile)"),
    "grype": ("Grype (filesystem)",),
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_matrix_security_scans(path: Path) -> list[str]:
    scans: list[str] = []
    in_security_scans = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw.startswith(" ") and stripped.endswith(":"):
            in_security_scans = stripped == "security_scans:"
            continue
        if in_security_scans and raw.startswith("  - "):
            scans.append(stripped[2:].strip())
    return scans


def check_sort_key(item: dict[str, Any]) -> tuple[str, str, int]:
    completed = str(item.get("completed_at") or "")
    started = str(item.get("started_at") or "")
    ident = item.get("id")
    return completed, started, ident if isinstance(ident, int) else 0


def check_runs_from_payload(payload: Any) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        candidates = payload.get("check_runs")
        if isinstance(candidates, list):
            runs.extend(item for item in candidates if isinstance(item, dict))
    elif isinstance(payload, list):
        for page in payload:
            if isinstance(page, dict) and isinstance(page.get("check_runs"), list):
                runs.extend(item for item in page["check_runs"] if isinstance(item, dict))
            elif isinstance(page, list):
                runs.extend(item for item in page if isinstance(item, dict))
    return runs


def latest_checks_by_name(check_runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for item in check_runs:
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        current = latest.get(name)
        if current is None or check_sort_key(item) >= check_sort_key(current):
            latest[name] = item
    return latest


def compact_check(item: dict[str, Any]) -> dict[str, Any]:
    app = item.get("app") if isinstance(item.get("app"), dict) else {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "started_at": item.get("started_at"),
        "completed_at": item.get("completed_at"),
        "html_url": item.get("html_url"),
        "details_url": item.get("details_url"),
        "app": app.get("slug"),
    }


def validate_required_checks(
    scan: str,
    required_names: tuple[str, ...],
    latest: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    failures: list[str] = []
    matched: list[dict[str, Any]] = []
    for name in required_names:
        item = latest.get(name)
        if item is None:
            failures.append(f"{scan}: missing GitHub check run {name!r}")
            continue
        matched.append(item)
        if item.get("status") != "completed" or item.get("conclusion") != "success":
            failures.append(
                f"{scan}: check run {name!r} must be completed/success, "
                f"got {item.get('status')!r}/{item.get('conclusion')!r}"
            )
    return matched, failures


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect(args: argparse.Namespace) -> int:
    if not SOURCE_SHA_RE.fullmatch(args.source_sha):
        print("ERROR: --source-sha must be a lowercase 40-character git SHA", file=sys.stderr)
        return 2
    scans = load_matrix_security_scans(args.matrix)
    unknown = [scan for scan in scans if scan not in CHECKS_BY_SCAN]
    if unknown:
        print(f"ERROR: no check-run mapping for security scan(s): {', '.join(unknown)}", file=sys.stderr)
        return 1

    try:
        payload = json.loads(args.checks_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read check-runs JSON: {exc}", file=sys.stderr)
        return 1
    check_runs = check_runs_from_payload(payload)
    latest = latest_checks_by_name(check_runs)
    evidence_sha = sha256_file(args.checks_json)
    evidence_bytes = args.checks_json.stat().st_size
    if evidence_bytes <= 0:
        print(f"ERROR: check-runs JSON is empty: {args.checks_json}", file=sys.stderr)
        return 1
    if evidence_bytes > MAX_RAW_EVIDENCE_BYTES:
        print(
            f"ERROR: check-runs JSON exceeds raw evidence cap "
            f"({evidence_bytes} > {MAX_RAW_EVIDENCE_BYTES} bytes): {args.checks_json}",
            file=sys.stderr,
        )
        return 1
    out_dir = args.output_root / args.version

    failures: list[str] = []
    for scan in scans:
        matched, scan_failures = validate_required_checks(scan, CHECKS_BY_SCAN[scan], latest)
        failures.extend(scan_failures)
        if scan_failures:
            continue
        write_json(
            out_dir / f"{scan}.json",
            {
                "schema_version": SCHEMA_VERSION,
                "version": args.version,
                "source_sha": args.source_sha,
                "source_run_id": str(args.source_run_id),
                "scan": scan,
                "status": "passed",
                "generated_at": now_utc(),
                "tool": "github-actions-check-runs",
                "tool_version": "v1",
                "evidence_type": "github_check_runs",
                "evidence_sha256": evidence_sha,
                "evidence_bytes": evidence_bytes,
                "evidence_path": args.checks_json.relative_to(args.output_root).as_posix()
                if args.checks_json.is_relative_to(args.output_root)
                else args.checks_json.as_posix(),
                "required_checks": list(CHECKS_BY_SCAN[scan]),
                "check_runs": [compact_check(item) for item in matched],
                "severity_counts": {"critical": 0, "high": 0},
            },
        )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"collected {len(scans)} release security report(s) under {out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--checks-json", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("release-security"))
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    return collect(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
