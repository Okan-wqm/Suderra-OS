#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Classify Buildroot build warnings for CI evidence.

Buildroot builds compile a large amount of third-party code, so treating every
upstream compiler warning as a Suderra defect creates noisy and brittle gates.
This checker is intentionally fail-closed for Suderra-owned paths while still
counting and surfacing third-party warnings in the build evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
import re
import sys
from pathlib import Path


WARNING_RE = re.compile(r"\b(?:warning|WARNING):")
BUILD_ENV_FAILURE_RE = re.compile(
    r"(?:^|: )(?:chown|chgrp): invalid (?:user|group):|(?:^|: )install: invalid (?:user|group)"
)
OWNED_PATH_RE = re.compile(
    r"(?:(?:^|/|\\)(?:\.github|board|ci|configs|docs|package|patches|scripts|tests|userspace)(?:/|\\)|(?:^|/|\\)(?:Config\.in|external\.desc|external\.mk)(?::|$))"
)
BUILDROOT_PACKAGE_RE = re.compile(
    r"^>>> (?P<package>\S+)\s+(?:\S+\s+)?(?P<phase>Downloading|Extracting|Patching|Configuring|Building|Installing|Fixing|Finalizing)\b"
)
BUILDROOT_CORE_CONTEXT_RE = re.compile(r"(?:/workspace/buildroot/support/kconfig|build/buildroot-config)")
KNOWN_UPSTREAM_PATTERNS = (
    re.compile(r"(?:^|/|\.\./)(?:c\+\+tools|gcc|libcc1|libcpp|libgcc|libsanitizer|libstdc\+\+-v3)/.+warning:"),
    re.compile(r"(?:^|/|\.\./)gcc/\.\./libgcc/.+warning:"),
    re.compile(r"^gengtype-lex\.cc:.+warning:"),
    re.compile(r"^plural\.y:.+warning:"),
    re.compile(r"^configure: WARNING:"),
    re.compile(r"^config\.status: WARNING:"),
    re.compile(r"^checking for makeinfo\.\.\. configure: WARNING:"),
    re.compile(r"^libtool: install: warning:"),
    re.compile(r"\bWARNING: 'makeinfo' is missing"),
)
LOCATION_RE = re.compile(r"^(?P<location>.*?):\d+(?::\d+)?: (?P<body>warning: .*)$")


@dataclass(frozen=True)
class WarningLine:
    path: str
    line_number: int
    text: str
    category: str
    fingerprint: str
    package: str | None


def is_suderra_package(package: str | None) -> bool:
    if not package:
        return False
    normalized = package.removeprefix("host-")
    return normalized == "suderra" or normalized.startswith("suderra-")


def classify(text: str, package: str | None) -> str:
    if BUILD_ENV_FAILURE_RE.search(text):
        return "owned"
    if OWNED_PATH_RE.search(text):
        return "owned"
    if is_suderra_package(package):
        return "owned"
    if any(pattern.search(text) for pattern in KNOWN_UPSTREAM_PATTERNS):
        return "known-upstream"
    if package:
        return "known-upstream"
    return "third-party"


def fingerprint(text: str) -> str:
    match = LOCATION_RE.match(text)
    if not match:
        return text
    location = re.sub(r"(?:\.\./)+", "", match.group("location"))
    return f"{location}: {match.group('body')}"


def collect(path: Path) -> list[WarningLine]:
    warnings: list[WarningLine] = []
    current_package: str | None = None
    for line_number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        package_match = BUILDROOT_PACKAGE_RE.match(raw)
        if package_match:
            current_package = package_match.group("package")
        elif BUILDROOT_CORE_CONTEXT_RE.search(raw):
            current_package = "buildroot-kconfig"
        if not (WARNING_RE.search(raw) or BUILD_ENV_FAILURE_RE.search(raw)):
            continue
        raw_fingerprint = fingerprint(raw.strip())
        if current_package and not OWNED_PATH_RE.search(raw):
            raw_fingerprint = f"{current_package}: {raw_fingerprint}"
        warnings.append(
            WarningLine(
                path=str(path),
                line_number=line_number,
                text=raw.strip(),
                category=classify(raw, current_package),
                fingerprint=raw_fingerprint,
                package=current_package,
            )
        )
    return warnings


def summarize(warnings: list[WarningLine]) -> dict[str, int]:
    summary = {"owned": 0, "known-upstream": 0, "third-party": 0}
    for warning in warnings:
        summary[warning.category] += 1
    return summary


def evidence(warnings: list[WarningLine]) -> dict[str, object]:
    summary = summarize(warnings)
    fingerprints = Counter(warning.fingerprint for warning in warnings)
    return {
        "summary": summary,
        "unique_fingerprints": len(fingerprints),
        "fingerprints": dict(sorted(fingerprints.items())),
        "warnings": [warning.__dict__ for warning in warnings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path, help="Build log file(s) to inspect")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable warning evidence instead of a text summary",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Write machine-readable warning evidence while keeping the text summary on stdout",
    )
    parser.add_argument(
        "--fail-third-party",
        action="store_true",
        help="Also fail on unclassified third-party warnings",
    )
    args = parser.parse_args()

    all_warnings: list[WarningLine] = []
    missing = [str(path) for path in args.logs if not path.is_file()]
    if missing:
        for path in missing:
            print(f"ERROR: build log not found: {path}", file=sys.stderr)
        return 2

    for path in args.logs:
        all_warnings.extend(collect(path))

    evidence_doc = evidence(all_warnings)
    summary = evidence_doc["summary"]
    failing = [
        warning
        for warning in all_warnings
        if warning.category == "owned" or (args.fail_third_party and warning.category == "third-party")
    ]
    evidence_doc["failing"] = [warning.__dict__ for warning in failing]

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(evidence_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(evidence_doc, indent=2, sort_keys=True))
    else:
        print(
            "build warning summary: "
            f"owned={summary['owned']} "
            f"known-upstream={summary['known-upstream']} "
            f"third-party={summary['third-party']} "
            f"unique={evidence_doc['unique_fingerprints']}"
        )
        for warning in failing[:50]:
            print(f"{warning.path}:{warning.line_number}: {warning.category}: {warning.text}")
        if len(failing) > 50:
            print(f"... {len(failing) - 50} additional failing warning(s) omitted")

    if failing:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
