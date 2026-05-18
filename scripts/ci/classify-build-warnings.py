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
from datetime import datetime, timezone
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
    re.compile(r"\bPOSIX Yacc does not support\b"),
    re.compile(r"^configure: WARNING:"),
    re.compile(r"^config\.status: WARNING:"),
    re.compile(r"^checking for makeinfo\.\.\. configure: WARNING:"),
    re.compile(r"^libtool: install: warning:"),
    re.compile(r"^libtool: link: warning:"),
    re.compile(r"\bWARNING: 'makeinfo' is missing"),
)
LOCATION_RE = re.compile(
    r"^(?P<location>.*?):\d+(?:[.-]\d+)*(?::\d+(?:[.-]\d+)*)?: (?P<body>(?:warning|WARNING):.*)$"
)
BUILD_OUTPUT_PATH_RE = re.compile(r"(?:/workspace/|\.\./)?output/[^/\s'`]+/")
AUTOCONF_PREFIXED_LOCATION_RE = re.compile(
    r"^checking .*?\.\.\. (?P<diagnostic>.*?:\d+(?:[.-]\d+)*(?::\d+(?:[.-]\d+)*)?: (?:warning|WARNING):.*)$"
)
STABLE_WARNING_MARKERS = (
    "configure: WARNING:",
    "config.status: WARNING:",
    "libtool: install: warning:",
    "libtool: link: warning:",
    "WARNING: 'makeinfo' is missing",
)
AWK_SCRIPT_WARNING_RE = re.compile(r"^awk: (?P<script>\./[^:]+)(?::\d+(?:[.-]\d+)*)?: warning:(?P<body>.*)$")


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
    stable_text = stable_warning_text(text)
    if BUILD_ENV_FAILURE_RE.search(text):
        return "owned"
    if OWNED_PATH_RE.search(text):
        return "owned"
    if is_suderra_package(package):
        return "owned"
    if any(pattern.search(stable_text) for pattern in KNOWN_UPSTREAM_PATTERNS):
        return "known-upstream"
    if package:
        return "known-upstream"
    return "third-party"


def stable_warning_text(text: str) -> str:
    stripped = normalize_warning_text(text.strip())
    for marker in STABLE_WARNING_MARKERS:
        marker_index = stripped.find(marker)
        if marker_index >= 0:
            return normalize_warning_text(stripped[marker_index:])
    return stripped


def normalize_warning_text(text: str) -> str:
    text = BUILD_OUTPUT_PATH_RE.sub("$OUTPUT_DIR/", text)
    awk_match = AWK_SCRIPT_WARNING_RE.match(text)
    if awk_match:
        text = f"{awk_match.group('script')}: warning:{awk_match.group('body')}"
    return text


def fingerprint(text: str) -> str:
    stable_text = stable_warning_text(text)
    probe_match = AUTOCONF_PREFIXED_LOCATION_RE.match(stable_text)
    if probe_match:
        stable_text = probe_match.group("diagnostic")
    match = LOCATION_RE.match(stable_text)
    if not match:
        return stable_text
    location = normalize_warning_text(re.sub(r"(?:\.\./)+", "", match.group("location")))
    body = match.group("body")
    if body.startswith("warning: POSIX Yacc does not support"):
        return body
    if not location:
        return body
    return f"{location}: {body}"


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


def parse_utc_timestamp(value: object, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{path} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{path} must be an ISO-8601 UTC timestamp") from exc


def policy_failures(policy_path: Path, warnings: list[WarningLine]) -> list[str]:
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"cannot read warning policy {policy_path}: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"warning policy {policy_path} is not valid JSON: {exc}"]

    failures: list[str] = []
    if not isinstance(policy, dict):
        return [f"warning policy {policy_path} root must be an object"]
    if policy.get("schema_version") != "suderra.build-warning-policy.v1":
        failures.append("warning policy schema_version must be suderra.build-warning-policy.v1")

    known_upstream = policy.get("known_upstream")
    if not isinstance(known_upstream, dict):
        failures.append("warning policy known_upstream must be an object")
        known_upstream = {}
    owner = known_upstream.get("owner")
    if not isinstance(owner, str) or not owner.strip():
        failures.append("warning policy known_upstream.owner must be set")
    allowed_fingerprints = known_upstream.get("allowed_fingerprints")
    if not isinstance(allowed_fingerprints, list) or not all(
        isinstance(fingerprint, str) and fingerprint.strip()
        for fingerprint in allowed_fingerprints
    ):
        failures.append("warning policy known_upstream.allowed_fingerprints must be a string list")
        allowed_fingerprints = []
    try:
        expires_at = parse_utc_timestamp(known_upstream.get("expires_at"), "known_upstream.expires_at")
    except ValueError as exc:
        failures.append(str(exc))
        expires_at = None
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        failures.append("warning policy known_upstream.expires_at is expired")

    third_party = policy.get("third_party")
    if not isinstance(third_party, dict):
        failures.append("warning policy third_party must be an object")
        third_party = {}
    if third_party.get("fail") is not True:
        failures.append("warning policy third_party.fail must be true")

    if failures:
        return failures

    summary = summarize(warnings)
    if summary["known-upstream"] and not owner:
        failures.append("known-upstream warnings require a policy owner")
    known_upstream_fingerprints = sorted(
        {warning.fingerprint for warning in warnings if warning.category == "known-upstream"}
    )
    unknown_known_upstream = sorted(set(known_upstream_fingerprints) - set(allowed_fingerprints))
    if unknown_known_upstream:
        failures.append(
            f"{len(unknown_known_upstream)} known-upstream warning fingerprint(s) are not policy-approved"
        )
        failures.extend(
            f"unapproved known-upstream fingerprint: {fingerprint}"
            for fingerprint in unknown_known_upstream[:20]
        )
    if summary["third-party"] and third_party.get("fail") is True:
        failures.append(f"{summary['third-party']} unclassified third-party warning(s) require triage")
    return failures


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
    parser.add_argument(
        "--policy",
        type=Path,
        help="Enforce warning governance policy with owner/expiry and third-party fail-closed behavior",
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
    policy_errors = policy_failures(args.policy, all_warnings) if args.policy else []
    evidence_doc["failing"] = [warning.__dict__ for warning in failing]
    evidence_doc["policy_errors"] = policy_errors

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
        for error in policy_errors:
            print(f"policy: {error}")

    if failing or policy_errors:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
