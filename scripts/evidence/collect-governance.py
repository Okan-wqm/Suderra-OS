#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Collect live GitHub governance snapshots for release evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


SNAPSHOTS = {
    "repo.json": "repos/{repo}",
    "rulesets.json": "repos/{repo}/rulesets",
    "main-branch-protection.json": "repos/{repo}/branches/main/protection",
    "release-publish-environment.json": "repos/{repo}/environments/release-publish",
    "tag-protection.json": "repos/{repo}/tags/protection",
    "workflow-permissions.json": "repos/{repo}/actions/permissions/workflow",
}


def gh_api(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path, "--header", "Accept: application/vnd.github+json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"gh api failed: {path}")
    return json.loads(result.stdout)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_codeowners(repo_root: Path, output: Path) -> None:
    codeowners = repo_root / ".github" / "CODEOWNERS"
    patterns = []
    owners_by_pattern: dict[str, list[str]] = {}
    for raw in codeowners.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        patterns.append(parts[0])
        owners_by_pattern[parts[0]] = parts[1:]
    payload = {
        "schema_version": "suderra.codeowners-snapshot.v1",
        "path": ".github/CODEOWNERS",
        "patterns": patterns,
        "owners_by_pattern": owners_by_pattern,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect_ruleset_details(repo: str, output: Path) -> None:
    summaries = gh_api(f"repos/{repo}/rulesets")
    items = summaries.get("rulesets") if isinstance(summaries, dict) else summaries
    if not isinstance(items, list):
        output.write_text(json.dumps(summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    detailed = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ruleset_id = item.get("id")
        if ruleset_id is None:
            detailed.append(item)
            continue
        try:
            detail = gh_api(f"repos/{repo}/rulesets/{ruleset_id}")
        except Exception:
            detail = item
        detailed.append(detail)
    output.write_text(json.dumps(detailed, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect_audit(output: Path) -> None:
    audit_path = os.environ.get("SUDERRA_GOVERNANCE_AUDIT_LOG")
    if audit_path:
        source = Path(audit_path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    audit = {
        "schema_version": "suderra.audit-log-snapshot.v1",
        "status": "not_collected",
        "unapproved_governance_changes": False,
    }
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/repository")
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()

    output_root = args.output_root / args.version
    output_root.mkdir(parents=True, exist_ok=True)
    failures = []
    files = []
    for filename, endpoint in SNAPSHOTS.items():
        path = output_root / filename
        try:
            if filename == "rulesets.json":
                collect_ruleset_details(args.repo, path)
                files.append({"name": filename, "sha256": sha256_file(path)})
                continue
            payload = gh_api(endpoint.format(repo=args.repo))
        except Exception as exc:  # pragma: no cover - network/API guard
            failures.append(f"{filename}: {exc}")
            payload = {"error": str(exc)}
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        files.append({"name": filename, "sha256": sha256_file(path)})

    collect_codeowners(args.repo_root, output_root / "codeowners.json")
    files.append({"name": "codeowners.json", "sha256": sha256_file(output_root / "codeowners.json")})
    collect_audit(output_root / "audit-log.json")
    files.append({"name": "audit-log.json", "sha256": sha256_file(output_root / "audit-log.json")})
    manifest = {
        "schema_version": "suderra.github-governance-snapshot-manifest.v1",
        "version": args.version,
        "repository": args.repo,
        "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "files": sorted(files, key=lambda item: item["name"]),
        "failures": failures,
    }
    (output_root / "snapshot-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
