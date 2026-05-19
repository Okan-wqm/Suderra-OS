#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Describe and validate the effective Buildroot source used by Suderra OS."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BUILDROOT_DIR = ROOT / "buildroot"
PATCH_DIR = ROOT / "patches" / "buildroot"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
APPLIED_DIFF_DOMAIN = b"suderra-buildroot-applied-diff-from-patchset-v1\n"


def run(
    args: list[str],
    cwd: Path = ROOT,
    *,
    check: bool = True,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        args,
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        raise RuntimeError(stderr or stdout or f"{' '.join(args)} failed")
    return result


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_text(args: list[str], cwd: Path = ROOT) -> str:
    return run(["git", *args], cwd=cwd).stdout.decode("utf-8", errors="replace").strip()


def git_stdout(args: list[str], cwd: Path = ROOT) -> str:
    return run(["git", *args], cwd=cwd).stdout.decode("utf-8", errors="replace")


def patch_paths() -> list[Path]:
    if not PATCH_DIR.is_dir():
        return []
    return sorted(PATCH_DIR.glob("*.patch"), key=lambda path: path.name)


def patch_entries() -> list[dict[str, Any]]:
    entries = []
    for path in patch_paths():
        rel = path.relative_to(ROOT).as_posix()
        entries.append(
            {
                "path": rel,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def canonical_patchset_payload(entries: list[dict[str, Any]]) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def patchset_sha256(entries: list[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_patchset_payload(entries))


def canonical_applied_diff_sha256(entries: list[dict[str, Any]]) -> str | None:
    if not entries:
        return None
    return sha256_bytes(APPLIED_DIFF_DOMAIN + canonical_patchset_payload(entries))


def buildroot_index_sha(source_sha: str) -> str:
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise RuntimeError(f"source_sha must be a lowercase git commit sha: {source_sha}")
    parts = git_text(["ls-tree", source_sha, "buildroot"]).split()
    if len(parts) < 3 or parts[1] != "commit":
        raise RuntimeError(f"cannot resolve Buildroot submodule for {source_sha}")
    return parts[2]


def effective_source_id(base_sha: str, patchset_digest: str, applied_diff_sha256: str | None = None) -> str:
    applied = applied_diff_sha256 or "none"
    return sha256_bytes(
        f"buildroot:{base_sha}\npatchset:{patchset_digest}\napplied-diff:{applied}\n".encode("utf-8")
    )


def current_buildroot_diff_sha256() -> str | None:
    if not BUILDROOT_DIR.is_dir():
        return None
    diff = run(["git", "diff", "--binary", "--full-index"], cwd=BUILDROOT_DIR).stdout
    if not diff:
        return None
    return sha256_bytes(diff)


def metadata(source_sha: str) -> dict[str, Any]:
    entries = patch_entries()
    base_sha = buildroot_index_sha(source_sha)
    patchset_digest = patchset_sha256(entries)
    applied_diff_sha = canonical_applied_diff_sha256(entries)
    worktree_diff_sha = current_buildroot_diff_sha256()
    payload: dict[str, Any] = {
        "buildroot_index_sha": base_sha,
        "buildroot_patchset_sha256": patchset_digest,
        "buildroot_patch_files": entries,
        "buildroot_effective_source_id": effective_source_id(base_sha, patchset_digest, applied_diff_sha),
        "buildroot_expected_patched": bool(entries),
    }
    if applied_diff_sha is not None:
        payload["buildroot_applied_diff_sha256"] = applied_diff_sha
    if worktree_diff_sha is not None:
        payload["buildroot_worktree_diff_sha256"] = worktree_diff_sha
    return payload


def patch_touched_files(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    touched: set[str] = set()
    for line in text:
        if not line.startswith(("--- ", "+++ ")):
            continue
        value = line[4:].split("\t", 1)[0].strip()
        if value == "/dev/null":
            continue
        if value.startswith(("a/", "b/")):
            value = value[2:]
        if value:
            touched.add(value)
    return touched


def expected_touched_files() -> set[str]:
    touched: set[str] = set()
    for patch in patch_paths():
        touched.update(patch_touched_files(patch))
    return touched


def validate_applied(source_sha: str) -> list[str]:
    failures: list[str] = []
    if not BUILDROOT_DIR.is_dir():
        return [f"Buildroot submodule not found: {BUILDROOT_DIR}"]
    try:
        expected_base = buildroot_index_sha(source_sha)
    except RuntimeError as exc:
        return [str(exc)]
    actual_base = git_text(["rev-parse", "HEAD"], cwd=BUILDROOT_DIR)
    if actual_base != expected_base:
        failures.append(f"Buildroot HEAD {actual_base} does not match index {expected_base}")

    expected_files = expected_touched_files()
    status_lines = git_stdout(["status", "--porcelain", "--untracked-files=all"], cwd=BUILDROOT_DIR).splitlines()
    for line in status_lines:
        status = line[:2]
        rel = line[3:].strip()
        if " -> " in rel:
            rel = rel.split(" -> ", 1)[1]
        if rel not in expected_files:
            failures.append(f"unexpected Buildroot dirty path: {status} {rel}")
        elif status.strip() not in {"M", "A", "D", "R", "C"}:
            failures.append(f"unexpected Buildroot status for patch-managed path: {status} {rel}")

    for patch in reversed(patch_paths()):
        result = run(["git", "apply", "--reverse", "--check", str(patch)], cwd=BUILDROOT_DIR, check=False)
        if result.returncode != 0:
            zero_context = run(
                ["git", "apply", "--unidiff-zero", "--reverse", "--check", str(patch)],
                cwd=BUILDROOT_DIR,
                check=False,
            )
            if zero_context.returncode != 0:
                stderr = zero_context.stderr.decode("utf-8", errors="replace").strip()
                failures.append(f"Buildroot patch is not applied cleanly: {patch.name}: {stderr}")

    if patch_paths() and not status_lines:
        failures.append("Buildroot patch set exists but submodule has no applied patch diff")
    return failures


def validate_metadata_payload(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    index_sha = payload.get("buildroot_index_sha")
    if not isinstance(index_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", index_sha):
        failures.append("buildroot_index_sha must be a lowercase git commit sha")
    effective = payload.get("buildroot_effective_source_id")
    if not isinstance(effective, str) or not re.fullmatch(r"[0-9a-f]{64}", effective):
        failures.append("buildroot_effective_source_id must be a lowercase sha256")
    digest = payload.get("buildroot_patchset_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        failures.append("buildroot_patchset_sha256 must be a lowercase sha256")
    files = payload.get("buildroot_patch_files")
    if not isinstance(files, list):
        failures.append("buildroot_patch_files must be a list")
    else:
        seen: set[str] = set()
        for index, item in enumerate(files):
            if not isinstance(item, dict):
                failures.append(f"buildroot_patch_files[{index}] must be an object")
                continue
            path = item.get("path")
            if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
                failures.append(f"buildroot_patch_files[{index}].path must be relative")
            elif path in seen:
                failures.append(f"duplicate Buildroot patch path: {path}")
            else:
                seen.add(path)
            if not isinstance(item.get("bytes"), int) or item.get("bytes", 0) <= 0:
                failures.append(f"buildroot_patch_files[{index}].bytes must be positive")
            sha = item.get("sha256")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                failures.append(f"buildroot_patch_files[{index}].sha256 must be a lowercase sha256")
    if not isinstance(payload.get("buildroot_expected_patched"), bool):
        failures.append("buildroot_expected_patched must be true or false")
    applied_diff = payload.get("buildroot_applied_diff_sha256")
    if payload.get("buildroot_expected_patched") is True and not applied_diff:
        failures.append("buildroot_applied_diff_sha256 is required when Buildroot patches are expected")
    if applied_diff is not None and not (
        isinstance(applied_diff, str)
        and re.fullmatch(r"[0-9a-f]{64}", applied_diff)
        and applied_diff != "0" * 64
    ):
        failures.append("buildroot_applied_diff_sha256 must be a non-zero lowercase sha256 when present")
    worktree_diff = payload.get("buildroot_worktree_diff_sha256")
    if worktree_diff is not None and not (
        isinstance(worktree_diff, str)
        and re.fullmatch(r"[0-9a-f]{64}", worktree_diff)
        and worktree_diff != "0" * 64
    ):
        failures.append("buildroot_worktree_diff_sha256 must be a non-zero lowercase sha256 when present")
    if (
        isinstance(index_sha, str)
        and isinstance(digest, str)
        and isinstance(effective, str)
        and re.fullmatch(r"[0-9a-f]{40}", index_sha)
        and re.fullmatch(r"[0-9a-f]{64}", digest)
        and (applied_diff is None or isinstance(applied_diff, str))
    ):
        expected_effective = effective_source_id(index_sha, digest, applied_diff if isinstance(applied_diff, str) else None)
        if effective != expected_effective:
            failures.append("buildroot_effective_source_id must bind index, patchset, and applied diff")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    meta = subparsers.add_parser("metadata")
    meta.add_argument("--source-sha", default=git_text(["rev-parse", "HEAD"]))

    applied = subparsers.add_parser("validate-applied")
    applied.add_argument("--source-sha", default=git_text(["rev-parse", "HEAD"]))

    args = parser.parse_args()
    if args.command == "metadata":
        payload = metadata(args.source_sha)
        failures = validate_metadata_payload(payload)
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-applied":
        failures = validate_applied(args.source_sha)
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print("validated Buildroot patch identity")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
