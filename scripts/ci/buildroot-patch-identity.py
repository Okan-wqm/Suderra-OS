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
SCHEMA_VERSION = "suderra.buildroot-source-identity.v2"
NATIVE_BUILDROOT_REF = "2025.05.3"
NATIVE_BUILDROOT_COMMIT = "019201c6e007d80c1ab1bf65b98d9902bc767bdd"
NATIVE_RUST_VERSION = "1.86.0"
APPLIED_DIFF_DOMAIN = b"suderra-buildroot-applied-diff-from-patchset-v1\n"
EXTERNAL_DIRTY_EXCLUDES = (
    "buildroot",
    "output",
    "dl",
    ".ccache",
    "build-logs",
)


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


def external_tree_entries(source_sha: str) -> list[dict[str, str]]:
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise RuntimeError(f"source_sha must be a lowercase git commit sha: {source_sha}")
    output = run(["git", "ls-tree", "-r", "-z", "--full-tree", source_sha]).stdout
    entries: list[dict[str, str]] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        meta, raw_path = raw.split(b"\t", 1)
        mode, object_type, object_id = meta.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if path == "buildroot" or path.startswith("buildroot/"):
            continue
        entries.append(
            {
                "mode": mode,
                "type": object_type,
                "object": object_id,
                "path": path,
            }
        )
    return entries


def external_tree_sha256(source_sha: str) -> str:
    return sha256_bytes(
        json.dumps(
            external_tree_entries(source_sha),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def release_source_id(source_sha: str, external_tree_digest: str, buildroot_effective_id: str) -> str:
    return sha256_bytes(
        (
            "suderra-release-source-identity-v1\n"
            f"source:{source_sha}\n"
            f"external-tree:{external_tree_digest}\n"
            f"buildroot-effective:{buildroot_effective_id}\n"
        ).encode("utf-8")
    )


def external_status_lines() -> list[str]:
    args = ["git", "status", "--porcelain", "--untracked-files=all", "--", "."]
    args.extend(f":(exclude){path}" for path in EXTERNAL_DIRTY_EXCLUDES)
    return run(args).stdout.decode("utf-8", errors="replace").splitlines()


def buildroot_upstream_ref(base_sha: str) -> str:
    if base_sha == NATIVE_BUILDROOT_COMMIT:
        return NATIVE_BUILDROOT_REF
    tags = git_stdout(["tag", "--points-at", base_sha], cwd=BUILDROOT_DIR).splitlines()
    if NATIVE_BUILDROOT_REF in tags:
        return NATIVE_BUILDROOT_REF
    return tags[0] if tags else base_sha


def effective_source_id(
    base_sha: str,
    patchset_digest: str,
    diff_identity_sha256: str | None = None,
    *,
    upstream_ref: str = "unknown",
    source_mode: str = "clean-native",
) -> str:
    diff_identity = diff_identity_sha256 or "none"
    return sha256_bytes(
        (
            "buildroot-source-identity-v2\n"
            f"index:{base_sha}\n"
            f"upstream-ref:{upstream_ref}\n"
            f"source-mode:{source_mode}\n"
            f"patchset:{patchset_digest}\n"
            f"diff-identity:{diff_identity}\n"
        ).encode("utf-8")
    )


def is_git_worktree(path: Path) -> bool:
    if not path.is_dir():
        return False
    result = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=path, check=False)
    return result.returncode == 0 and result.stdout.decode("utf-8", errors="replace").strip() == "true"


def current_buildroot_diff_sha256(buildroot_dir: Path = BUILDROOT_DIR) -> str | None:
    if not is_git_worktree(buildroot_dir):
        return None
    diff = run(["git", "diff", "--binary", "--full-index"], cwd=buildroot_dir).stdout
    if not diff:
        return None
    return sha256_bytes(diff)


def buildroot_status_lines(buildroot_dir: Path = BUILDROOT_DIR) -> list[str]:
    if not is_git_worktree(buildroot_dir):
        return []
    return git_stdout(["status", "--porcelain", "--untracked-files=all"], cwd=buildroot_dir).splitlines()


def read_buildroot_var(buildroot_dir: Path, rel_path: str, var_name: str) -> str | None:
    path = buildroot_dir / rel_path
    if not path.is_file():
        return None
    pattern = re.compile(rf"^\s*{re.escape(var_name)}\s*=\s*(\S+)\s*$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1)
    return None


def metadata(source_sha: str, buildroot_dir: Path = BUILDROOT_DIR) -> dict[str, Any]:
    entries = patch_entries()
    base_sha = buildroot_index_sha(source_sha)
    patchset_digest = patchset_sha256(entries)
    upstream_ref = buildroot_upstream_ref(base_sha)
    expected_patched = bool(entries)
    source_mode = "staged-patched-tree" if expected_patched else "clean-native"
    worktree_diff_sha = current_buildroot_diff_sha256(buildroot_dir)
    diff_identity_sha = worktree_diff_sha if expected_patched else None
    buildroot_effective_id = effective_source_id(
        base_sha,
        patchset_digest,
        diff_identity_sha,
        upstream_ref=upstream_ref,
        source_mode=source_mode,
    )
    external_tree_digest = external_tree_sha256(source_sha)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "suderra_source_sha": source_sha,
        "suderra_external_tree_sha256": external_tree_digest,
        "suderra_external_dirty_paths": external_status_lines(),
        "suderra_release_source_id": release_source_id(
            source_sha,
            external_tree_digest,
            buildroot_effective_id,
        ),
        "buildroot_index_sha": base_sha,
        "buildroot_upstream_ref": upstream_ref,
        "buildroot_source_mode": source_mode,
        "buildroot_patchset_sha256": patchset_digest,
        "buildroot_patch_files": entries,
        "buildroot_effective_source_id": buildroot_effective_id,
        "buildroot_expected_patched": expected_patched,
        "buildroot_rust_version": read_buildroot_var(buildroot_dir, "package/rust/rust.mk", "RUST_VERSION"),
        "buildroot_rust_bin_version": read_buildroot_var(
            buildroot_dir,
            "package/rust-bin/rust-bin.mk",
            "RUST_BIN_VERSION",
        ),
    }
    if expected_patched:
        if worktree_diff_sha is not None:
            payload["buildroot_expected_diff_sha256"] = worktree_diff_sha
            payload["buildroot_staged_diff_sha256"] = worktree_diff_sha
            payload["buildroot_applied_diff_sha256"] = worktree_diff_sha
        else:
            payload["buildroot_expected_diff_sha256"] = canonical_applied_diff_sha256(entries)
    elif worktree_diff_sha is not None:
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


def validate_applied(source_sha: str, buildroot_dir: Path = BUILDROOT_DIR) -> list[str]:
    failures: list[str] = []
    if not buildroot_dir.is_dir():
        return [f"Buildroot source not found: {buildroot_dir}"]
    if not is_git_worktree(buildroot_dir):
        return [f"Buildroot source is not a git worktree: {buildroot_dir}"]
    try:
        expected_base = buildroot_index_sha(source_sha)
    except RuntimeError as exc:
        return [str(exc)]
    actual_base = git_text(["rev-parse", "HEAD"], cwd=buildroot_dir)
    if actual_base != expected_base:
        failures.append(f"Buildroot HEAD {actual_base} does not match index {expected_base}")

    expected_files = expected_touched_files()
    status_lines = buildroot_status_lines(buildroot_dir)
    if not expected_files:
        if status_lines:
            failures.append("clean-native Buildroot source must not be dirty")
        return failures
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
        result = run(["git", "apply", "--reverse", "--check", str(patch)], cwd=buildroot_dir, check=False)
        if result.returncode != 0:
            zero_context = run(
                ["git", "apply", "--unidiff-zero", "--reverse", "--check", str(patch)],
                cwd=buildroot_dir,
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
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    index_sha = payload.get("buildroot_index_sha")
    if not isinstance(index_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", index_sha):
        failures.append("buildroot_index_sha must be a lowercase git commit sha")
    effective = payload.get("buildroot_effective_source_id")
    if not isinstance(effective, str) or not re.fullmatch(r"[0-9a-f]{64}", effective):
        failures.append("buildroot_effective_source_id must be a lowercase sha256")
    source_sha = payload.get("suderra_source_sha")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        failures.append("suderra_source_sha must be a lowercase git commit sha")
    external_tree = payload.get("suderra_external_tree_sha256")
    if not isinstance(external_tree, str) or not re.fullmatch(r"[0-9a-f]{64}", external_tree):
        failures.append("suderra_external_tree_sha256 must be a lowercase sha256")
    release_id = payload.get("suderra_release_source_id")
    if not isinstance(release_id, str) or not re.fullmatch(r"[0-9a-f]{64}", release_id):
        failures.append("suderra_release_source_id must be a lowercase sha256")
    dirty_paths = payload.get("suderra_external_dirty_paths")
    if not isinstance(dirty_paths, list):
        failures.append("suderra_external_dirty_paths must be a list")
    else:
        for index, item in enumerate(dirty_paths):
            if not isinstance(item, str) or not item:
                failures.append(f"suderra_external_dirty_paths[{index}] must be a non-empty string")
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
    upstream_ref = payload.get("buildroot_upstream_ref")
    if not isinstance(upstream_ref, str) or not upstream_ref:
        failures.append("buildroot_upstream_ref must be a non-empty string")
    source_mode = payload.get("buildroot_source_mode")
    if source_mode not in {"clean-native", "staged-patched-tree"}:
        failures.append("buildroot_source_mode must be clean-native or staged-patched-tree")
    for field in ("buildroot_rust_version", "buildroot_rust_bin_version"):
        value = payload.get(field)
        if value is not None and value != NATIVE_RUST_VERSION:
            failures.append(f"{field} must be {NATIVE_RUST_VERSION}")
    applied_diff = payload.get("buildroot_applied_diff_sha256")
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
    expected_diff = payload.get("buildroot_expected_diff_sha256")
    staged_diff = payload.get("buildroot_staged_diff_sha256")
    for field, value in (
        ("buildroot_expected_diff_sha256", expected_diff),
        ("buildroot_staged_diff_sha256", staged_diff),
    ):
        if value is not None and not (
            isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{64}", value)
            and value != "0" * 64
        ):
            failures.append(f"{field} must be a non-zero lowercase sha256 when present")
    if source_mode == "clean-native":
        if index_sha != NATIVE_BUILDROOT_COMMIT:
            failures.append(f"clean-native Buildroot source must be {NATIVE_BUILDROOT_REF} ({NATIVE_BUILDROOT_COMMIT})")
        if upstream_ref != NATIVE_BUILDROOT_REF:
            failures.append(f"clean-native Buildroot source must bind upstream ref {NATIVE_BUILDROOT_REF}")
        if payload.get("buildroot_expected_patched") is not False:
            failures.append("clean-native Buildroot source must not be marked patched")
        if files not in ([], None):
            failures.append("clean-native Buildroot source must not list patch files")
        for field in (
            "buildroot_applied_diff_sha256",
            "buildroot_worktree_diff_sha256",
            "buildroot_expected_diff_sha256",
            "buildroot_staged_diff_sha256",
        ):
            if payload.get(field) is not None:
                failures.append(f"clean-native Buildroot source must not include {field}")
    elif source_mode == "staged-patched-tree":
        if payload.get("buildroot_expected_patched") is not True:
            failures.append("staged-patched-tree Buildroot source must be marked patched")
        if not files:
            failures.append("staged-patched-tree Buildroot source must list patch files")
        if not applied_diff:
            failures.append("buildroot_applied_diff_sha256 is required when Buildroot patches are expected")
        if not expected_diff or not staged_diff:
            failures.append("staged-patched-tree Buildroot source must include expected and staged diff digests")
        elif expected_diff != staged_diff:
            failures.append("buildroot_staged_diff_sha256 must match buildroot_expected_diff_sha256")
    if (
        isinstance(index_sha, str)
        and isinstance(digest, str)
        and isinstance(effective, str)
        and isinstance(upstream_ref, str)
        and isinstance(source_mode, str)
        and re.fullmatch(r"[0-9a-f]{40}", index_sha)
        and re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        diff_identity = staged_diff if source_mode == "staged-patched-tree" and isinstance(staged_diff, str) else None
        expected_effective = effective_source_id(
            index_sha,
            digest,
            diff_identity,
            upstream_ref=upstream_ref,
            source_mode=source_mode,
        )
        if effective != expected_effective:
            failures.append("buildroot_effective_source_id must bind index, upstream ref, mode, patchset, and diff identity")
    if (
        isinstance(source_sha, str)
        and SOURCE_SHA_RE.fullmatch(source_sha)
        and isinstance(external_tree, str)
        and re.fullmatch(r"[0-9a-f]{64}", external_tree)
        and isinstance(effective, str)
        and re.fullmatch(r"[0-9a-f]{64}", effective)
        and isinstance(release_id, str)
    ):
        expected_release_id = release_source_id(source_sha, external_tree, effective)
        if release_id != expected_release_id:
            failures.append("suderra_release_source_id must bind source SHA, external tree, and Buildroot effective source")
        result = run(["git", "cat-file", "-e", f"{source_sha}^{{commit}}"], check=False)
        if result.returncode == 0:
            expected_external_tree = external_tree_sha256(source_sha)
            if external_tree != expected_external_tree:
                failures.append("suderra_external_tree_sha256 must match the source SHA git tree excluding buildroot")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    meta = subparsers.add_parser("metadata")
    meta.add_argument("--source-sha", default=git_text(["rev-parse", "HEAD"]))
    meta.add_argument("--buildroot-dir", type=Path, default=BUILDROOT_DIR)

    applied = subparsers.add_parser("validate-applied")
    applied.add_argument("--source-sha", default=git_text(["rev-parse", "HEAD"]))
    applied.add_argument("--buildroot-dir", type=Path, default=BUILDROOT_DIR)

    args = parser.parse_args()
    if args.command == "metadata":
        payload = metadata(args.source_sha, args.buildroot_dir)
        failures = validate_metadata_payload(payload)
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.command == "validate-applied":
        failures = validate_applied(args.source_sha, args.buildroot_dir)
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}", file=sys.stderr)
            return 1
        print("validated Buildroot patch identity")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
