#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate release tag binding metadata before publishing release bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = "suderra.release-tag-binding.v1"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = {
    "version": "Suderra-Version",
    "source_sha": "Suderra-Source-SHA",
    "source_build_run_id": "Suderra-Source-Build-Run-ID",
    "source_build_run_attempt": "Suderra-Source-Build-Run-Attempt",
    "preflight_run_id": "Suderra-Preflight-Run-ID",
    "preflight_run_attempt": "Suderra-Preflight-Run-Attempt",
    "preflight_artifact_id": "Suderra-Preflight-Artifact-ID",
    "ingress_manifest_sha256": "Suderra-Ingress-Manifest-SHA256",
}


def git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def git_raw(args: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


def fail(message: str) -> None:
    raise SystemExit(message)


def parse_annotation(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    binding_markers = 0
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "Suderra-Release-Binding":
            binding_markers += 1
            if value != "v1":
                fail("Suderra-Release-Binding must be v1")
            continue
        for field, annotation_key in REQUIRED_FIELDS.items():
            if key == annotation_key:
                if field in values:
                    fail(f"duplicate tag binding field: {annotation_key}")
                values[field] = value
    if binding_markers != 1:
        fail("annotated release tag must include exactly one Suderra-Release-Binding: v1 line")
    missing = sorted(annotation_key for field, annotation_key in REQUIRED_FIELDS.items() if field not in values)
    if missing:
        fail("annotated release tag is missing binding fields: " + ", ".join(missing))
    return values


def check_positive_int(name: str, value: str) -> None:
    try:
        if int(value) <= 0:
            raise ValueError
    except ValueError:
        fail(f"{name} must be a positive integer")


def normalize_fingerprints(value: str | None) -> set[str]:
    if value is None:
        return set()
    raw = re.split(r"[\s,]+", value.strip())
    return {item.upper() for item in raw if item}


def verify_tag_signature(version: str, trusted_fingerprints: set[str]) -> str:
    if not trusted_fingerprints:
        fail("trusted release tag signing fingerprint policy is required")
    code, stdout, stderr = git_raw(["verify-tag", "--raw", f"refs/tags/{version}"])
    if code != 0:
        fail((stderr or stdout).strip() or f"git verify-tag failed for {version}")
    raw = stdout + "\n" + stderr
    valid_fingerprints: list[str] = []
    for line in raw.splitlines():
        marker = "[GNUPG:] VALIDSIG "
        if marker not in line:
            continue
        fields = line.split(marker, 1)[1].split()
        if fields:
            valid_fingerprints.append(fields[0].upper())
    if not valid_fingerprints:
        fail("release tag signature did not report a VALIDSIG fingerprint")
    for fingerprint in valid_fingerprints:
        if fingerprint in trusted_fingerprints:
            return fingerprint
    fail(
        "release tag signer fingerprint is not trusted: "
        + ", ".join(valid_fingerprints)
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_outputs(binding: dict[str, str], output_json: Path | None) -> None:
    payload = {"schema_version": SCHEMA_VERSION, **binding}
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    github_output = Path(str(Path.cwd() / "__missing_github_output__"))
    import os

    if os.environ.get("GITHUB_OUTPUT"):
        github_output = Path(os.environ["GITHUB_OUTPUT"])
        with github_output.open("a", encoding="utf-8") as handle:
            for key, value in binding.items():
                handle.write(f"{key}={value}\n")


def parse_command(args: argparse.Namespace) -> int:
    ref = f"refs/tags/{args.version}"
    try:
        object_type = git(["cat-file", "-t", ref])
    except RuntimeError as exc:
        fail(str(exc))
    if object_type != "tag":
        fail(f"release tag {args.version} must be an annotated tag object, got {object_type}")
    tag_object = git(["cat-file", "tag", ref])
    if "\ngpgsig " not in tag_object and not tag_object.startswith("gpgsig "):
        fail(f"release tag {args.version} must include an embedded GPG signature")
    trusted = normalize_fingerprints(args.trusted_fingerprints)
    if args.trusted_fingerprints_file is not None:
        trusted.update(normalize_fingerprints(args.trusted_fingerprints_file.read_text(encoding="utf-8")))
    signer_fingerprint = verify_tag_signature(args.version, trusted)
    annotation = Path(args.annotation).read_text(encoding="utf-8")
    binding = parse_annotation(annotation)
    if binding["version"] != args.version:
        fail(f"Suderra-Version {binding['version']} does not match tag {args.version}")
    if binding["source_sha"] != args.source_sha:
        fail("Suderra-Source-SHA does not match resolved tag commit")
    if not SOURCE_SHA_RE.fullmatch(binding["source_sha"]):
        fail("Suderra-Source-SHA must be a lowercase git commit sha")
    if not SHA256_RE.fullmatch(binding["ingress_manifest_sha256"]):
        fail("Suderra-Ingress-Manifest-SHA256 must be a lowercase sha256")
    for field in (
        "source_build_run_id",
        "source_build_run_attempt",
        "preflight_run_id",
        "preflight_run_attempt",
        "preflight_artifact_id",
    ):
        check_positive_int(field, binding[field])
    binding["tag_signer_fingerprint"] = signer_fingerprint
    write_outputs(binding, args.output_json)
    return 0


def validate_run_command(args: argparse.Namespace) -> int:
    binding = load_json(args.binding)
    if not isinstance(binding, dict) or binding.get("schema_version") != SCHEMA_VERSION:
        fail(f"invalid tag binding JSON: {args.binding}")
    run = load_json(args.run_json)
    if not isinstance(run, dict):
        fail(f"invalid preflight run JSON: {args.run_json}")
    expected = {
        "id": int(binding["preflight_run_id"]),
        "run_attempt": int(binding["preflight_run_attempt"]),
        "head_sha": binding["source_sha"],
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
    }
    for key, value in expected.items():
        if run.get(key) != value:
            fail(f"preflight run {key} must be {value!r}, got {run.get(key)!r}")
    if run.get("name") != "Release Preflight":
        fail(f"preflight run must be named Release Preflight, got {run.get('name')!r}")
    if run.get("event") != "workflow_dispatch":
        fail(f"preflight run event must be workflow_dispatch, got {run.get('event')!r}")
    if run.get("path") != ".github/workflows/release-preflight.yml":
        fail(f"preflight run path must be .github/workflows/release-preflight.yml, got {run.get('path')!r}")
    repo = run.get("head_repository")
    if not isinstance(repo, dict) or repo.get("full_name") != args.repository:
        fail("preflight run must come from the same repository")

    artifacts = load_json(args.artifacts_json)
    items = artifacts.get("artifacts") if isinstance(artifacts, dict) else None
    if not isinstance(items, list):
        fail(f"invalid preflight artifacts JSON: {args.artifacts_json}")
    preflight_profile = "release-candidate" if "-" in binding["version"] else "production-candidate"
    expected_name = f"release-preflight-{preflight_profile}-{binding['version']}-{binding['source_sha']}"
    matches = [item for item in items if isinstance(item, dict) and item.get("name") == expected_name]
    if len(matches) != 1:
        fail(f"expected exactly one preflight artifact named {expected_name}, got {len(matches)}")
    artifact = matches[0]
    if int(artifact.get("id", 0)) != int(binding["preflight_artifact_id"]):
        fail("preflight artifact ID does not match tag binding")
    if artifact.get("expired") is True:
        fail("preflight artifact is expired")
    if not isinstance(artifact.get("size_in_bytes"), int) or artifact["size_in_bytes"] <= 0:
        fail("preflight artifact must have a positive size")
    if args.output_artifact_name:
        args.output_artifact_name.write_text(expected_name + "\n", encoding="utf-8")
    return 0


def validate_ingress_command(args: argparse.Namespace) -> int:
    binding = load_json(args.binding)
    if not isinstance(binding, dict) or binding.get("schema_version") != SCHEMA_VERSION:
        fail(f"invalid tag binding JSON: {args.binding}")
    import hashlib

    digest = hashlib.sha256(args.ingress_manifest.read_bytes()).hexdigest()
    if digest != binding["ingress_manifest_sha256"]:
        fail(
            "downloaded ingress manifest sha256 does not match tag binding: "
            f"expected {binding['ingress_manifest_sha256']}, got {digest}"
        )
    return 0


def validate_cross_binding_command(args: argparse.Namespace) -> int:
    binding = load_json(args.binding)
    if not isinstance(binding, dict) or binding.get("schema_version") != SCHEMA_VERSION:
        fail(f"invalid tag binding JSON: {args.binding}")
    release_input = load_json(args.release_input)
    ingress = load_json(args.ingress_manifest)
    if not isinstance(release_input, dict):
        fail(f"invalid release input binding JSON: {args.release_input}")
    if not isinstance(ingress, dict):
        fail(f"invalid ingress manifest JSON: {args.ingress_manifest}")
    field_pairs = {
        "version": "version",
        "source_sha": "source_sha",
        "source_build_run_id": "source_run_id",
        "source_build_run_attempt": "source_run_attempt",
    }
    failures: list[str] = []
    for tag_field, release_field in field_pairs.items():
        expected = str(binding.get(tag_field))
        if str(release_input.get(release_field)) != expected:
            failures.append(f"release input {release_field} must match tag {tag_field}")
        if str(ingress.get(release_field)) != expected:
            failures.append(f"ingress {release_field} must match tag {tag_field}")
    profile = "release-candidate" if "-" in str(binding.get("version", "")) else "production-candidate"
    if release_input.get("profile") != profile:
        failures.append(f"release input profile must be {profile}")
    if ingress.get("profile") != profile:
        failures.append(f"ingress profile must be {profile}")
    for field in (
        "build_workflow_name",
        "matrix_sha256",
        "buildroot_source_identity_schema_version",
        "buildroot_index_sha",
        "buildroot_upstream_ref",
        "buildroot_source_mode",
        "buildroot_patchset_sha256",
        "buildroot_patch_files",
        "buildroot_effective_source_id",
        "buildroot_applied_diff_sha256",
        "buildroot_expected_patched",
        "buildroot_rust_version",
        "buildroot_rust_bin_version",
        "buildroot_expected_diff_sha256",
        "buildroot_staged_diff_sha256",
        "buildroot_worktree_diff_sha256",
    ):
        if field in release_input or field in ingress:
            if release_input.get(field) != ingress.get(field):
                failures.append(f"ingress {field} must match release input binding")
    digest = hashlib.sha256(args.ingress_manifest.read_bytes()).hexdigest()
    if digest != binding.get("ingress_manifest_sha256"):
        failures.append("ingress manifest sha256 must match tag binding")
    if failures:
        fail("; ".join(failures))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse = subparsers.add_parser("parse")
    parse.add_argument("--version", required=True)
    parse.add_argument("--source-sha", required=True)
    parse.add_argument("--annotation", type=Path, required=True)
    parse.add_argument("--output-json", type=Path)
    parse.add_argument("--trusted-fingerprints")
    parse.add_argument("--trusted-fingerprints-file", type=Path)

    run = subparsers.add_parser("validate-run")
    run.add_argument("--binding", type=Path, required=True)
    run.add_argument("--run-json", type=Path, required=True)
    run.add_argument("--artifacts-json", type=Path, required=True)
    run.add_argument("--repository", required=True)
    run.add_argument("--output-artifact-name", type=Path)

    ingress = subparsers.add_parser("validate-ingress")
    ingress.add_argument("--binding", type=Path, required=True)
    ingress.add_argument("--ingress-manifest", type=Path, required=True)

    cross = subparsers.add_parser("validate-cross-binding")
    cross.add_argument("--binding", type=Path, required=True)
    cross.add_argument("--release-input", type=Path, required=True)
    cross.add_argument("--ingress-manifest", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "parse":
        return parse_command(args)
    if args.command == "validate-run":
        return validate_run_command(args)
    if args.command == "validate-ingress":
        return validate_ingress_command(args)
    if args.command == "validate-cross-binding":
        return validate_cross_binding_command(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
