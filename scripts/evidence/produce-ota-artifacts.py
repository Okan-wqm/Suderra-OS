#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Produce target-bound OTA artifact metadata from the evidence SSOT."""

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = evidence_contract.schema_version("ota_artifacts")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_ref(path: Path, *, root: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix(),
        "name": path.name,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def production_mode() -> bool:
    return os.environ.get("SUDERRA_SIGNING_MODE") == "prod" or os.environ.get("SUDERRA_RELEASE_TIER") == "production"


def bundle_name_for(version: str, target: str, policy: dict[str, Any]) -> str:
    for template in policy.get("bundle_artifacts", []):
        if isinstance(template, str) and template.endswith(".raucb"):
            return template.format(version=version, target=target)
    raise ValueError(f"OTA target {target} has no RAUC bundle artifact template")


def run(command: list[str]) -> None:
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed with exit code {result.returncode}")


def apply_subject_plan(args: argparse.Namespace, contract: dict[str, Any]) -> dict[str, Any] | None:
    if args.subject_plan is None:
        if not args.version or not args.target:
            raise ValueError("--version and --target are required when --subject-plan is not provided")
        return None
    plan = read_json(args.subject_plan)
    if not isinstance(plan, dict):
        raise ValueError("subject plan must be a JSON object")
    if plan.get("schema_version") != evidence_contract.schema_version("release_subject_graph", contract):
        raise ValueError("subject plan schema_version must match release subject graph schema")
    plan_target = plan.get("target")
    plan_version = plan.get("version")
    if not isinstance(plan_target, str) or not plan_target:
        raise ValueError("subject plan target is required")
    if not isinstance(plan_version, str) or not plan_version:
        raise ValueError("subject plan version is required")
    if args.target and args.target != plan_target:
        raise ValueError(f"--target {args.target} does not match subject plan target {plan_target}")
    if args.version and args.version != plan_version:
        raise ValueError(f"--version {args.version} does not match subject plan version {plan_version}")
    args.target = plan_target
    args.version = plan_version
    args.source_sha = args.source_sha or plan.get("source_sha")
    args.source_run_id = args.source_run_id or plan.get("source_run_id")
    ota = plan.get("ota")
    if not isinstance(ota, dict) or ota.get("ota_capable") is not True:
        raise ValueError("subject plan must carry an OTA-capable target contract")
    required = plan.get("required_evidence")
    if isinstance(required, dict):
        expected = f"release-ota/{args.version}/{args.target}/ota-artifacts.json"
        if required.get("release-ota") != expected:
            raise ValueError("subject plan release-ota required path does not match target/version")
    return plan


def create_manifest(args: argparse.Namespace, bundle: Path, manifest: Path) -> dict[str, Any] | None:
    signing_key = os.environ.get("SUDERRA_OS_UPDATE_MANIFEST_SIGNING_KEY")
    public_key = os.environ.get("SUDERRA_OS_UPDATE_MANIFEST_PUBLIC_KEY")
    if not signing_key and not public_key:
        if production_mode():
            raise ValueError("production OTA manifest requires HSM-bound OS update manifest signing evidence")
        return None
    if not signing_key or not public_key:
        raise ValueError("SUDERRA_OS_UPDATE_MANIFEST_SIGNING_KEY and SUDERRA_OS_UPDATE_MANIFEST_PUBLIC_KEY must be set together")
    if production_mode() and os.environ.get("SUDERRA_OS_UPDATE_MANIFEST_ALLOW_FILE_KEY") != "1":
        raise ValueError("production OTA manifest signing rejects file-backed Ed25519 keys; provide HSM signing evidence")
    run(
        [
            sys.executable,
            str(ROOT / "scripts" / "create-os-update-manifest.py"),
            "create",
            "--bundle",
            str(bundle),
            "--version",
            args.version,
            "--target",
            args.target,
            "--min-current-version",
            args.min_current_version,
            "--rollback-floor",
            args.rollback_floor,
            "--key-epoch",
            str(args.key_epoch),
            "--key-id",
            args.key_id,
            "--expires-at",
            args.expires_at,
            "--release-notes",
            args.release_notes or "",
            "--signing-key",
            signing_key,
            "--public-key",
            public_key,
            "--output",
            str(manifest),
        ]
    )
    return artifact_ref(manifest, root=args.binaries_dir)


def create_command(args: argparse.Namespace) -> int:
    try:
        contract = evidence_contract.load_contract()
        subject_plan = apply_subject_plan(args, contract)
        policy = evidence_contract.ota_target_policy(args.target, contract)
        target_policy = evidence_contract.target_policy(args.target, contract)
        if not policy or policy.get("ota_capable") is not True or target_policy.get("ota_capable") is not True:
            raise ValueError(f"target {args.target} is not OTA capable in ci/evidence-contract.yml")
        args.binaries_dir.mkdir(parents=True, exist_ok=True)
        bundle = args.binaries_dir / bundle_name_for(args.version, args.target, policy)
        run([str(args.rauc_bundle_tool), "x86", str(args.binaries_dir), args.version, str(bundle)])
        if not bundle.is_file() or bundle.stat().st_size <= 0:
            raise ValueError(f"RAUC bundle was not produced: {bundle}")
        manifest_path = args.binaries_dir / "suderra-os-update-manifest.json"
        manifest_ref = create_manifest(args, bundle, manifest_path)
        subject_id = None
        if args.source_sha and args.source_run_id:
            subject_id = evidence_contract.release_subject_id(
                version=args.version,
                target=args.target,
                source_sha=args.source_sha,
                source_run_id=str(args.source_run_id),
                contract=contract,
            )
        if subject_plan is not None:
            plan_subject_id = subject_plan.get("subject_id")
            if plan_subject_id != subject_id:
                raise ValueError("subject plan subject_id does not match OTA artifact binding inputs")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "version": args.version,
            "target": args.target,
            "source_sha": args.source_sha,
            "source_run_id": str(args.source_run_id) if args.source_run_id else None,
            "subject_id": subject_id,
            "generated_at": now_utc(),
            "ota_contract": {
                "schema_version": evidence_contract.schema_version("ota_target_contract", contract),
                "compatible": policy["compatible"],
                "boot_backend": policy["boot_backend"],
                "backend": policy["backend"],
                "slot_labels": policy["slot_labels"],
                "verity_devices": policy["verity_devices"],
                "health_checks": policy["health_checks"],
                "mark_good_policy": policy["mark_good_policy"],
                "rollback_storage": policy["rollback_storage"],
            },
            "bundle": artifact_ref(bundle, root=args.binaries_dir),
            "manifest": manifest_ref,
            "signing_roles": ["rauc-bundle", "os-update-manifest"],
            "producer": {
                "name": "produce-ota-artifacts.py",
                "source": "ci/evidence-contract.yml",
            },
        }
        if subject_plan is not None and args.subject_plan is not None:
            payload["subject_plan"] = {
                "path": args.subject_plan.as_posix(),
                "sha256": sha256_file(args.subject_plan),
                "bytes": args.subject_plan.stat().st_size,
            }
        output = args.output or args.output_root / args.version / args.target / "ota-artifacts.json"
        write_json(output, payload)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"wrote OTA artifact metadata: {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--version")
    create.add_argument("--target")
    create.add_argument("--subject-plan", type=Path)
    create.add_argument("--source-sha")
    create.add_argument("--source-run-id")
    create.add_argument("--binaries-dir", type=Path, required=True)
    create.add_argument("--output-root", type=Path, default=Path("release-ota"))
    create.add_argument("--output", type=Path)
    create.add_argument("--rauc-bundle-tool", type=Path, default=ROOT / "scripts" / "create-rauc-bundle.sh")
    create.add_argument("--min-current-version", default="v0.1.0-alpha")
    create.add_argument("--rollback-floor", default="v0.1.0-alpha")
    create.add_argument("--key-epoch", type=int, default=1)
    create.add_argument("--key-id", default="suderra-os-update-manifest")
    create.add_argument("--expires-at", default="2099-01-01T00:00:00Z")
    create.add_argument("--release-notes")
    create.set_defaults(func=create_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
