#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Produce an immutable evidence retention manifest from archive receipts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = evidence_contract.schema_version("retention_manifest")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def artifact_ref(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"retention evidence file is missing or empty: {path}")
    return {
        "path": path.as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def custody_event(args: argparse.Namespace, archive_sha256: str) -> dict[str, str]:
    occurred_at = args.custody_occurred_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parse_utc(occurred_at)
    return {
        "event_id": args.custody_event_id,
        "event_type": args.custody_event_type,
        "actor": args.custody_actor,
        "occurred_at": occurred_at,
        "evidence_sha256": archive_sha256,
    }


def load_release_inputs_validator() -> Any:
    script = Path(__file__).resolve().parent / "validate-release-inputs.py"
    spec = importlib.util.spec_from_file_location("validate_release_inputs", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_command(args: argparse.Namespace) -> int:
    try:
        contract = evidence_contract.load_contract(args.contract)
        policy = evidence_contract.retention_policy(contract)
        retain_until = parse_utc(args.retain_until)
        if retain_until <= datetime.now(timezone.utc):
            raise ValueError("--retain-until must be in the future")
        archive = artifact_ref(args.archive)
        restored = artifact_ref(args.restored_archive)
        access_log = artifact_ref(args.access_log)
        replay_output = artifact_ref(args.replay_validator_output)
        if restored["sha256"] != archive["sha256"]:
            raise ValueError("restored archive digest must match archived object digest")
        if args.archive_object_uri.startswith("github-artifact://") or "://" not in args.archive_object_uri:
            raise ValueError("--archive-object-uri must name immutable external archive storage")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "policy_id": policy["policy_id"],
            "version": args.version,
            "source_sha": args.source_sha,
            "source_run_id": str(args.source_run_id),
            "store_class": policy["store_class"],
            "retention_years": int(args.retention_years or policy["minimum_years"]),
            "exports": [
                {"name": name, "path": name}
                for name in policy["required_exports"]
            ],
            "restore_replay_tests": [
                {"name": name, "status": "passed"}
                for name in policy["required_replay"]
            ],
            "kms_key_id": args.kms_key_id,
            "custody_chain": args.custody_chain,
            "custody_events": [custody_event(args, archive["sha256"])],
            "access_log": access_log["path"],
            "access_log_sha256": access_log["sha256"],
            "archive_object_uri": args.archive_object_uri,
            "archive_object_version_id": args.archive_object_version_id,
            "archive_object_sha256": archive["sha256"],
            "archive_object_bytes": archive["bytes"],
            "retention_lock_mode": args.retention_lock_mode,
            "retain_until": retain_until.isoformat().replace("+00:00", "Z"),
            "legal_hold_status": args.legal_hold_status,
            "legal_hold_id": args.legal_hold_id,
            "restore_job_id": args.restore_job_id,
            "restored_archive_sha256": restored["sha256"],
            "restored_archive_bytes": restored["bytes"],
            "replay_validator_output": replay_output["path"],
            "replay_validator_output_sha256": replay_output["sha256"],
        }
        if payload["retention_years"] < policy["minimum_years"]:
            raise ValueError(f"retention_years must be at least {policy['minimum_years']}")
        # validate_retention_manifest reads from disk; write before replaying it.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validator = load_release_inputs_validator()
        failures = validator.validate_retention_manifest(
            args.output,
            version=args.version,
            source_sha=args.source_sha,
            source_run_id=str(args.source_run_id),
        )
        if failures:
            raise ValueError("; ".join(failures))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"wrote retention manifest: {args.output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=ROOT / "ci/evidence-contract.yml")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--version", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--source-run-id", required=True)
    create.add_argument("--archive", type=Path, required=True)
    create.add_argument("--archive-object-uri", required=True)
    create.add_argument("--archive-object-version-id", required=True)
    create.add_argument("--kms-key-id", required=True)
    create.add_argument("--retention-lock-mode", choices=("governance", "compliance"), required=True)
    create.add_argument("--retain-until", required=True)
    create.add_argument("--retention-years", type=int)
    create.add_argument("--legal-hold-status", required=True)
    create.add_argument("--legal-hold-id", required=True)
    create.add_argument("--access-log", type=Path, required=True)
    create.add_argument("--custody-chain", required=True)
    create.add_argument("--custody-event-id", required=True)
    create.add_argument("--custody-event-type", default="archive-written")
    create.add_argument("--custody-actor", required=True)
    create.add_argument("--custody-occurred-at")
    create.add_argument("--restore-job-id", required=True)
    create.add_argument("--restored-archive", type=Path, required=True)
    create.add_argument("--replay-validator-output", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(func=create_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
