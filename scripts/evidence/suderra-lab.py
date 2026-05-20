#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Collect and sign Suderra hardware lab evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "evidence" / "validate-lab-input.py"
COLLECTOR_VERSION = "suderra-lab-collector.v1"
STATION_BUNDLE_SCHEMA_VERSION = "suderra.lab-station-bundle.v1"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._+-]+")


def load_validator() -> Any:
    spec = importlib.util.spec_from_file_location("validate_lab_input", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_lab_payload(payload: dict[str, Any]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("station_bundle", None)
    unsigned.pop("station_signature", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def require_string(payload: dict[str, Any], field: str, path: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}.{field} must be a non-empty string")
    return value


def safe_rel(value: str, path: str) -> Path:
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"{path} must be relative and must not contain '..'")
    return rel


def safe_name(value: str) -> str:
    return SAFE_NAME_RE.sub("-", value).strip("-") or "unknown"


def copy_evidence(
    source_root: Path,
    lab_root: Path,
    item: dict[str, Any],
    default_rel: str,
    path: str,
) -> tuple[str, str, int]:
    source_value = require_string(item, "source", path)
    source = Path(source_value)
    if not source.is_absolute():
        source = source_root / source
    if not source.is_file() or source.stat().st_size <= 0:
        raise ValueError(f"{path}.source must point to a non-empty evidence file: {source}")
    rel = safe_rel(str(item.get("path", default_rel)), f"{path}.path")
    dest = lab_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    return rel.as_posix(), sha256_file(dest), dest.stat().st_size


def check_record(
    source_root: Path,
    lab_root: Path,
    board: str,
    name: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    evidence, digest, _size = copy_evidence(
        source_root,
        lab_root,
        item,
        f"hardware/{safe_name(board)}/{safe_name(name)}.txt",
        f"devices[{board}].checks.{name}",
    )
    return {
        "status": str(item.get("status", "passed")),
        "evidence": evidence,
        "evidence_sha256": digest,
        "command": str(item.get("command", f"collect {name}")),
        "expected": str(item.get("expected", "passed")),
        "observed": str(item.get("observed", item.get("status", "passed"))),
        "parsed_result": str(item.get("parsed_result", item.get("status", "passed"))),
    }


def build_device(
    validator: Any,
    source_root: Path,
    lab_root: Path,
    artifact_sha256: str,
    artifact_bytes: int,
    device: dict[str, Any],
) -> dict[str, Any]:
    board = require_string(device, "board", "device")
    checks_spec = device.get("checks")
    if not isinstance(checks_spec, dict):
        raise ValueError(f"device {board} checks must be an object")
    required_checks = list(validator.REQUIRED_LAB_CHECKS)
    if board == "revpi-connect-4":
        required_checks.append("revpi-io")
    missing = sorted(set(required_checks) - set(checks_spec))
    if missing:
        raise ValueError(f"device {board} missing required check inputs: {', '.join(missing)}")
    checks = {
        name: check_record(source_root, lab_root, board, name, checks_spec[name])
        for name in required_checks
    }

    logs = []
    logs_spec = device.get("logs")
    if not isinstance(logs_spec, list) or not logs_spec:
        raise ValueError(f"device {board} logs must be a non-empty list")
    for idx, log in enumerate(logs_spec):
        if not isinstance(log, dict):
            raise ValueError(f"device {board} logs[{idx}] must be an object")
        rel, digest, _size = copy_evidence(
            source_root,
            lab_root,
            log,
            f"hardware/{safe_name(board)}/logs/{idx}-log.txt",
            f"devices[{board}].logs[{idx}]",
        )
        logs.append({"path": rel, "sha256": digest})

    readback_spec = device.get("readback")
    if not isinstance(readback_spec, dict):
        raise ValueError(f"device {board} readback must be an object")
    readback_source = Path(require_string(readback_spec, "source", f"device {board}.readback"))
    if not readback_source.is_absolute():
        readback_source = source_root / readback_source
    if not readback_source.is_file():
        raise ValueError(f"device {board} readback source is missing: {readback_source}")
    actual_sha256 = sha256_file(readback_source)
    bytes_read = readback_source.stat().st_size
    if actual_sha256 != artifact_sha256:
        raise ValueError(f"device {board} readback sha256 does not match bound artifact sha256")
    if bytes_read != artifact_bytes:
        raise ValueError(f"device {board} readback size does not match bound artifact bytes")

    identity = device.get("device_identity")
    if not isinstance(identity, dict):
        raise ValueError(f"device {board} device_identity must be an object")
    output = {
        "board": board,
        "serial": require_string(device, "serial", f"device {board}"),
        "sku": require_string(device, "sku", f"device {board}"),
        "storage_serial": require_string(device, "storage_serial", f"device {board}"),
        "uart_adapter": require_string(device, "uart_adapter", f"device {board}"),
        "power_supply": require_string(device, "power_supply", f"device {board}"),
        "boot_firmware": require_string(device, "boot_firmware", f"device {board}"),
        "operator": require_string(device, "operator", f"device {board}"),
        "tested_at": str(device.get("tested_at", now_utc())),
        "status": str(device.get("status", "passed")),
        "logs": logs,
        "device_identity": identity,
        "readback": {
            "scope": "full",
            "bytes_read": bytes_read,
            "expected_sha256": artifact_sha256,
            "actual_sha256": actual_sha256,
            "command": str(readback_spec.get("command", "sha256sum full readback")),
        },
        "checks": checks,
    }
    return output


def negative_test_record(
    source_root: Path,
    lab_root: Path,
    item: dict[str, Any],
) -> dict[str, Any]:
    name = require_string(item, "name", "negative_test")
    evidence, digest, _size = copy_evidence(
        source_root,
        lab_root,
        item,
        f"negative/{safe_name(name)}.txt",
        f"negative_tests.{name}",
    )
    write_prevention = item.get("write_prevention")
    if not isinstance(write_prevention, dict):
        raise ValueError(f"negative test {name} write_prevention must be an object")
    return {
        "name": name,
        "failure_code": require_string(item, "failure_code", f"negative_tests.{name}"),
        "status": str(item.get("status", "passed")),
        "command": str(item.get("command", f"flash negative {name}")),
        "expected": str(item.get("expected", "closed-fail")),
        "observed": str(item.get("observed", "closed-fail")),
        "exit_code": int(item.get("exit_code", 1)),
        "evidence": evidence,
        "evidence_sha256": digest,
        "write_prevention": write_prevention,
    }


def evidence_files(root: Path) -> list[dict[str, Any]]:
    output = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in {"lab.json", "station-bundle.json", "station-bundle.json.sig", "station-public.pem"}:
            continue
        output.append(
            {
                "path": rel,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return output


def run_openssl(args: list[str]) -> None:
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"{' '.join(args)} failed")


def sign_station_bundle(lab_root: Path, signing_key: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl is required to sign station bundle")
    if not signing_key.is_file():
        raise ValueError(f"station signing key is missing: {signing_key}")

    public_key = lab_root / "station-public.pem"
    bundle_path = lab_root / "station-bundle.json"
    signature_path = lab_root / "station-bundle.json.sig"
    run_openssl(["openssl", "pkey", "-in", str(signing_key), "-pubout", "-out", str(public_key)])
    public_key_sha256 = sha256_file(public_key)
    station = payload["station"]
    station["trusted_key_fingerprint"] = public_key_sha256

    binding = payload["artifact_binding"]
    bundle = {
        "schema_version": STATION_BUNDLE_SCHEMA_VERSION,
        "collector": COLLECTOR_VERSION,
        "version": payload["version"],
        "target": payload["target"],
        "lab_id": payload["lab_id"],
        "station_id": station["station_id"],
        "generated_at": now_utc(),
        "source_sha": binding["source_sha"],
        "source_run_id": binding["source_run_id"],
        "build_artifact_sha256": binding["build_artifact_sha256"],
        "build_artifact_bytes": binding["build_artifact_bytes"],
        "lab_payload_sha256": sha256_bytes(canonical_lab_payload(payload)),
        "evidence_files": evidence_files(lab_root),
    }
    write_json(bundle_path, bundle)
    run_openssl(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(signing_key),
            "-in",
            str(bundle_path),
            "-out",
            str(signature_path),
        ]
    )
    return {
        "station_bundle": {
            "schema_version": STATION_BUNDLE_SCHEMA_VERSION,
            "path": bundle_path.relative_to(lab_root).as_posix(),
            "sha256": sha256_file(bundle_path),
            "bytes": bundle_path.stat().st_size,
        },
        "station_signature": {
            "algorithm": "openssl-pkeyutl-ed25519-raw",
            "signature": signature_path.relative_to(lab_root).as_posix(),
            "signature_sha256": sha256_file(signature_path),
            "public_key": public_key.relative_to(lab_root).as_posix(),
            "public_key_sha256": public_key_sha256,
        },
    }


def collect_command(args: argparse.Namespace) -> int:
    validator = load_validator()
    spec_path = args.spec
    source_root = spec_path.parent
    spec = read_json(spec_path)
    if not isinstance(spec, dict):
        raise ValueError("lab collection spec must be a JSON object")
    artifact = args.artifact
    if not artifact.is_file() or artifact.stat().st_size <= 0:
        raise ValueError(f"artifact must be a non-empty file: {artifact}")
    artifact_sha256 = sha256_file(artifact)
    artifact_bytes = artifact.stat().st_size
    lab_root = args.output_root / args.version / args.target
    lab_root.mkdir(parents=True, exist_ok=True)

    station = spec.get("station")
    if not isinstance(station, dict):
        raise ValueError("spec.station must be an object")
    station = dict(station)
    tool_versions = station.get("tool_versions")
    if not isinstance(tool_versions, dict):
        tool_versions = {}
    tool_versions["suderra-lab"] = COLLECTOR_VERSION
    station["tool_versions"] = tool_versions

    devices_spec = spec.get("devices")
    if not isinstance(devices_spec, list) or not devices_spec:
        raise ValueError("spec.devices must be a non-empty list")
    devices = [
        build_device(validator, source_root, lab_root, artifact_sha256, artifact_bytes, item)
        for item in devices_spec
        if isinstance(item, dict)
    ]
    if len(devices) != len(devices_spec):
        raise ValueError("every spec.devices entry must be an object")

    negative_spec = spec.get("negative_tests", [])
    if not isinstance(negative_spec, list):
        raise ValueError("spec.negative_tests must be a list")
    negative_tests = [
        negative_test_record(source_root, lab_root, item)
        for item in negative_spec
        if isinstance(item, dict)
    ]
    if len(negative_tests) != len(negative_spec):
        raise ValueError("every spec.negative_tests entry must be an object")

    payload = {
        "schema_version": validator.SCHEMA_VERSION,
        "version": args.version,
        "target": args.target,
        "generated_at": now_utc(),
        "lab_id": require_string(spec, "lab_id", "spec"),
        "operator": require_string(spec, "operator", "spec"),
        "station": station,
        "artifact_binding": {
            "version": args.version,
            "source_sha": args.source_sha,
            "source_run_id": args.source_run_id,
            "build_artifact_sha256": artifact_sha256,
            "build_artifact_bytes": artifact_bytes,
        },
        "devices": devices,
        "negative_tests": negative_tests,
    }
    payload.update(sign_station_bundle(lab_root, args.signing_key, payload))
    lab_json = lab_root / "lab.json"
    write_json(lab_json, payload)
    failures = validator.validate_lab(
        lab_json,
        True,
        True,
        args.version,
        args.target,
        args.profile,
        args.source_sha,
        args.source_run_id,
        args.station_registry,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(f"wrote signed lab evidence: {lab_json}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect", help="collect signed lab evidence from a station spec")
    collect.add_argument("--version", required=True)
    collect.add_argument("--target", required=True)
    collect.add_argument("--source-sha", required=True)
    collect.add_argument("--source-run-id", required=True)
    collect.add_argument("--artifact", type=Path, required=True)
    collect.add_argument("--spec", type=Path, required=True)
    collect.add_argument("--signing-key", type=Path, required=True)
    collect.add_argument("--station-registry", type=Path)
    collect.add_argument("--output-root", type=Path, default=Path("release-lab-input"))
    collect.add_argument(
        "--profile",
        choices=("technical-dry-run", "release-candidate", "production-candidate"),
        default="release-candidate",
    )
    collect.set_defaults(func=collect_command)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
