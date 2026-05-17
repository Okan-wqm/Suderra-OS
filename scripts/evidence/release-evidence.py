#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Generate and validate Suderra OS release evidence bundles.

The evidence contract intentionally uses only JSON plus Python's standard
library. A release bundle is rooted at:

    release-evidence/<version>/<target>/evidence.json

The validator checks the schema on every run and can also enforce the stricter
"ready for release" invariants with --require-pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.release-evidence.v1"

TOP_LEVEL_FIELDS = {
    "schema_version",
    "version",
    "target",
    "generated_at",
    "target_contract",
    "source",
    "artifacts",
    "sbom",
    "vex",
    "reproducibility",
    "security_scans",
    "qemu",
    "hardware",
    "runtime_checks",
    "approvals",
    "residual_risk",
    "release_decision",
}

TARGET_CONTRACT_FIELDS = {
    "defconfig",
    "target",
    "arch",
    "artifact",
    "release_artifact",
    "profile",
    "boot_mode",
    "partition_table",
    "root_partition",
    "root_identity",
    "signing",
    "acceptance",
    "production_required",
    "production_ready",
}

STATUS_VALUES = {"passed", "failed", "not_run", "not_applicable", "not_collected"}
VEX_STATUS_VALUES = {"present", "not_applicable", "not_collected"}
RISK_STATUS_VALUES = {"none", "accepted", "blocked"}
DECISION_STATUS_VALUES = {"approved", "approved_with_residual_risk", "blocked"}
REQUIRED_RUNTIME_CHECKS = ("dm_verity", "rauc", "lockdown", "nmap", "systemd_security")
REQUIRED_QEMU_CHECKS = (
    "boot",
    "systemd",
    "zero-failed-units",
    "firstboot-idempotence",
    "network",
    "lockdown-transition",
)
REQUIRED_HARDWARE_CHECKS = (
    "board-identity",
    "partitions",
    "root-data-mounts",
    "network",
    "gpio",
    "i2c",
    "spi",
    "rtc-time",
    "watchdog",
    "thermal",
    "lockdown",
)
REQUIRED_HARDWARE_BOARDS_BY_TARGET = {
    "rpi4": ("raspberry-pi-4-model-b", "cm4-lite-sd", "cm4-emmc-io-board"),
    "pi-cm4-revpi-usb-installer": (
        "raspberry-pi-4-model-b",
        "cm4-lite-sd",
        "cm4-emmc-io-board",
        "revpi-connect-4",
    ),
    "revpi4": ("revpi-connect-4",),
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class Validation:
    def __init__(self, evidence_path: Path, check_files: bool) -> None:
        self.evidence_path = evidence_path
        self.evidence_dir = evidence_path.parent
        self.check_files = check_files
        self.errors: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line.rstrip()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if re.fullmatch(r"[0-9]+", value):
        return int(value)
    return value


def parse_key_value(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"expected key/value entry: {text!r}")
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def load_matrix(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"defconfigs": [], "variants": [], "security_scans": []}
    section: str | None = None
    current: dict[str, Any] | None = None
    pending_key: str | None = None

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()

        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            data.setdefault(section, [])
            current = None
            pending_key = None
            continue

        if section in {"defconfigs", "variants"}:
            if indent == 2 and text.startswith("- "):
                current = {}
                data[section].append(current)
                rest = text[2:].strip()
                if rest:
                    key, value = parse_key_value(rest)
                    current[key] = parse_scalar(value)
                pending_key = None
                continue
            if indent == 4 and current is not None:
                key, value = parse_key_value(text)
                if value:
                    current[key] = parse_scalar(value)
                    pending_key = None
                else:
                    current[key] = []
                    pending_key = key
                continue
            if indent == 6 and text.startswith("- ") and current is not None and pending_key:
                current[pending_key].append(parse_scalar(text[2:].strip()))
                continue

        if section == "security_scans" and indent == 2 and text.startswith("- "):
            data[section].append(parse_scalar(text[2:].strip()))
            continue

        raise ValueError(f"unsupported YAML subset at {path}:{lineno}: {raw}")

    return data


def targets_by_id(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for entry in matrix.get("defconfigs", []):
        target = str(entry.get("target", ""))
        if target:
            targets[target] = entry
        name = str(entry.get("name", ""))
        if name:
            targets.setdefault(name, entry)
    return targets


def git_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def release_base(release_artifact: str) -> str:
    if release_artifact.endswith(".img.xz"):
        return release_artifact[: -len(".img.xz")]
    return release_artifact[:-3] if release_artifact.endswith(".xz") else release_artifact


def contract_from_matrix(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "defconfig": row["name"],
        "target": row["target"],
        "arch": row["arch"],
        "artifact": row["artifact"],
        "release_artifact": row["release_artifact"],
        "profile": row["profile"],
        "boot_mode": row["boot_mode"],
        "partition_table": row["partition_table"],
        "root_partition": row["root_partition"],
        "root_identity": row["root_identity"],
        "signing": row["signing"],
        "acceptance": row["acceptance"],
        "production_required": row["production_required"],
        "production_ready": row["production_ready"],
    }


def generated_evidence(version: str, row: dict[str, Any], security_scans: list[str]) -> dict[str, Any]:
    contract = contract_from_matrix(row)
    release_artifact = str(contract["release_artifact"])
    base = release_base(release_artifact)
    acceptance = str(contract["acceptance"])
    production_required = bool(contract["production_required"])
    qemu_required = bool(row.get("qemu_test", False))
    hardware_required = production_required or "hardware" in acceptance
    dirty = bool(git_output(["status", "--porcelain"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "target": contract["target"],
        "generated_at": now_utc(),
        "target_contract": contract,
        "source": {
            "repository": git_output(["config", "--get", "remote.origin.url"]) or "unknown",
            "git_commit": git_output(["rev-parse", "HEAD"]) or "unknown",
            "git_tag": version,
            "dirty": dirty,
            "ci": {
                "provider": "github-actions",
                "workflow": "release",
                "run_id": "not_collected",
                "run_attempt": "not_collected",
            },
        },
        "artifacts": [
            {
                "name": release_artifact,
                "role": "release-image",
                "path": f"artifacts/{release_artifact}",
                "sha256": None,
                "bytes": None,
                "signature": {
                    "path": f"artifacts/{release_artifact}.sig",
                    "certificate": f"artifacts/{release_artifact}.cert",
                    "verified": False,
                },
                "provenance": {
                    "path": f"provenance/{release_artifact}.intoto.jsonl",
                    "verified": False,
                },
            }
        ],
        "sbom": {
            "format": "cyclonedx-json",
            "path": f"sbom/{base}.cyclonedx.json",
            "sha256": None,
            "component_count": None,
            "signature_verified": False,
        },
        "vex": {
            "status": "not_collected",
            "path": None,
            "sha256": None,
            "signature_verified": False,
        },
        "reproducibility": {
            "status": "not_run",
            "comparison": None,
            "logs": [],
        },
        "security_scans": [
            {"name": str(name), "status": "not_run", "report": None} for name in security_scans
        ],
        "qemu": {
            "required": qemu_required,
            "status": "not_run" if qemu_required else "not_applicable",
            "logs": [],
            "checks": [],
        },
        "hardware": {
            "required": hardware_required,
            "status": "not_run" if hardware_required else "not_applicable",
            "devices": [],
        },
        "runtime_checks": {
            name: {
                "required": production_required,
                "status": "not_run" if production_required else "not_applicable",
                "evidence": None,
            }
            for name in REQUIRED_RUNTIME_CHECKS
        },
        "approvals": [],
        "residual_risk": {
            "status": "none",
            "items": [],
            "accepted_by": None,
            "accepted_at": None,
            "expires_at": None,
        },
        "release_decision": {
            "status": "blocked",
            "decided_by": None,
            "decided_at": None,
            "rationale": "Evidence has not been reviewed.",
        },
    }


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_string(validation: Validation, path: str, value: Any) -> None:
    if not is_non_empty_string(value):
        validation.error(path, "must be a non-empty string")


def check_bool(validation: Validation, path: str, value: Any) -> None:
    if not isinstance(value, bool):
        validation.error(path, "must be true or false")


def check_status(validation: Validation, path: str, value: Any, allowed: set[str]) -> None:
    if value not in allowed:
        validation.error(path, f"must be one of: {', '.join(sorted(allowed))}")


def check_sha256(validation: Validation, path: str, value: Any, required: bool) -> None:
    if value is None and not required:
        return
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        validation.error(path, "must be a lowercase sha256 hex digest")


def check_positive_int(validation: Validation, path: str, value: Any, required: bool) -> None:
    if value is None and not required:
        return
    if not isinstance(value, int) or value <= 0:
        validation.error(path, "must be a positive integer")


def check_relative_path(validation: Validation, path: str, value: Any, required: bool) -> Path | None:
    if value is None and not required:
        return None
    if not is_non_empty_string(value):
        validation.error(path, "must be a relative path")
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        validation.error(path, "must be relative and must not contain '..'")
        return None
    actual = validation.evidence_dir / rel
    if validation.check_files:
        if not actual.is_file():
            validation.error(path, f"referenced file is missing: {value}")
            return None
        if actual.stat().st_size <= 0:
            validation.error(path, f"referenced file is empty: {value}")
            return None
    return actual


def file_for_relative_path(validation: Validation, value: Any) -> Path | None:
    if not validation.check_files or not is_non_empty_string(value):
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    actual = validation.evidence_dir / rel
    if not actual.is_file():
        return None
    return actual


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_file_sha256(validation: Validation, path: str, rel: Any, expected: Any) -> None:
    if not validation.check_files or expected is None:
        return
    actual = file_for_relative_path(validation, rel)
    if actual is not None and sha256_file(actual) != expected:
        validation.error(path, "does not match referenced file sha256")


def check_file_size(validation: Validation, path: str, rel: Any, expected: Any) -> None:
    if not validation.check_files or expected is None:
        return
    actual = file_for_relative_path(validation, rel)
    if actual is not None and actual.stat().st_size != expected:
        validation.error(path, "does not match referenced file size")


def parse_timestamp(validation: Validation, path: str, value: Any, required: bool) -> datetime | None:
    if value is None and not required:
        return None
    if not is_non_empty_string(value):
        validation.error(path, "must be an ISO-8601 UTC timestamp")
        return None
    text = value.strip()
    if not text.endswith("Z"):
        validation.error(path, "must use UTC Z suffix")
        return None
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        validation.error(path, "must be an ISO-8601 UTC timestamp")
        return None


def check_path_contract(validation: Validation, evidence: dict[str, Any]) -> None:
    parts = validation.evidence_path.as_posix().split("/")
    if len(parts) < 4 or parts[-4] != "release-evidence" or parts[-1] != "evidence.json":
        validation.error(
            "$path",
            "must end with release-evidence/<version>/<target>/evidence.json",
        )
        return
    if parts[-3] != evidence.get("version"):
        validation.error("$path", "version directory must match evidence.version")
    if parts[-2] != evidence.get("target"):
        validation.error("$path", "target directory must match evidence.target")


def validate_artifacts(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        validation.error("$.artifacts", "must be a non-empty list")
        return

    for idx, artifact in enumerate(artifacts):
        path = f"$.artifacts[{idx}]"
        if not isinstance(artifact, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("name", "role"):
            check_string(validation, f"{path}.{field}", artifact.get(field))
        check_relative_path(validation, f"{path}.path", artifact.get("path"), True)
        check_sha256(validation, f"{path}.sha256", artifact.get("sha256"), require_pass)
        check_positive_int(validation, f"{path}.bytes", artifact.get("bytes"), require_pass)
        check_file_sha256(validation, f"{path}.sha256", artifact.get("path"), artifact.get("sha256"))
        check_file_size(validation, f"{path}.bytes", artifact.get("path"), artifact.get("bytes"))

        signature = artifact.get("signature")
        if not isinstance(signature, dict):
            validation.error(f"{path}.signature", "must be an object")
        else:
            require_signed_controls = require_pass and release_tier == "production"
            signature_path = (
                signature.get("path")
                if require_signed_controls or signature.get("verified") is True
                else None
            )
            certificate_path = (
                signature.get("certificate")
                if require_signed_controls or signature.get("verified") is True
                else None
            )
            check_relative_path(validation, f"{path}.signature.path", signature_path, require_signed_controls)
            check_relative_path(
                validation,
                f"{path}.signature.certificate",
                certificate_path,
                require_signed_controls,
            )
            check_bool(validation, f"{path}.signature.verified", signature.get("verified"))
            if require_signed_controls and signature.get("verified") is not True:
                validation.error(f"{path}.signature.verified", "must be true for release-ready evidence")

        provenance = artifact.get("provenance")
        if not isinstance(provenance, dict):
            validation.error(f"{path}.provenance", "must be an object")
        else:
            require_provenance = require_pass and release_tier == "production"
            provenance_path = (
                provenance.get("path")
                if require_provenance or provenance.get("verified") is True
                else None
            )
            check_relative_path(validation, f"{path}.provenance.path", provenance_path, require_provenance)
            check_bool(validation, f"{path}.provenance.verified", provenance.get("verified"))
            if require_provenance and provenance.get("verified") is not True:
                validation.error(f"{path}.provenance.verified", "must be true for release-ready evidence")


def validate_sbom(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    sbom = evidence.get("sbom")
    if not isinstance(sbom, dict):
        validation.error("$.sbom", "must be an object")
        return
    if sbom.get("format") != "cyclonedx-json":
        validation.error("$.sbom.format", "must be cyclonedx-json")
    check_relative_path(validation, "$.sbom.path", sbom.get("path"), True)
    check_sha256(validation, "$.sbom.sha256", sbom.get("sha256"), require_pass)
    check_positive_int(validation, "$.sbom.component_count", sbom.get("component_count"), require_pass)
    check_file_sha256(validation, "$.sbom.sha256", sbom.get("path"), sbom.get("sha256"))
    check_bool(validation, "$.sbom.signature_verified", sbom.get("signature_verified"))
    if validation.check_files:
        sbom_file = file_for_relative_path(validation, sbom.get("path"))
        if sbom_file is not None:
            try:
                payload = json.loads(sbom_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                validation.error("$.sbom.path", f"must be readable CycloneDX JSON: {exc}")
            else:
                components = payload.get("components")
                actual_count = len(components) if isinstance(components, list) else 0
                if actual_count <= 0:
                    validation.error("$.sbom.component_count", "CycloneDX components must be non-empty")
                if isinstance(sbom.get("component_count"), int) and sbom["component_count"] != actual_count:
                    validation.error("$.sbom.component_count", "does not match CycloneDX components length")
    if require_pass and release_tier == "production" and sbom.get("signature_verified") is not True:
        validation.error("$.sbom.signature_verified", "must be true for release-ready evidence")


def validate_vex(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    vex = evidence.get("vex")
    if not isinstance(vex, dict):
        validation.error("$.vex", "must be an object")
        return
    check_status(validation, "$.vex.status", vex.get("status"), VEX_STATUS_VALUES)
    present = vex.get("status") == "present"
    check_relative_path(validation, "$.vex.path", vex.get("path"), present)
    check_sha256(validation, "$.vex.sha256", vex.get("sha256"), present)
    check_file_sha256(validation, "$.vex.sha256", vex.get("path"), vex.get("sha256"))
    check_bool(validation, "$.vex.signature_verified", vex.get("signature_verified"))
    if require_pass and release_tier == "production" and not present:
        validation.error("$.vex.status", "must be present for release-ready evidence")
    if present and require_pass and release_tier == "production" and vex.get("signature_verified") is not True:
        validation.error("$.vex.signature_verified", "must be true when VEX is present")


def validate_status_list(
    validation: Validation,
    base_path: str,
    value: Any,
    require_pass: bool,
    require_report: bool,
    expected_names: list[str] | None = None,
) -> None:
    if not isinstance(value, list):
        validation.error(base_path, "must be a list")
        return
    if expected_names is not None:
        actual_names = [
            str(entry.get("name"))
            for entry in value
            if isinstance(entry, dict) and is_non_empty_string(entry.get("name"))
        ]
        if sorted(actual_names) != sorted(expected_names):
            validation.error(base_path, f"must contain exactly: {', '.join(sorted(expected_names))}")
    for idx, entry in enumerate(value):
        path = f"{base_path}[{idx}]"
        if not isinstance(entry, dict):
            validation.error(path, "must be an object")
            continue
        check_string(validation, f"{path}.name", entry.get("name"))
        check_status(validation, f"{path}.status", entry.get("status"), STATUS_VALUES)
        check_relative_path(
            validation,
            f"{path}.report",
            entry.get("report"),
            require_report or (require_pass and entry.get("status") == "passed"),
        )
        if require_pass and entry.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
    if require_pass and not value:
        validation.error(base_path, "must not be empty for release-ready evidence")


def validate_qemu(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    qemu = evidence.get("qemu")
    if not isinstance(qemu, dict):
        validation.error("$.qemu", "must be an object")
        return
    check_bool(validation, "$.qemu.required", qemu.get("required"))
    check_status(validation, "$.qemu.status", qemu.get("status"), STATUS_VALUES)
    logs = qemu.get("logs")
    if not isinstance(logs, list):
        validation.error("$.qemu.logs", "must be a list")
    else:
        for idx, log in enumerate(logs):
            check_relative_path(validation, f"$.qemu.logs[{idx}]", log, True)
    checks = qemu.get("checks")
    if not isinstance(checks, list):
        validation.error("$.qemu.checks", "must be a list")
    else:
        for idx, check in enumerate(checks):
            if not is_non_empty_string(check):
                validation.error(f"$.qemu.checks[{idx}]", "must be a non-empty string")

    if require_pass and qemu.get("required"):
        if qemu.get("status") != "passed":
            validation.error("$.qemu.status", "must be passed when QEMU evidence is required")
        if not logs:
            validation.error("$.qemu.logs", "must include at least one log when QEMU is required")
        missing_checks = sorted(set(REQUIRED_QEMU_CHECKS) - set(checks or []))
        if missing_checks:
            validation.error("$.qemu.checks", f"missing required checks: {', '.join(missing_checks)}")


def validate_hardware(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    hardware = evidence.get("hardware")
    if not isinstance(hardware, dict):
        validation.error("$.hardware", "must be an object")
        return
    check_bool(validation, "$.hardware.required", hardware.get("required"))
    check_status(validation, "$.hardware.status", hardware.get("status"), STATUS_VALUES)
    devices = hardware.get("devices")
    if not isinstance(devices, list):
        validation.error("$.hardware.devices", "must be a list")
        return

    for idx, device in enumerate(devices):
        path = f"$.hardware.devices[{idx}]"
        if not isinstance(device, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("board", "serial", "operator"):
            check_string(validation, f"{path}.{field}", device.get(field))
        check_status(validation, f"{path}.status", device.get("status"), STATUS_VALUES)
        logs = device.get("logs")
        if not isinstance(logs, list):
            validation.error(f"{path}.logs", "must be a list")
        else:
            for log_idx, log in enumerate(logs):
                check_relative_path(validation, f"{path}.logs[{log_idx}]", log, True)
        checks = device.get("checks")
        if not isinstance(checks, dict):
            validation.error(f"{path}.checks", "must be an object")
        else:
            for check_name, check in checks.items():
                check_path = f"{path}.checks.{check_name}"
                if not isinstance(check, dict):
                    validation.error(check_path, "must be an object")
                    continue
                check_status(validation, f"{check_path}.status", check.get("status"), STATUS_VALUES)
                check_relative_path(
                    validation,
                    f"{check_path}.evidence",
                    check.get("evidence"),
                    require_pass
                    and bool(hardware.get("required"))
                    and check_name in REQUIRED_HARDWARE_CHECKS,
                )
                if require_pass and check.get("status") != "passed":
                    validation.error(f"{check_path}.status", "must be passed for release-ready evidence")

        if require_pass and hardware.get("required") and device.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")
        if require_pass and hardware.get("required"):
            if not logs:
                validation.error(f"{path}.logs", "must include serial/install logs")
            if isinstance(checks, dict):
                missing_checks = sorted(set(REQUIRED_HARDWARE_CHECKS) - set(checks))
                if missing_checks:
                    validation.error(
                        f"{path}.checks",
                        f"missing required checks: {', '.join(missing_checks)}",
                    )

    if require_pass and hardware.get("required"):
        if hardware.get("status") != "passed":
            validation.error("$.hardware.status", "must be passed when hardware evidence is required")
        if not devices:
            validation.error("$.hardware.devices", "must include at least one device")
        required_boards = REQUIRED_HARDWARE_BOARDS_BY_TARGET.get(str(evidence.get("target", "")), ())
        if required_boards:
            seen_boards = {
                device.get("board")
                for device in devices
                if isinstance(device, dict) and isinstance(device.get("board"), str)
            }
            missing_boards = sorted(set(required_boards) - seen_boards)
            if missing_boards:
                validation.error(
                    "$.hardware.devices",
                    f"missing required board evidence: {', '.join(missing_boards)}",
                )


def validate_runtime_checks(
    validation: Validation,
    evidence: dict[str, Any],
    require_pass: bool,
    release_tier: str,
) -> None:
    runtime_checks = evidence.get("runtime_checks")
    if not isinstance(runtime_checks, dict):
        validation.error("$.runtime_checks", "must be an object")
        return
    for name in REQUIRED_RUNTIME_CHECKS:
        if name not in runtime_checks:
            validation.error("$.runtime_checks", f"missing required check: {name}")
    for name, check in runtime_checks.items():
        path = f"$.runtime_checks.{name}"
        if not isinstance(check, dict):
            validation.error(path, "must be an object")
            continue
        check_bool(validation, f"{path}.required", check.get("required"))
        check_status(validation, f"{path}.status", check.get("status"), STATUS_VALUES)
        check_relative_path(
            validation,
            f"{path}.evidence",
            check.get("evidence"),
            require_pass and release_tier == "production" and bool(check.get("required")),
        )
        if require_pass and release_tier == "production" and check.get("required") and check.get("status") != "passed":
            validation.error(f"{path}.status", "must be passed for release-ready evidence")


def validate_approvals(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    approvals = evidence.get("approvals")
    if not isinstance(approvals, list):
        validation.error("$.approvals", "must be a list")
        return
    for idx, approval in enumerate(approvals):
        path = f"$.approvals[{idx}]"
        if not isinstance(approval, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("role", "name", "approved_at"):
            check_string(validation, f"{path}.{field}", approval.get(field))
        parse_timestamp(validation, f"{path}.approved_at", approval.get("approved_at"), True)
        if "ticket" in approval:
            check_string(validation, f"{path}.ticket", approval.get("ticket"))
    if require_pass and not approvals:
        validation.error("$.approvals", "must include at least one approval")


def validate_residual_risk(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    risk = evidence.get("residual_risk")
    if not isinstance(risk, dict):
        validation.error("$.residual_risk", "must be an object")
        return
    check_status(validation, "$.residual_risk.status", risk.get("status"), RISK_STATUS_VALUES)
    items = risk.get("items")
    if not isinstance(items, list):
        validation.error("$.residual_risk.items", "must be a list")
        items = []
    for idx, item in enumerate(items):
        path = f"$.residual_risk.items[{idx}]"
        if not isinstance(item, dict):
            validation.error(path, "must be an object")
            continue
        for field in ("id", "severity", "description", "mitigation", "owner", "ticket"):
            check_string(validation, f"{path}.{field}", item.get(field))

    decision = evidence.get("release_decision")
    decision_status = decision.get("status") if isinstance(decision, dict) else None
    if require_pass and risk.get("status") == "blocked":
        validation.error("$.residual_risk.status", "must not be blocked for release-ready evidence")
    if require_pass and decision_status == "approved":
        if risk.get("status") != "none":
            validation.error(
                "$.residual_risk.status",
                "must be none when release decision is approved without residual risk",
            )
        if items:
            validation.error(
                "$.residual_risk.items",
                "must be empty when release decision is approved without residual risk",
            )
    if require_pass and decision_status == "approved_with_residual_risk":
        if risk.get("status") != "accepted":
            validation.error(
                "$.residual_risk.status",
                "must be accepted when release decision carries residual risk",
            )
        if not items:
            validation.error("$.residual_risk.items", "must list accepted residual risks")
        for field in ("accepted_by", "accepted_at", "expires_at"):
            check_string(validation, f"$.residual_risk.{field}", risk.get(field))
        parse_timestamp(validation, "$.residual_risk.accepted_at", risk.get("accepted_at"), True)
        expires_at = parse_timestamp(validation, "$.residual_risk.expires_at", risk.get("expires_at"), True)
        if expires_at is not None and expires_at <= datetime.now(timezone.utc):
            validation.error("$.residual_risk.expires_at", "must be in the future")


def validate_release_decision(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    decision = evidence.get("release_decision")
    if not isinstance(decision, dict):
        validation.error("$.release_decision", "must be an object")
        return
    check_status(validation, "$.release_decision.status", decision.get("status"), DECISION_STATUS_VALUES)
    for field in ("decided_by", "decided_at", "rationale"):
        required = require_pass or field == "rationale"
        value = decision.get(field)
        if required or value is not None:
            check_string(validation, f"$.release_decision.{field}", value)
    parse_timestamp(validation, "$.release_decision.decided_at", decision.get("decided_at"), require_pass)
    if require_pass and decision.get("status") not in {"approved", "approved_with_residual_risk"}:
        validation.error("$.release_decision.status", "must be approved for release-ready evidence")


def validate_source(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    source = evidence.get("source")
    if not isinstance(source, dict):
        validation.error("$.source", "must be an object")
        return
    for field in ("repository", "git_commit", "git_tag"):
        check_string(validation, f"$.source.{field}", source.get(field))
    check_bool(validation, "$.source.dirty", source.get("dirty"))
    if source.get("git_tag") != evidence.get("version"):
        validation.error("$.source.git_tag", "must match evidence.version")
    ci = source.get("ci")
    if not isinstance(ci, dict):
        validation.error("$.source.ci", "must be an object")
    else:
        for field in ("provider", "workflow", "run_id", "run_attempt"):
            check_string(validation, f"$.source.ci.{field}", ci.get(field))
        if require_pass:
            if ci.get("run_id") == "not_collected":
                validation.error("$.source.ci.run_id", "must be collected for release-ready evidence")
            if ci.get("run_attempt") == "not_collected":
                validation.error("$.source.ci.run_attempt", "must be collected for release-ready evidence")
    if require_pass:
        if not isinstance(source.get("git_commit"), str) or not re.fullmatch(
            r"[0-9a-f]{40}", source["git_commit"]
        ):
            validation.error("$.source.git_commit", "must be a full git commit sha")
        if source.get("dirty") is not False:
            validation.error("$.source.dirty", "must be false for release-ready evidence")


def validate_reproducibility(validation: Validation, evidence: dict[str, Any], require_pass: bool) -> None:
    reproducibility = evidence.get("reproducibility")
    if not isinstance(reproducibility, dict):
        validation.error("$.reproducibility", "must be an object")
        return
    check_status(validation, "$.reproducibility.status", reproducibility.get("status"), STATUS_VALUES)
    comparison = reproducibility.get("comparison")
    if comparison is not None:
        check_string(validation, "$.reproducibility.comparison", comparison)
    logs = reproducibility.get("logs")
    if not isinstance(logs, list):
        validation.error("$.reproducibility.logs", "must be a list")
    else:
        for idx, log in enumerate(logs):
            check_relative_path(validation, f"$.reproducibility.logs[{idx}]", log, True)
    if require_pass and reproducibility.get("status") != "passed":
        validation.error("$.reproducibility.status", "must be passed for release-ready evidence")


def validate_target_contract(
    validation: Validation,
    evidence: dict[str, Any],
    matrix: dict[str, Any] | None,
) -> None:
    contract = evidence.get("target_contract")
    if not isinstance(contract, dict):
        validation.error("$.target_contract", "must be an object")
        return
    missing = sorted(TARGET_CONTRACT_FIELDS - set(contract))
    extra = sorted(set(contract) - TARGET_CONTRACT_FIELDS)
    if missing:
        validation.error("$.target_contract", f"missing fields: {', '.join(missing)}")
    if extra:
        validation.error("$.target_contract", f"unknown fields: {', '.join(extra)}")
    if contract.get("target") != evidence.get("target"):
        validation.error("$.target_contract.target", "must match evidence.target")
    for field in TARGET_CONTRACT_FIELDS - {"production_required", "production_ready"}:
        check_string(validation, f"$.target_contract.{field}", contract.get(field))
    for field in ("production_required", "production_ready"):
        check_bool(validation, f"$.target_contract.{field}", contract.get(field))

    if matrix is None:
        return
    row = targets_by_id(matrix).get(str(evidence.get("target", "")))
    if row is None:
        validation.error("$.target", "must exist in ci/build-matrix.yml")
        return
    expected = contract_from_matrix(row)
    for field, expected_value in expected.items():
        if contract.get(field) != expected_value:
            validation.error(
                f"$.target_contract.{field}",
                f"does not match matrix value {expected_value!r}",
            )


def validate_evidence(
    evidence_path: Path,
    matrix_path: Path | None,
    require_pass: bool,
    check_files: bool,
    release_tier: str,
) -> list[str]:
    validation = Validation(evidence_path, check_files)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{evidence_path}: cannot read evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{evidence_path}: invalid JSON: {exc}"]
    if not isinstance(evidence, dict):
        return [f"{evidence_path}: top-level JSON value must be an object"]

    missing = sorted(TOP_LEVEL_FIELDS - set(evidence))
    extra = sorted(set(evidence) - TOP_LEVEL_FIELDS)
    if missing:
        validation.error("$", f"missing fields: {', '.join(missing)}")
    if extra:
        validation.error("$", f"unknown fields: {', '.join(extra)}")

    if evidence.get("schema_version") != SCHEMA_VERSION:
        validation.error("$.schema_version", f"must be {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at"):
        check_string(validation, f"$.{field}", evidence.get(field))
    parse_timestamp(validation, "$.generated_at", evidence.get("generated_at"), True)
    for field in ("version", "target"):
        value = evidence.get(field)
        if isinstance(value, str) and not SAFE_ID_RE.fullmatch(value):
            validation.error(f"$.{field}", "must be a safe path identifier")

    check_path_contract(validation, evidence)

    matrix = None
    if matrix_path is not None:
        try:
            matrix = load_matrix(matrix_path)
        except (OSError, ValueError) as exc:
            validation.error("$matrix", f"cannot read matrix: {exc}")

    validate_target_contract(validation, evidence, matrix)
    validate_source(validation, evidence, require_pass)
    validate_artifacts(validation, evidence, require_pass, release_tier)
    validate_sbom(validation, evidence, require_pass, release_tier)
    validate_vex(validation, evidence, require_pass, release_tier)
    validate_reproducibility(validation, evidence, require_pass)
    expected_security_scans = None
    if matrix is not None:
        expected_security_scans = [str(item) for item in matrix.get("security_scans", [])]
    validate_status_list(
        validation,
        "$.security_scans",
        evidence.get("security_scans"),
        require_pass,
        False,
        expected_security_scans if require_pass else None,
    )
    validate_qemu(validation, evidence, require_pass)
    validate_hardware(validation, evidence, require_pass)
    validate_runtime_checks(validation, evidence, require_pass, release_tier)
    validate_approvals(validation, evidence, require_pass)
    validate_release_decision(validation, evidence, require_pass)
    validate_residual_risk(validation, evidence, require_pass)
    return validation.errors


def schema_contract() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "path": "release-evidence/<version>/<target>/evidence.json",
        "required_top_level_fields": sorted(TOP_LEVEL_FIELDS),
        "target_contract_fields": sorted(TARGET_CONTRACT_FIELDS),
        "status_values": sorted(STATUS_VALUES),
        "vex_status_values": sorted(VEX_STATUS_VALUES),
        "residual_risk_status_values": sorted(RISK_STATUS_VALUES),
        "release_decision_status_values": sorted(DECISION_STATUS_VALUES),
        "release_tiers": ["alpha", "production"],
        "required_runtime_checks": list(REQUIRED_RUNTIME_CHECKS),
        "required_qemu_checks": list(REQUIRED_QEMU_CHECKS),
        "required_hardware_checks": list(REQUIRED_HARDWARE_CHECKS),
        "required_hardware_boards_by_target": {
            target: list(boards)
            for target, boards in sorted(REQUIRED_HARDWARE_BOARDS_BY_TARGET.items())
        },
        "release_ready_invariants": [
            "source.dirty is false and source.git_commit is a full commit sha",
            "artifact hashes, sizes, signatures, and provenance are present, verified, and match referenced files",
            "SBOM is CycloneDX JSON with a non-empty matching component count and verified signature",
            "signed VEX is present",
            "reproducibility and every matrix security scan are passed with reports",
            "required QEMU and hardware evidence sections are passed",
            "required runtime checks have passed evidence files",
            "release_decision is approved or approved_with_residual_risk",
            "approval and decision timestamps are ISO-8601 UTC",
            "approved requires residual_risk.status none and no residual risk items",
            "approved_with_residual_risk requires accepted, future-expiring residual risk records",
        ],
    }


def generate_command(args: argparse.Namespace) -> int:
    matrix = load_matrix(args.matrix)
    row = targets_by_id(matrix).get(args.target)
    if row is None:
        print(f"ERROR: target not found in matrix: {args.target}", file=sys.stderr)
        return 1

    evidence = generated_evidence(
        args.version,
        row,
        [str(item) for item in matrix.get("security_scans", [])],
    )
    output = args.output
    if output is None:
        output = Path("release-evidence") / args.version / str(evidence["target"]) / "evidence.json"
    if output.exists() and not args.force:
        print(f"ERROR: refusing to overwrite existing evidence file: {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


def validate_command(args: argparse.Namespace) -> int:
    errors = validate_evidence(
        args.evidence,
        args.matrix,
        args.require_pass,
        args.check_files,
        args.release_tier,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    mode = "release-ready" if args.require_pass else "schema"
    print(f"validated {mode} evidence: {args.evidence}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="create a blocked evidence.json skeleton")
    generate.add_argument("--version", required=True)
    generate.add_argument("--target", required=True, help="matrix target id or defconfig name")
    generate.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    generate.add_argument("--output", type=Path)
    generate.add_argument("--force", action="store_true")
    generate.set_defaults(func=generate_command)

    validate = subparsers.add_parser("validate", help="validate an evidence.json file")
    validate.add_argument("evidence", type=Path)
    validate.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate.add_argument("--require-pass", action="store_true")
    validate.add_argument("--check-files", action="store_true")
    validate.add_argument(
        "--release-tier",
        choices=("alpha", "production"),
        default="production",
        help="alpha relaxes production-only signing, VEX, and runtime gates while keeping build/hardware evidence strict",
    )
    validate.set_defaults(func=validate_command)

    schema = subparsers.add_parser("schema", help="print the canonical evidence contract")
    schema.set_defaults(
        func=lambda _args: print(json.dumps(schema_contract(), indent=2, sort_keys=True)) or 0
    )

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
