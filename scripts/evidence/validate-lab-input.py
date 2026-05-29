#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate pre-release Suderra hardware lab input.

This is intentionally separate from final release evidence. Lab input is
collected before a tag exists, then the release workflow binds it to the
actual staged, signed, and attested release bytes.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = ROOT / "ci" / "build-matrix.yml"
SCHEMA_VERSION = "suderra.lab-evidence.v3"
STATION_BUNDLE_SCHEMA_VERSION = "suderra.lab-station-bundle.v1"
STATION_REGISTRY_SCHEMA_VERSION = "suderra.lab-station-registry.v1"
LEGACY_SCHEMA_VERSIONS = {"suderra.lab-evidence.v2"}
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STATUS_VALUES = {"passed", "failed", "not_run", "not_applicable", "not_collected"}
REQUIRED_DEVICE_FIELDS = (
    "board",
    "serial",
    "sku",
    "storage_serial",
    "uart_adapter",
    "power_supply",
    "boot_firmware",
    "operator",
    "tested_at",
)
REQUIRED_STATION_FIELDS = (
    "station_id",
    "fixture_id",
    "operator_id",
    "trusted_key_fingerprint",
    "clock",
)
REQUIRED_ARTIFACT_BINDING_FIELDS = (
    "version",
    "source_sha",
    "source_run_id",
    "build_artifact_sha256",
    "build_artifact_bytes",
)
REQUIRED_DEVICE_IDENTITY_FIELDS = (
    "model",
    "compatible",
    "storage_by_id",
    "storage_serial",
    "root_partuuid",
)
REQUIRED_LAB_CHECKS = (
    "board-identity",
    "artifact-hash",
    "flash-transcript",
    "full-readback-hash",
    "serial-boot-log",
    "post-install-boot",
    "partitions",
    "root-data-mounts",
    "network",
    "listeners",
    "failed-units",
    "thermal",
    "watchdog",
)
REQUIRED_USB_NEGATIVE_TESTS = (
    "no-target-disk",
    "ambiguous-targets",
    "usb-target-without-override",
    "tampered-payload",
    "bad-signature",
    "expired-manifest",
    "wrong-board",
    "small-target",
    "rollback-floor-violation",
)
REQUIRED_X86_HARDWARE_CHECKS = (
    "tpm-presence",
    "secure-boot-enforced",
    "rauc-rollback",
    "dm-verity-tamper-rejection",
    "boot-tamper-rejection",
    "power-cycle-transcript",
)
REQUIRED_X86_NEGATIVE_TESTS = (
    "dm-verity-rootfs-tamper",
    "secure-boot-unsigned-uki",
    "rauc-health-rollback",
)
REQUIRED_BOARDS_BY_TARGET = {
    "x86_64": ("industrial-x86_64",),
    "rpi4": ("raspberry-pi-4-model-b", "cm4-lite-sd", "cm4-emmc-io-board"),
    "pi-cm4-revpi-usb-installer": (
        "raspberry-pi-4-model-b",
        "cm4-lite-sd",
        "cm4-emmc-io-board",
        "revpi-connect-4",
    ),
    "revpi4": ("revpi-connect-4",),
}
STRICT_PROFILES = {"release-candidate", "production-candidate"}


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def is_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_string(errors: list[str], path: str, value: Any) -> None:
    if not is_string(value):
        error(errors, path, "must be a non-empty string")


def check_status(errors: list[str], path: str, value: Any) -> None:
    if value not in STATUS_VALUES:
        error(errors, path, f"must be one of: {', '.join(sorted(STATUS_VALUES))}")


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def check_sha256(errors: list[str], path: str, value: Any) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        error(errors, path, "must be a lowercase sha256 hex digest")


def check_relative_file(
    errors: list[str],
    root: Path,
    path: str,
    value: Any,
    check_files: bool,
    expected_sha256: str | None = None,
) -> None:
    if not is_string(value):
        error(errors, path, "must be a relative file path")
        return
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return
    actual = root / rel
    if check_files and (not actual.is_file() or actual.stat().st_size <= 0):
        error(errors, path, f"referenced file is missing or empty: {value}")
        return
    if check_files and expected_sha256 is not None and actual.is_file():
        actual_sha256 = sha256_file(actual)
        if actual_sha256 != expected_sha256:
            error(errors, path, f"referenced file sha256 mismatch: expected {expected_sha256}, got {actual_sha256}")


def resolve_relative_file(
    errors: list[str],
    root: Path,
    path: str,
    value: Any,
    check_files: bool,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
    allow_empty: bool = False,
) -> Path | None:
    if not is_string(value):
        error(errors, path, "must be a relative file path")
        return None
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        error(errors, path, "must be relative and must not contain '..'")
        return None
    actual = root / rel
    if not check_files:
        return actual
    if not actual.is_file() or (actual.stat().st_size <= 0 and not allow_empty):
        error(errors, path, f"referenced file is missing or empty: {value}")
        return actual
    if expected_bytes is not None and actual.stat().st_size != expected_bytes:
        error(
            errors,
            path,
            f"referenced file size mismatch: expected {expected_bytes}, got {actual.stat().st_size}",
        )
    if expected_sha256 is not None:
        actual_sha256 = sha256_file(actual)
        if actual_sha256 != expected_sha256:
            error(errors, path, f"referenced file sha256 mismatch: expected {expected_sha256}, got {actual_sha256}")
    return actual


def canonical_lab_payload(payload: dict[str, Any]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("station_bundle", None)
    unsigned.pop("station_signature", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def station_registry_entry(registry: dict[str, Any] | None, station_id: str | None) -> dict[str, Any] | None:
    if not isinstance(registry, dict) or not isinstance(station_id, str):
        return None
    stations = registry.get("stations")
    if not isinstance(stations, list):
        return None
    for item in stations:
        if isinstance(item, dict) and item.get("station_id") == station_id:
            return item
    return None


def check_station_registry(
    errors: list[str],
    payload: dict[str, Any],
    registry: dict[str, Any] | None,
    public_key_sha256: Any,
    profile: str,
) -> None:
    if not isinstance(registry, dict):
        error(errors, "$.station_registry", "strict lab input requires an external station registry")
        return
    if registry.get("schema_version") != STATION_REGISTRY_SCHEMA_VERSION:
        error(errors, "$.station_registry.schema_version", f"must be {STATION_REGISTRY_SCHEMA_VERSION}")
    station = payload.get("station") if isinstance(payload.get("station"), dict) else {}
    station_id = station.get("station_id")
    entry = station_registry_entry(registry, station_id if isinstance(station_id, str) else None)
    if entry is None:
        error(errors, "$.station.station_id", "must exist in external station registry")
        return
    if entry.get("fixture_id") != station.get("fixture_id"):
        error(errors, "$.station.fixture_id", "must match external station registry")
    if entry.get("public_key_sha256") != public_key_sha256:
        error(errors, "$.station_signature.public_key_sha256", "must match external station registry")
    allowed_targets = entry.get("allowed_targets")
    if isinstance(allowed_targets, list) and "*" not in allowed_targets and payload.get("target") not in allowed_targets:
        error(errors, "$.target", "must be allowed by external station registry")
    elif not isinstance(allowed_targets, list) or not allowed_targets:
        error(errors, "$.station_registry.allowed_targets", "must be a non-empty list")
    calibration_expires_at = entry.get("calibration_expires_at")
    calibration_expiry = parse_utc(calibration_expires_at)
    if calibration_expiry is None:
        error(errors, "$.station_registry.calibration_expires_at", "must be recorded")
    elif profile in STRICT_PROFILES and calibration_expiry <= datetime.now(timezone.utc):
        error(errors, "$.station_registry.calibration_expires_at", "must be in the future")
    if not isinstance(entry.get("adapter_inventory"), dict) or not entry["adapter_inventory"]:
        error(errors, "$.station_registry.adapter_inventory", "must be a non-empty object")
    operator_roles = entry.get("operator_roles")
    if profile in STRICT_PROFILES and (not isinstance(operator_roles, list) or not operator_roles):
        error(errors, "$.station_registry.operator_roles", "must be a non-empty list")
    allowed_storage = entry.get("allowed_storage_by_id")
    if not isinstance(allowed_storage, list) or not allowed_storage:
        error(errors, "$.station_registry.allowed_storage_by_id", "must be a non-empty list")
        allowed_storage = []
    devices = payload.get("devices")
    if isinstance(devices, list):
        for idx, device in enumerate(devices):
            if not isinstance(device, dict):
                continue
            identity = device.get("device_identity")
            storage_by_id = identity.get("storage_by_id") if isinstance(identity, dict) else None
            if isinstance(storage_by_id, str) and storage_by_id not in allowed_storage:
                error(errors, f"$.devices[{idx}].device_identity.storage_by_id", "must be allowed by station registry")


def check_station_bundle(
    errors: list[str],
    root: Path,
    payload: dict[str, Any],
    check_files: bool,
    profile: str,
    station_registry: dict[str, Any] | None,
) -> None:
    if profile not in STRICT_PROFILES:
        return
    station_bundle = payload.get("station_bundle")
    station_signature = payload.get("station_signature")
    if not isinstance(station_bundle, dict):
        error(errors, "$.station_bundle", "must be an object for release lab input")
        return
    if not isinstance(station_signature, dict):
        error(errors, "$.station_signature", "must be an object for release lab input")
        return

    if station_bundle.get("schema_version") != STATION_BUNDLE_SCHEMA_VERSION:
        error(
            errors,
            "$.station_bundle.schema_version",
            f"must be {STATION_BUNDLE_SCHEMA_VERSION}",
        )
    check_sha256(errors, "$.station_bundle.sha256", station_bundle.get("sha256"))
    if not isinstance(station_bundle.get("bytes"), int) or station_bundle.get("bytes", 0) <= 0:
        error(errors, "$.station_bundle.bytes", "must be a positive integer")
    bundle_path = resolve_relative_file(
        errors,
        root,
        "$.station_bundle.path",
        station_bundle.get("path"),
        check_files,
        station_bundle.get("sha256") if isinstance(station_bundle.get("sha256"), str) else None,
        station_bundle.get("bytes") if isinstance(station_bundle.get("bytes"), int) else None,
    )

    for field in ("algorithm", "signature", "public_key"):
        check_string(errors, f"$.station_signature.{field}", station_signature.get(field))
    if station_signature.get("algorithm") != "openssl-pkeyutl-ed25519-raw":
        error(
            errors,
            "$.station_signature.algorithm",
            "must be openssl-pkeyutl-ed25519-raw",
        )
    check_sha256(errors, "$.station_signature.signature_sha256", station_signature.get("signature_sha256"))
    check_sha256(errors, "$.station_signature.public_key_sha256", station_signature.get("public_key_sha256"))
    signature_path = resolve_relative_file(
        errors,
        root,
        "$.station_signature.signature",
        station_signature.get("signature"),
        check_files,
        station_signature.get("signature_sha256")
        if isinstance(station_signature.get("signature_sha256"), str)
        else None,
    )
    public_key_path = resolve_relative_file(
        errors,
        root,
        "$.station_signature.public_key",
        station_signature.get("public_key"),
        check_files,
        station_signature.get("public_key_sha256")
        if isinstance(station_signature.get("public_key_sha256"), str)
        else None,
    )

    station = payload.get("station") if isinstance(payload.get("station"), dict) else {}
    public_key_sha256 = station_signature.get("public_key_sha256")
    check_station_registry(errors, payload, station_registry, public_key_sha256, profile)
    trusted_key_fingerprint = station.get("trusted_key_fingerprint")
    if isinstance(public_key_sha256, str) and isinstance(trusted_key_fingerprint, str):
        if trusted_key_fingerprint not in {public_key_sha256, f"sha256:{public_key_sha256}"}:
            error(
                errors,
                "$.station.trusted_key_fingerprint",
                "must match station public key sha256",
            )

    if not check_files or bundle_path is None:
        return
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(errors, "$.station_bundle.path", f"cannot read station bundle JSON: {exc}")
        return
    if not isinstance(bundle, dict):
        error(errors, "$.station_bundle.path", "station bundle must be a JSON object")
        return
    if bundle.get("schema_version") != STATION_BUNDLE_SCHEMA_VERSION:
        error(errors, "$.station_bundle.path", f"station bundle schema must be {STATION_BUNDLE_SCHEMA_VERSION}")
    for field in ("version", "target", "lab_id"):
        if bundle.get(field) != payload.get(field):
            error(errors, f"$.station_bundle.{field}", f"must match top-level {field}")
    station_id = station.get("station_id") if isinstance(station, dict) else None
    if bundle.get("station_id") != station_id:
        error(errors, "$.station_bundle.station_id", "must match station.station_id")
    binding = payload.get("artifact_binding") if isinstance(payload.get("artifact_binding"), dict) else {}
    for field in ("source_sha", "source_run_id", "build_artifact_sha256", "build_artifact_bytes"):
        if bundle.get(field) != binding.get(field):
            error(errors, f"$.station_bundle.{field}", f"must match artifact_binding.{field}")
    expected_payload_sha = sha256_bytes(canonical_lab_payload(payload))
    if bundle.get("lab_payload_sha256") != expected_payload_sha:
        error(errors, "$.station_bundle.lab_payload_sha256", "must match unsigned lab payload")

    if signature_path is None or public_key_path is None:
        return
    if shutil.which("openssl") is None:
        error(errors, "$.station_signature", "openssl is required to verify station signature")
        return
    result = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-sigfile",
            str(signature_path),
            "-in",
            str(bundle_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        error(
            errors,
            "$.station_signature.signature",
            result.stderr.strip() or result.stdout.strip() or "station bundle signature verification failed",
        )


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


def release_targets_requiring_hardware(matrix: dict[str, Any]) -> list[str]:
    targets = []
    for row in matrix.get("defconfigs", []):
        if not row.get("release"):
            continue
        target = str(row.get("target", ""))
        acceptance = str(row.get("acceptance", ""))
        if row.get("production_required") or "hardware" in acceptance:
            targets.append(target)
    return targets


def expected_from_lab_path(path: Path) -> tuple[str | None, str | None]:
    parts = path.as_posix().split("/")
    if path.name != "lab.json" or "release-lab-input" not in parts:
        return None, None
    index = len(parts) - 1 - parts[::-1].index("release-lab-input")
    if len(parts) <= index + 3:
        return None, None
    return parts[index + 1], parts[index + 2]


def validate_lab(
    path: Path,
    check_files: bool,
    require_pass: bool,
    expected_version: str | None = None,
    expected_target: str | None = None,
    profile: str = "release-candidate",
    expected_source_sha: str | None = None,
    expected_source_run_id: str | None = None,
    station_registry_path: Path | None = None,
) -> list[str]:
    root = path.parent
    errors: list[str] = []
    inferred_version, inferred_target = expected_from_lab_path(path)
    expected_version = expected_version or inferred_version
    expected_target = expected_target or inferred_target
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"{path}: cannot read lab evidence: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]
    station_registry = read_json(station_registry_path) if station_registry_path is not None else None
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        if profile in STRICT_PROFILES or schema_version not in LEGACY_SCHEMA_VERSIONS:
            error(errors, "$.schema_version", f"must be {SCHEMA_VERSION}")
    for field in ("version", "target", "generated_at", "lab_id", "operator"):
        check_string(errors, f"$.{field}", payload.get(field))
    for field in ("version", "target"):
        value = payload.get(field)
        if isinstance(value, str) and not SAFE_ID_RE.fullmatch(value):
            error(errors, f"$.{field}", "must be a safe path identifier")
    if expected_version is not None and payload.get("version") != expected_version:
        error(errors, "$.version", f"must match lab evidence path version {expected_version}")
    if expected_target is not None and payload.get("target") != expected_target:
        error(errors, "$.target", f"must match lab evidence path target {expected_target}")
    is_v3 = schema_version == SCHEMA_VERSION
    if is_v3:
        station = payload.get("station")
        if not isinstance(station, dict):
            error(errors, "$.station", "must be an object")
        else:
            for field in REQUIRED_STATION_FIELDS:
                check_string(errors, f"$.station.{field}", station.get(field))
            if not isinstance(station.get("tool_versions"), dict) or not station["tool_versions"]:
                error(errors, "$.station.tool_versions", "must be a non-empty object")
        binding = payload.get("artifact_binding")
        if not isinstance(binding, dict):
            error(errors, "$.artifact_binding", "must be an object")
        else:
            for field in REQUIRED_ARTIFACT_BINDING_FIELDS:
                if field != "build_artifact_bytes":
                    check_string(errors, f"$.artifact_binding.{field}", binding.get(field))
            if binding.get("version") != payload.get("version"):
                error(errors, "$.artifact_binding.version", "must match top-level version")
            source_sha = binding.get("source_sha")
            if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
                error(errors, "$.artifact_binding.source_sha", "must be a lowercase git commit sha")
            elif expected_source_sha is not None and source_sha != expected_source_sha:
                error(errors, "$.artifact_binding.source_sha", f"must match bound source sha {expected_source_sha}")
            if expected_source_run_id is not None and str(binding.get("source_run_id")) != str(expected_source_run_id):
                error(
                    errors,
                    "$.artifact_binding.source_run_id",
                    f"must match bound source Image Build run {expected_source_run_id}",
                )
            check_sha256(errors, "$.artifact_binding.build_artifact_sha256", binding.get("build_artifact_sha256"))
            if not isinstance(binding.get("build_artifact_bytes"), int) or binding.get("build_artifact_bytes", 0) <= 0:
                error(errors, "$.artifact_binding.build_artifact_bytes", "must be a positive integer")
    devices = payload.get("devices")
    if not isinstance(devices, list) or not devices:
        error(errors, "$.devices", "must be a non-empty list")
        devices = []
    target = str(payload.get("target", ""))
    for idx, device in enumerate(devices):
        device_path = f"$.devices[{idx}]"
        if not isinstance(device, dict):
            error(errors, device_path, "must be an object")
            continue
        for field in REQUIRED_DEVICE_FIELDS:
            check_string(errors, f"{device_path}.{field}", device.get(field))
        if is_v3:
            identity = device.get("device_identity")
            if not isinstance(identity, dict):
                error(errors, f"{device_path}.device_identity", "must be an object")
            else:
                for field in REQUIRED_DEVICE_IDENTITY_FIELDS:
                    check_string(errors, f"{device_path}.device_identity.{field}", identity.get(field))
            readback = device.get("readback")
            if not isinstance(readback, dict):
                error(errors, f"{device_path}.readback", "must be an object")
            else:
                if readback.get("scope") != "full":
                    error(errors, f"{device_path}.readback.scope", "must be full for release lab input")
                expected_sha = readback.get("expected_sha256")
                actual_sha = readback.get("actual_sha256")
                check_sha256(errors, f"{device_path}.readback.expected_sha256", expected_sha)
                check_sha256(errors, f"{device_path}.readback.actual_sha256", actual_sha)
                if isinstance(expected_sha, str) and isinstance(actual_sha, str) and expected_sha != actual_sha:
                    error(errors, f"{device_path}.readback.actual_sha256", "must match expected_sha256")
                if not isinstance(readback.get("bytes_read"), int) or readback.get("bytes_read", 0) <= 0:
                    error(errors, f"{device_path}.readback.bytes_read", "must be a positive integer")
                if profile in STRICT_PROFILES and isinstance(binding, dict):
                    bound_sha = binding.get("build_artifact_sha256")
                    bound_bytes = binding.get("build_artifact_bytes")
                    if isinstance(bound_sha, str) and expected_sha != bound_sha:
                        error(
                            errors,
                            f"{device_path}.readback.expected_sha256",
                            "must match bound build artifact sha256",
                        )
                    if isinstance(bound_bytes, int) and readback.get("bytes_read") != bound_bytes:
                        error(errors, f"{device_path}.readback.bytes_read", "must match bound build artifact bytes")
        check_status(errors, f"{device_path}.status", device.get("status"))
        if require_pass and device.get("status") != "passed":
            error(errors, f"{device_path}.status", "must be passed for release lab input")
        logs = device.get("logs")
        if not isinstance(logs, list) or not logs:
            error(errors, f"{device_path}.logs", "must be a non-empty list")
        else:
            for log_idx, log in enumerate(logs):
                if isinstance(log, dict):
                    check_relative_file(
                        errors,
                        root,
                        f"{device_path}.logs[{log_idx}].path",
                        log.get("path"),
                        check_files,
                        log.get("sha256") if isinstance(log.get("sha256"), str) else None,
                    )
                    check_sha256(errors, f"{device_path}.logs[{log_idx}].sha256", log.get("sha256"))
                else:
                    check_relative_file(errors, root, f"{device_path}.logs[{log_idx}]", log, check_files)
        checks = device.get("checks")
        if not isinstance(checks, dict):
            error(errors, f"{device_path}.checks", "must be an object")
            checks = {}
        missing_checks = sorted(set(REQUIRED_LAB_CHECKS) - set(checks))
        if target == "x86_64":
            missing_checks = sorted(set(missing_checks) | (set(REQUIRED_X86_HARDWARE_CHECKS) - set(checks)))
        if missing_checks:
            error(errors, f"{device_path}.checks", f"missing required checks: {', '.join(missing_checks)}")
        if device.get("board") == "revpi-connect-4" and "revpi-io" not in checks:
            error(errors, f"{device_path}.checks", "revpi-connect-4 requires revpi-io check")
        for check_name, check in checks.items():
            check_path = f"{device_path}.checks.{check_name}"
            if not isinstance(check, dict):
                error(errors, check_path, "must be an object")
                continue
            check_status(errors, f"{check_path}.status", check.get("status"))
            check_relative_file(
                errors,
                root,
                f"{check_path}.evidence",
                check.get("evidence"),
                check_files,
                check.get("evidence_sha256") if isinstance(check.get("evidence_sha256"), str) else None,
            )
            if is_v3:
                for field in ("command", "expected", "observed", "parsed_result"):
                    check_string(errors, f"{check_path}.{field}", check.get(field))
                if "evidence_sha256" in check:
                    check_sha256(errors, f"{check_path}.evidence_sha256", check.get("evidence_sha256"))
            if require_pass and check.get("status") != "passed":
                error(errors, f"{check_path}.status", "must be passed for release lab input")
    required_boards = REQUIRED_BOARDS_BY_TARGET.get(target, ())
    if required_boards:
        seen = {
            device.get("board")
            for device in devices
            if isinstance(device, dict) and isinstance(device.get("board"), str)
        }
        missing = sorted(set(required_boards) - seen)
        if missing:
            error(errors, "$.devices", f"missing required board evidence: {', '.join(missing)}")
    negative_tests = payload.get("negative_tests")
    if not isinstance(negative_tests, list):
        error(errors, "$.negative_tests", "must be a list")
        negative_tests = []
    if target == "pi-cm4-revpi-usb-installer":
        names = {
            item.get("name")
            for item in negative_tests
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        missing = sorted(set(REQUIRED_USB_NEGATIVE_TESTS) - names)
        if missing:
            error(errors, "$.negative_tests", f"missing required negative tests: {', '.join(missing)}")
    if target == "x86_64" and profile == "production-candidate":
        names = {
            item.get("name")
            for item in negative_tests
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        missing = sorted(set(REQUIRED_X86_NEGATIVE_TESTS) - names)
        if missing:
            error(errors, "$.negative_tests", f"missing required x86 negative tests: {', '.join(missing)}")
    seen_negative_tests: set[str] = set()
    allowed_negative_tests = set(REQUIRED_USB_NEGATIVE_TESTS) if target == "pi-cm4-revpi-usb-installer" else None
    for idx, item in enumerate(negative_tests):
        item_path = f"$.negative_tests[{idx}]"
        if not isinstance(item, dict):
            error(errors, item_path, "must be an object")
            continue
        check_string(errors, f"{item_path}.name", item.get("name"))
        name = item.get("name")
        if isinstance(name, str):
            if name in seen_negative_tests:
                error(errors, f"{item_path}.name", "must be unique")
            seen_negative_tests.add(name)
            if allowed_negative_tests is not None and name not in allowed_negative_tests:
                error(errors, f"{item_path}.name", "must be a known required USB negative test")
        check_string(errors, f"{item_path}.failure_code", item.get("failure_code"))
        check_status(errors, f"{item_path}.status", item.get("status"))
        if is_v3:
            for field in ("command", "expected", "observed"):
                check_string(errors, f"{item_path}.{field}", item.get(field))
            if not isinstance(item.get("exit_code"), int):
                error(errors, f"{item_path}.exit_code", "must be an integer")
        check_relative_file(
            errors,
            root,
            f"{item_path}.evidence",
            item.get("evidence"),
            check_files,
            item.get("evidence_sha256") if isinstance(item.get("evidence_sha256"), str) else None,
        )
        if is_v3:
            write_prevention = item.get("write_prevention")
            if not isinstance(write_prevention, dict):
                error(errors, f"{item_path}.write_prevention", "must be an object")
            elif write_prevention.get("target_hash_unchanged") is not True:
                error(errors, f"{item_path}.write_prevention.target_hash_unchanged", "must be true")
            else:
                check_sha256(
                    errors,
                    f"{item_path}.write_prevention.before_sha256",
                    write_prevention.get("before_sha256"),
                )
                check_sha256(errors, f"{item_path}.write_prevention.after_sha256", write_prevention.get("after_sha256"))
                if write_prevention.get("before_sha256") != write_prevention.get("after_sha256"):
                    error(errors, f"{item_path}.write_prevention.after_sha256", "must match before_sha256")
                if (
                    not isinstance(write_prevention.get("bytes_checked"), int)
                    or write_prevention.get("bytes_checked", 0) <= 0
                ):
                    error(errors, f"{item_path}.write_prevention.bytes_checked", "must be a positive integer")
        if require_pass and item.get("status") != "passed":
            error(errors, f"{item_path}.status", "must be passed for release lab input")
    if is_v3:
        check_station_bundle(errors, root, payload, check_files, profile, station_registry)
    return errors


def validate_command(args: argparse.Namespace) -> int:
    errors = validate_lab(
        args.input,
        args.check_files,
        args.require_pass,
        args.expected_version,
        args.expected_target,
        args.profile,
        args.expected_source_sha,
        args.expected_source_run_id,
        args.station_registry,
    )
    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated lab evidence: {args.input}")
    return 0


def validate_matrix_command(args: argparse.Namespace) -> int:
    matrix = load_matrix(args.matrix)
    failures: list[str] = []
    for target in release_targets_requiring_hardware(matrix):
        evidence = args.root / args.version / target / "lab.json"
        failures.extend(
            validate_lab(
                evidence,
                args.check_files,
                args.require_pass,
                args.version,
                target,
                args.profile,
                args.expected_source_sha,
                args.expected_source_run_id,
                args.station_registry,
            )
        )
    if failures:
        for item in failures:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1
    print(f"validated release lab input for {args.version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--require-pass", action="store_true")
    validate.add_argument("--check-files", action="store_true")
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-target")
    validate.add_argument("--expected-source-sha")
    validate.add_argument("--expected-source-run-id")
    validate.add_argument("--station-registry", type=Path)
    validate.add_argument(
        "--profile",
        choices=("technical-dry-run", "release-candidate", "production-candidate"),
        default="release-candidate",
    )
    validate.set_defaults(func=validate_command)
    validate_matrix = subparsers.add_parser("validate-matrix")
    validate_matrix.add_argument("--version", required=True)
    validate_matrix.add_argument("--root", type=Path, default=Path("release-lab-input"))
    validate_matrix.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    validate_matrix.add_argument("--require-pass", action="store_true")
    validate_matrix.add_argument("--check-files", action="store_true")
    validate_matrix.add_argument("--expected-source-sha")
    validate_matrix.add_argument("--expected-source-run-id")
    validate_matrix.add_argument("--station-registry", type=Path)
    validate_matrix.add_argument(
        "--profile",
        choices=("technical-dry-run", "release-candidate", "production-candidate"),
        default="release-candidate",
    )
    validate_matrix.set_defaults(func=validate_matrix_command)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
