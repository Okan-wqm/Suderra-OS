#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Assemble the RPi4/RevPi4 USB installer from a prebuilt base artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IMAGE_NAME = "suderra-pi-cm4-revpi-usb-installer.img"
SCHEMA_VERSION = "suderra.usb-installer-payload-package.v1"
BASE_SCHEMA_VERSION = "suderra.usb-installer-base.v1"
PAYLOAD_INPUTS_SCHEMA_VERSION = "suderra.payload-inputs.v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def xz_uncompressed_identity(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with lzma.open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def timestamp_from_epoch(epoch: str | None) -> str:
    if epoch:
        try:
            value = int(epoch)
        except ValueError as exc:
            raise SystemExit(f"SOURCE_DATE_EPOCH must be an integer, got {epoch!r}") from exc
        return datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_iso8601_z(value: str, field: str) -> None:
    if not value.endswith("Z"):
        raise SystemExit(f"{field} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SystemExit(f"{field} must be an ISO-8601 UTC timestamp") from exc


def load_base_manifest(path: Path, base_dir: Path, public_key: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict) or payload.get("schema_version") != BASE_SCHEMA_VERSION:
        raise SystemExit(f"base manifest schema_version must be {BASE_SCHEMA_VERSION}: {path}")
    files = payload.get("files")
    if not isinstance(files, list):
        raise SystemExit("base manifest files must be a list")
    by_role = {item.get("role"): item for item in files if isinstance(item, dict)}
    for role, name in (("boot-vfat", "boot.vfat"), ("rootfs-ext4", "rootfs.ext4")):
        item = by_role.get(role)
        if not isinstance(item, dict):
            raise SystemExit(f"base manifest missing {role}")
        candidate = base_dir / name
        if not candidate.is_file() or candidate.stat().st_size <= 0:
            raise SystemExit(f"base file missing or empty: {candidate}")
        if item.get("bytes") != candidate.stat().st_size:
            raise SystemExit(f"base file size mismatch: {candidate}")
        if item.get("sha256") != sha256_file(candidate):
            raise SystemExit(f"base file sha mismatch: {candidate}")
    key = payload.get("installer_payload_public_key")
    if not isinstance(key, dict) or key.get("sha256") != sha256_file(public_key):
        raise SystemExit("base manifest public key digest does not match payload signing public key")
    return payload


def load_payload_inputs_manifest(path: Path, rpi4_image: Path, revpi4_image: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict) or payload.get("schema_version") != PAYLOAD_INPUTS_SCHEMA_VERSION:
        raise SystemExit(f"payload inputs schema_version must be {PAYLOAD_INPUTS_SCHEMA_VERSION}: {path}")
    inputs = payload.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise SystemExit("payload inputs manifest must contain inputs")
    expected = {
        "suderra-rpi4-target.img.xz": rpi4_image,
        "suderra-revpi4-target.img.xz": revpi4_image,
    }
    by_artifact = {
        item.get("artifact"): item
        for item in inputs
        if isinstance(item, dict) and isinstance(item.get("artifact"), str)
    }
    for artifact, source in expected.items():
        item = by_artifact.get(artifact)
        if not isinstance(item, dict):
            raise SystemExit(f"payload inputs manifest missing {artifact}")
        if not source.is_file() or source.stat().st_size <= 0:
            raise SystemExit(f"payload input missing or empty: {source}")
        if item.get("bytes") != source.stat().st_size:
            raise SystemExit(f"payload input size mismatch: {source}")
        if item.get("sha256") != sha256_file(source):
            raise SystemExit(f"payload input sha mismatch: {source}")
    return payload


def install_or_link(source: Path, destination: Path) -> None:
    destination.unlink(missing_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)


def payload_entry(
    *,
    name: str,
    board_family: str,
    image_path: str,
    source: Path,
    rollback_floor: str,
) -> dict[str, Any]:
    uncompressed_sha, uncompressed_size = xz_uncompressed_identity(source)
    return {
        "name": name,
        "board_family": board_family,
        "compatible_models": [board_family],
        "arch": "aarch64",
        "image_path": image_path,
        "compressed_sha256": sha256_file(source),
        "compressed_size_bytes": source.stat().st_size,
        "uncompressed_sha256": uncompressed_sha,
        "uncompressed_size_bytes": uncompressed_size,
        "min_storage_bytes": 8589934592,
        "rollback_floor": rollback_floor,
    }


def clean_known_outputs(output_dir: Path) -> None:
    for name in (
        "boot.vfat",
        "rootfs.ext4",
        "payload.ext4",
        IMAGE_NAME,
        f"{IMAGE_NAME}.xz",
        "MANIFEST.txt",
        "manifest.json",
        "manifest.sig",
        "manifest.canonical",
        "suderra-rpi4-target.img.xz",
        "suderra-revpi4-target.img.xz",
    ):
        (output_dir / name).unlink(missing_ok=True)
    shutil.rmtree(output_dir / "installer-payload-root", ignore_errors=True)
    shutil.rmtree(output_dir / "genimage.tmp", ignore_errors=True)


def assemble(args: argparse.Namespace) -> None:
    start = time.monotonic()
    if args.key_epoch <= 0:
        raise SystemExit("--key-epoch must be positive")
    validate_iso8601_z(args.expires_at, "--expires-at")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    clean_known_outputs(args.output_dir)

    base_boot = args.base_dir / "boot.vfat"
    base_rootfs = args.base_dir / "rootfs.ext4"
    for required in (base_boot, base_rootfs, args.rpi4_image, args.revpi4_image, args.sign_key, args.public_key):
        if not required.is_file() or required.stat().st_size <= 0:
            raise SystemExit(f"required input missing or empty: {required}")
    if not args.genimage_cfg.is_file():
        raise SystemExit(f"genimage config missing: {args.genimage_cfg}")
    base_manifest = load_base_manifest(args.base_manifest, args.base_dir, args.public_key)
    payload_inputs_manifest = load_payload_inputs_manifest(args.payload_inputs_manifest, args.rpi4_image, args.revpi4_image)

    shutil.copyfile(base_boot, args.output_dir / "boot.vfat")
    shutil.copyfile(base_rootfs, args.output_dir / "rootfs.ext4")
    shutil.copyfile(args.rpi4_image, args.output_dir / "suderra-rpi4-target.img.xz")
    shutil.copyfile(args.revpi4_image, args.output_dir / "suderra-revpi4-target.img.xz")

    manifest = {
        "schema_version": 1,
        "kind": "suderra.usb-payload-index.v1",
        "board_family": "pi-cm4-revpi",
        "compatible_models": ["rpi4-cm4", "revpi4"],
        "payloads": [
            payload_entry(
                name="rpi4-cm4",
                board_family="rpi4-cm4",
                image_path="suderra-rpi4-target.img.xz",
                source=args.output_dir / "suderra-rpi4-target.img.xz",
                rollback_floor=args.rollback_floor,
            ),
            payload_entry(
                name="revpi4",
                board_family="revpi4",
                image_path="suderra-revpi4-target.img.xz",
                source=args.output_dir / "suderra-revpi4-target.img.xz",
                rollback_floor=args.rollback_floor,
            ),
        ],
        "created_at": timestamp_from_epoch(args.source_date_epoch),
        "expires_at": args.expires_at,
        "key_epoch": args.key_epoch,
    }
    manifest_path = args.output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    canonical_path = args.output_dir / "manifest.canonical"
    canonical_path.write_bytes(canonical)
    sig_path = args.output_dir / "manifest.sig"
    run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(args.sign_key),
            "-in",
            str(canonical_path),
            "-out",
            str(sig_path),
        ]
    )
    run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(args.public_key),
            "-sigfile",
            str(sig_path),
            "-in",
            str(canonical_path),
        ]
    )
    canonical_path.unlink()

    payload_root = args.output_dir / "installer-payload-root"
    payload_root.mkdir(mode=0o755, exist_ok=True)
    for name in ("suderra-rpi4-target.img.xz", "suderra-revpi4-target.img.xz", "manifest.json", "manifest.sig"):
        install_or_link(args.output_dir / name, payload_root / name)

    genimage_tmp = args.output_dir / "genimage.tmp"
    shutil.rmtree(genimage_tmp, ignore_errors=True)
    run(
        [
            "genimage",
            "--config",
            str(args.genimage_cfg),
            "--rootpath",
            str(payload_root),
            "--inputpath",
            str(args.output_dir),
            "--outputpath",
            str(args.output_dir),
            "--tmppath",
            str(genimage_tmp),
        ]
    )
    image_path = args.output_dir / IMAGE_NAME
    if not image_path.is_file() or image_path.stat().st_size <= 0:
        raise SystemExit(f"final installer image was not created: {image_path}")
    run(["xz", "-k", "-T0", "-9", "-f", str(image_path)])
    xz_path = args.output_dir / f"{IMAGE_NAME}.xz"

    manifest_text = "\n".join(
        [
            "# Suderra OS — release manifest",
            f"# Build: {timestamp_from_epoch(args.source_date_epoch)}",
            "# Defconfig: suderra_aarch64_rpi4_usb_installer",
            "# Arch: aarch64",
            "",
            "# SHA256 checksums:",
            f"{sha256_file(image_path)}  {IMAGE_NAME}",
            f"{sha256_file(xz_path)}  {IMAGE_NAME}.xz",
            "",
        ]
    )
    (args.output_dir / "MANIFEST.txt").write_text(manifest_text, encoding="utf-8")

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "image": {
            "path": IMAGE_NAME,
            "sha256": sha256_file(image_path),
            "bytes": image_path.stat().st_size,
        },
        "compressed_image": {
            "path": f"{IMAGE_NAME}.xz",
            "sha256": sha256_file(xz_path),
            "bytes": xz_path.stat().st_size,
        },
        "base_manifest_sha256": sha256_file(args.base_manifest),
        "payload_inputs_sha256": payload_inputs_manifest["inputs_sha256"],
        "payload_inputs_manifest_sha256": sha256_file(args.payload_inputs_manifest),
        "installer_payload_public_key_sha256": sha256_file(args.public_key),
        "base": {
            "manifest_identity_digest": base_manifest["identity_digest"],
            "boot_vfat_sha256": sha256_file(args.output_dir / "boot.vfat"),
            "rootfs_ext4_sha256": sha256_file(args.output_dir / "rootfs.ext4"),
        },
        "payload_inputs": payload_inputs_manifest["inputs"],
        "payload_manifest": {
            "sha256": sha256_file(manifest_path),
            "signature_sha256": sha256_file(sig_path),
        },
        "partition_digest_map": {
            "boot.vfat": sha256_file(args.output_dir / "boot.vfat"),
            "rootfs.ext4": sha256_file(args.output_dir / "rootfs.ext4"),
            "payload.ext4": sha256_file(args.output_dir / "payload.ext4"),
        },
        "duration_seconds": round(time.monotonic() - start, 3),
    }
    if args.evidence_output is not None:
        args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--payload-inputs-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--genimage-cfg", type=Path, required=True)
    parser.add_argument("--rpi4-image", type=Path, required=True)
    parser.add_argument("--revpi4-image", type=Path, required=True)
    parser.add_argument("--sign-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--key-epoch", type=int, required=True)
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--rollback-floor", default="v0.1.0-alpha")
    parser.add_argument("--evidence-output", type=Path)
    assemble(parser.parse_args())


if __name__ == "__main__":
    main()
