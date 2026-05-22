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
    args.output_dir.mkdir(parents=True, exist_ok=True)
    clean_known_outputs(args.output_dir)

    base_boot = args.base_dir / "boot.vfat"
    base_rootfs = args.base_dir / "rootfs.ext4"
    for required in (base_boot, base_rootfs, args.rpi4_image, args.revpi4_image, args.sign_key, args.public_key):
        if not required.is_file() or required.stat().st_size <= 0:
            raise SystemExit(f"required input missing or empty: {required}")
    if not args.genimage_cfg.is_file():
        raise SystemExit(f"genimage config missing: {args.genimage_cfg}")

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
        "base": {
            "boot_vfat_sha256": sha256_file(args.output_dir / "boot.vfat"),
            "rootfs_ext4_sha256": sha256_file(args.output_dir / "rootfs.ext4"),
        },
        "payload_manifest": {
            "sha256": sha256_file(manifest_path),
            "signature_sha256": sha256_file(sig_path),
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
