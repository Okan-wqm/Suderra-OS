#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Derive per-scenario mutation producer inputs from a built prod-ab image.

The production-runtime suite (PR-B4) needs real inputs for each negative
scenario's mutation: the ESP byte offset (to replace the boot UKI), the rootfs
byte offset (to tamper a data block), the signed UKI + kernel/stub/initrd/
cmdline (to rebuild a bad-roothash UKI), signing keys, and the rollback floor.
This tool computes them from the built image + Buildroot output and emits the
mutation_inputs JSON consumed by ``evidence_contract.py runtime-plan
--mutation-inputs-file``. It runs in the production-runtime workflow where the
built image and keys exist; it never fabricates paths — a missing required
artifact is a hard error.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# GPT type GUID for an EFI System Partition.
ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def _partitions(image: Path) -> tuple[int, list[dict[str, Any]]]:
    out = subprocess.run(
        ["sfdisk", "-J", str(image)],
        check=True, capture_output=True, text=True,
    ).stdout
    table = json.loads(out)["partitiontable"]
    sector = int(table.get("sectorsize", 512))
    return sector, list(table.get("partitions", []))


def _find(parts: list[dict[str, Any]], *, type_guid: str | None = None, name_substrings: tuple[str, ...] = ()) -> dict[str, Any]:
    for part in parts:
        if type_guid and str(part.get("type", "")).upper() == type_guid.upper():
            return part
        name = str(part.get("name", "")).lower()
        if name and any(sub in name for sub in name_substrings):
            return part
    raise RuntimeError(f"no partition matching type={type_guid} names={name_substrings}")


def _need(path: Path, what: str) -> Path:
    if not path.exists():
        raise RuntimeError(f"{what} not found: {path}")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", type=Path, required=True, help="built disk.img")
    ap.add_argument("--binaries-dir", type=Path, required=True, help="Buildroot images/ dir")
    ap.add_argument("--keys-dir", type=Path, required=True, help="signing keys dir")
    ap.add_argument("--swtpm-state", type=Path, required=True)
    ap.add_argument("--rollback-floor", required=True, help="current anti-rollback floor version")
    ap.add_argument("--downgrade-version", required=True, help="version below floor to attempt")
    ap.add_argument("--package", default="suderra-os")
    ap.add_argument("--active-slot", default="A", choices=["A", "B"])
    ap.add_argument("--esp-uki-dest", default="/EFI/SUDERRA/suderra-A.efi")
    ap.add_argument("--bundle-tool", type=Path, default=Path("scripts/create-rauc-bundle.sh"))
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    _need(args.image, "disk image")
    sector, parts = _partitions(args.image)
    esp = _find(parts, type_guid=ESP_TYPE_GUID, name_substrings=("efi", "esp", "boot"))
    rootfs = _find(parts, name_substrings=(f"rootfs-{args.active_slot.lower()}", "rootfs"))
    esp_offset = int(esp["start"]) * sector
    rootfs_offset = int(rootfs["start"]) * sector
    # Tamper a block well inside the rootfs payload (past the superblock).
    rootfs_tamper_offset = rootfs_offset + (1 << 20)

    b = args.binaries_dir
    k = args.keys_dir
    slot = args.active_slot
    signed_uki = _need(b / f"suderra-{slot}.efi", "signed slot UKI")
    stub = _need(b / "linuxx64.efi.stub", "UKI stub")
    kernel = _need(b / "bzImage", "kernel")
    osrel = _need(b / "os-release", "os-release") if (b / "os-release").exists() else _need(Path("board/suderra/x86_64/os-release"), "os-release")
    initrd = _need(b / f"suderra-{slot}.initrd", "slot initrd")
    real_cmdline = _need(b / f"suderra-{slot}.cmdline", "slot cmdline")
    sign_key = _need(k / "uefi-db.key", "Secure Boot signing key")
    sign_cert = _need(k / "uefi-db.crt", "Secure Boot signing cert")
    ota_key = _need(k / "os-update-manifest.key", "OS update signing key")

    # Build a tampered cmdline: keep everything but corrupt the verity roothash.
    tampered_cmdline = args.output.parent / "cmdline.tampered"
    text = real_cmdline.read_text(encoding="utf-8", errors="replace")
    tampered = []
    for token in text.split():
        if token.startswith("suderra.verity.root_hash="):
            tampered.append("suderra.verity.root_hash=" + ("0" * 64))
        else:
            tampered.append(token)
    tampered_cmdline.write_text(" ".join(tampered) + "\n", encoding="utf-8")

    uki_common = {
        "image": str(args.image),
        "esp_offset": esp_offset,
        "esp_dest": args.esp_uki_dest,
    }
    mutation_inputs = {
        "unsigned-boot-rejection": {"signed_uki": str(signed_uki), **uki_common},
        "cmdline-tamper-rejection": {
            "stub": str(stub), "kernel": str(kernel), "osrel": str(osrel),
            "initrd": str(initrd), "cmdline_tampered": str(tampered_cmdline),
            "sign_key": str(sign_key), "sign_cert": str(sign_cert), **uki_common,
        },
        "dm-verity-rootfs-tamper-rejection": {
            "image": str(args.image), "offset": rootfs_tamper_offset,
            "length": 4096, "before_source": str(args.image),
        },
        "anti-rollback-downgrade-rejection": {
            "package": args.package, "downgrade_version": args.downgrade_version,
            "rollback_floor": args.rollback_floor, "sign_key": str(ota_key),
        },
        "data-luks-swtpm": {"swtpm_state": str(args.swtpm_state)},
        "rauc-good-update": {"bundle_tool": str(args.bundle_tool)},
        "rauc-bad-signature-rejection": {"bundle_tool": str(args.bundle_tool)},
        "rauc-health-rollback": {"bundle_tool": str(args.bundle_tool)},
    }
    args.output.write_text(json.dumps(mutation_inputs, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote mutation inputs: {args.output} (esp_offset={esp_offset} rootfs_offset={rootfs_offset})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
