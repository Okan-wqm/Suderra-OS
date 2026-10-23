#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Pin the edge keys of a trust-root set into the image (ADR-048 DEC-3.4, DEC-3.9).

The root installer verifies edge-release, edge-provisioning, trust-anchors
and device-lifecycle statements only against keys pinned on the verity
rootfs at /etc/suderra/keys/<purpose>/<epoch>.pub. This installs them from
<trust-roots>/edge/<purpose>/<epoch>.pub (scripts/ci/edge-dev-keys.py).

* dev images and every image of a `ci`-role board (the QEMU targets,
  production variant included) pin the dev/CI keys of the set: the same
  board-role rule as the root installer's PinPolicy
  (userspace/suderra-installer/src/trust_anchors.rs). Every os-image purpose
  must be present, each file an Ed25519 SubjectPublicKeyInfo, no key shared
  by two purposes. These images also carry the set's dev provisioning-API CA
  (edge/cloud-ca/ca.crt) as /etc/suderra/cloud-ca.pem, which the QEMU fake
  cloud's https certificate chains to.
* production images of hardware boards (and boardless production images)
  pin only keyids the key ceremony records in the inventory table of
  docs/security/key-management.md (--inventory; package/suderra-keys/
  edge_key_inventory.py reads it). Every key of the trust-root set must be
  the keyid recorded for its purpose and epoch, the dev/CI keys never are,
  and a set that carries edge keys while the table records none fails. An
  image whose trust-root set carries no edge key pins none (its installer
  then provisions nothing). Production images carry no cloud CA (the
  provisioning API is verified against the public roots only).

The contract's TEST-ONLY keys are refused before this runs
(scripts/ci/check-no-contract-test-keys.py in suderra-keys.mk).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

OS_PINNED = ("edge-release", "edge-provisioning", "fleet-root", "device-lifecycle")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
EPOCH_FILE = re.compile(r"^[1-9][0-9]{0,4}\.pub$")


def raw_key(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise ValueError(f"{path}: not a PEM PUBLIC KEY block")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise ValueError(f"{path}: not an Ed25519 SubjectPublicKeyInfo")
    return der[len(SPKI_PREFIX):]


def board_role(boards: Path, defconfig: str) -> str | None:
    """The boards.json role of the board `defconfig` builds; None when it
    declares no board. A defconfig boards.json does not classify fails."""
    data = json.loads(boards.read_text(encoding="utf-8"))
    rows = [b for b in data["boards"] if any(i["defconfig"] == defconfig for i in b["os_images"])]
    boardless = [f for f in data["pending_board_families"]
                 if any(i["defconfig"] == defconfig for i in f["os_images"])]
    boardless += [e for e in data["excluded_os_images"] if e["defconfig"] == defconfig]
    if len(rows) + len(boardless) != 1:
        raise ValueError(f"{defconfig} is classified {len(rows) + len(boardless)} times in {boards}")
    return rows[0]["role"] if rows else None


def load_inventory_module():
    """edge_key_inventory.py beside this file (run with -I, so by path)."""
    path = Path(__file__).resolve().with_name("edge_key_inventory.py")
    spec = importlib.util.spec_from_file_location("edge_key_inventory", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage_pins(edge: Path, pins: Path, missing_hint: str) -> list[tuple[Path, Path, str, str, int]]:
    """Every <purpose>/<epoch>.pub of the os-image purposes: (source, destination, keyid, purpose, epoch).

    Every purpose needs a key, each file an Ed25519 SubjectPublicKeyInfo, and
    no key serves two purposes (ADR-048 DEC-3.3)."""
    seen: dict[bytes, str] = {}
    staged: list[tuple[Path, Path, str, str, int]] = []
    for purpose in OS_PINNED:
        source = edge / purpose
        files = sorted(p for p in source.glob("*.pub")) if source.is_dir() else []
        if not files:
            raise ValueError(f"{source}: no <epoch>.pub ({missing_hint})")
        for f in files:
            if not EPOCH_FILE.match(f.name):
                raise ValueError(f"{f}: not <epoch>.pub")
            raw = raw_key(f)
            if raw in seen:
                raise ValueError(
                    f"{f} is the {seen[raw]} key; every purpose has its own key (ADR-048 DEC-3.3)"
                )
            seen[raw] = f"{purpose}/{f.name}"
            staged.append(
                (f, pins / purpose / f.name, hashlib.sha256(raw).hexdigest(), purpose, int(f.stem))
            )
    return staged


def install_pins(staged: list[tuple[Path, Path, str, str, int]], pins: Path, target: Path) -> None:
    for source, dest, keyid, _purpose, _epoch in staged:
        dest.parent.mkdir(parents=True, exist_ok=True)
        for d in (pins, dest.parent):
            d.chmod(0o755)
        shutil.copyfile(source, dest)
        dest.chmod(0o644)
        print(f"suderra-keys: pinned {dest.relative_to(target)} keyid {keyid}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--trust-roots", type=Path, required=True)
    ap.add_argument("--target", type=Path, required=True)
    ap.add_argument("--variant", choices=("dev", "prod"), required=True)
    ap.add_argument("--defconfig", required=True, help="e.g. suderra_qemu_x86_64_defconfig")
    ap.add_argument("--boards", type=Path, required=True, help="the vendored contract's boards.json")
    ap.add_argument(
        "--inventory", type=Path, required=True, help="docs/security/key-management.md, the key inventory"
    )
    args = ap.parse_args()

    try:
        role = board_role(args.boards, args.defconfig)
    except (OSError, ValueError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    edge = args.trust_roots / "edge"
    pins = args.target / "etc/suderra/keys"
    cloud_ca = args.target / "etc/suderra/cloud-ca.pem"
    if pins.exists():
        shutil.rmtree(pins)
    cloud_ca.unlink(missing_ok=True)

    if args.variant == "prod" and role != "ci":
        if not edge.exists():
            print("suderra-keys: production image, no edge key pinned (the trust-root set has none)")
            return 0
        inventory = load_inventory_module()
        try:
            recorded = inventory.recorded(args.inventory, args.boards.parent)
        except (inventory.InventoryError, OSError, KeyError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        if not any(purpose in OS_PINNED for purpose, _epoch in recorded):
            print(
                f"ERROR: {edge}: a production image pins only keyids the key ceremony inventories "
                "(ADR-048 DEC-3.9), and none is inventoried yet",
                file=sys.stderr,
            )
            return 1
        try:
            staged = stage_pins(
                edge, pins, "export the ceremony's public keys to <trust-roots>/edge/<purpose>/<epoch>.pub"
            )
        except (ValueError, UnicodeDecodeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        for source, _dest, keyid, purpose, epoch in staged:
            if recorded.get((purpose, epoch)) != keyid:
                print(
                    f"ERROR: {source}: key {keyid} is not the keyid the inventory records for "
                    f"{purpose}/{epoch} ({recorded.get((purpose, epoch), 'none')}); a production image "
                    "pins only inventoried keys (ADR-048 DEC-3.9)",
                    file=sys.stderr,
                )
                return 1
        install_pins(staged, pins, args.target)
        return 0

    ca_source = edge / "cloud-ca" / "ca.crt"
    if not ca_source.is_file() or not ca_source.read_text(encoding="ascii").startswith(
        "-----BEGIN CERTIFICATE-----\n"
    ):
        print(f"ERROR: {ca_source}: no dev provisioning-API CA certificate (run "
              "scripts/gen-dev-keys.sh or scripts/ci/prepare-ci-keyring.sh)", file=sys.stderr)
        return 1

    try:
        staged = stage_pins(edge, pins, "run scripts/gen-dev-keys.sh or scripts/ci/prepare-ci-keyring.sh")
    except (ValueError, UnicodeDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    install_pins(staged, pins, args.target)
    cloud_ca.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ca_source, cloud_ca)
    cloud_ca.chmod(0o644)
    print(f"suderra-keys: dev provisioning-API CA {cloud_ca.relative_to(args.target)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
