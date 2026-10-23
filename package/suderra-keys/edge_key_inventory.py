#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""The edge key inventory of docs/security/key-management.md (ADR-048 DEC-3.9, DEC-3.11).

The production keyids of the edge contract are recorded once, in the table
under the heading below, by the key ceremony. Three consumers read that one
table and nothing else:

* package/suderra-keys/suderra-edge-pins.py pins into a production image of a
  hardware board only keys whose keyid the table records for that purpose and
  epoch (the build fails on any other keyid, the dev/CI keys included);
* the root installer's `PRODUCTION_KEYIDS`
  (userspace/suderra-installer/src/trust_anchors.rs) is the same table as a
  compile-time constant; `rust` prints it and `rust-check` fails when the
  source differs, so the two cannot drift;
* tests/image-contracts/edge-key-inventory-contract-test.sh validates the
  table itself.

    edge_key_inventory.py check      [--inventory FILE]
    edge_key_inventory.py row        --purpose P --epoch N --public-key FILE --origin O
    edge_key_inventory.py rust       [--inventory FILE]
    edge_key_inventory.py rust-check [--inventory FILE] [--source FILE]

`row` is how the ceremony records a key: the keyid is computed from the
exported public key, never typed, and the key must be an Ed25519
SubjectPublicKeyInfo that is not one of the contract's TEST-ONLY keys.
The table stays `bekliyor: operatör` for every key until the ceremony has run.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = ROOT / "docs" / "security" / "key-management.md"
DEFAULT_RUST_SOURCE = ROOT / "userspace" / "suderra-installer" / "src" / "trust_anchors.rs"
CONTRACT = ROOT / "contracts" / "suderra-edge" / "v1"

HEADING = "## Edge sözleşmesi anahtar envanteri (ADR-048 DEC-3.9)"
COLUMNS = ("Amaç", "Epoch", "Keyid", "Köken", "Saklama", "Çapa")
PENDING = "bekliyor: operatör"

ORIGIN_OFFLINE = "ceremony-hsm-offline"
ORIGIN_SERVICE = "ceremony-service-secret"
ORIGIN_KMS = "kms"
# DEC-3.3 / DEC-3.9: edge-release and fleet-root private keys never leave the
# HSM; the online purposes live in service secrets until the KMS signer (P2).
ALLOWED_ORIGINS = {
    "edge-release": {ORIGIN_OFFLINE},
    "fleet-root": {ORIGIN_OFFLINE},
    "edge-provisioning": {ORIGIN_SERVICE, ORIGIN_KMS},
    "device-lifecycle": {ORIGIN_SERVICE, ORIGIN_KMS},
    "config-integrity": {ORIGIN_SERVICE, ORIGIN_KMS},
    "rbac-manifest": {ORIGIN_SERVICE, ORIGIN_KMS},
    "command": {ORIGIN_SERVICE, ORIGIN_KMS},
    # DEC-3.3: a P2 purpose, X.509, held in the KMS; no key exists in P1.
    "edge-image": {ORIGIN_KMS},
}
ANCHOR_OS_IMAGE = "os-image"
ANCHOR_BUNDLE = "trust-anchors"
ANCHOR_KERNEL = "kernel-keyring"
# The Rust names of the purposes the installer pins in the OS image
# (registry.rs `Purpose`, in the order of statements.json `purposes`).
RUST_PURPOSE = {
    "edge-release": "EdgeRelease",
    "edge-provisioning": "EdgeProvisioning",
    "fleet-root": "FleetRoot",
    "device-lifecycle": "DeviceLifecycle",
}
OS_PINNED = tuple(RUST_PURPOSE)
KEYID = re.compile(r"[0-9a-f]{64}")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
RUST_DECL = "pub(crate) const PRODUCTION_KEYIDS: &[(Purpose, u16, &str)] = "

# What the ceremony records for a key, by purpose.
CUSTODY = {
    "edge-release": "Offline HSM, iki emanetçi; üretim release statement'ı offline imzalanır",
    "fleet-root": "Offline HSM, iki emanetçi; yalnız trust-anchors ve key-epoch-advance imzalar",
    "edge-provisioning": "Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119)",
    "device-lifecycle": "Seremonide üretilir, ayrı signer secret'ı (KMS'e kadar, EDGE-HIGH-119)",
    "config-integrity": "Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119)",
    "rbac-manifest": "Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119)",
    "command": "Seremonide üretilir, sensor-service secret'ı (KMS'e kadar, EDGE-HIGH-119)",
    "edge-image": "KMS (P2); X.509, kernel keyring'ine gömülü sertifika",
}


class InventoryError(Exception):
    """The inventory table or a key breaks the rules above."""


def contract_purposes(contract: Path = CONTRACT) -> dict[str, str]:
    """Ed25519 purposes of the vendored contract -> where a device anchors them."""
    data = json.loads((contract / "statements.json").read_text(encoding="utf-8"))
    anchors: dict[str, str] = {}
    for purpose, spec in data["purposes"].items():
        if spec["algorithm"] != "ed25519":
            continue
        anchors[purpose] = ANCHOR_OS_IMAGE if "os-image" in spec["anchored_in"] else ANCHOR_BUNDLE
    return anchors


def test_only_keyids(contract: Path = CONTRACT) -> set[str]:
    keyring = json.loads((contract / "test-keys" / "keyring.json").read_text(encoding="utf-8"))
    return {k["keyid"] for k in [*keyring["keys"], *keyring.get("unanchored_keys", [])]}


def read_table(path: Path) -> list[dict[str, str]]:
    """The rows of the inventory table, as column -> cell."""
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index(HEADING)
    except ValueError:
        raise InventoryError(f"{path}: no heading {HEADING!r}") from None
    table: list[list[str]] = []
    for line in lines[start + 1 :]:
        if not line.startswith("|"):
            if table:
                break
            continue
        table.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    if len(table) < 3:
        raise InventoryError(f"{path}: the inventory table under {HEADING!r} has no rows")
    if tuple(table[0]) != COLUMNS:
        raise InventoryError(f"{path}: the table header is {table[0]}, not {list(COLUMNS)}")
    if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in table[1]):
        raise InventoryError(f"{path}: the second table line is not the header separator")
    rows = []
    for number, cells in enumerate(table[2:], start=1):
        if len(cells) != len(COLUMNS):
            raise InventoryError(f"inventory row {number} has {len(cells)} cells, not {len(COLUMNS)}")
        rows.append(dict(zip(COLUMNS, cells, strict=True)))
    return rows


def check_row(row: dict[str, str], forbidden: set[str], anchors: dict[str, str]) -> None:
    """The rules of one row; `row` (the ceremony's helper) and the table share them."""
    purpose = row["Amaç"]
    label = f"inventory row {purpose}/{row['Epoch']}"
    if purpose not in ALLOWED_ORIGINS:
        raise InventoryError(f"{label}: {purpose!r} is not an edge key purpose")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", row["Epoch"]):
        raise InventoryError(f"{label}: the epoch is not a positive integer")
    if row["Köken"] not in ALLOWED_ORIGINS[purpose]:
        raise InventoryError(
            f"{label}: origin {row['Köken']!r} is not one of {sorted(ALLOWED_ORIGINS[purpose])}"
        )
    expected_anchor = ANCHOR_KERNEL if purpose == "edge-image" else anchors[purpose]
    if row["Çapa"] != expected_anchor:
        raise InventoryError(f"{label}: the anchor is {row['Çapa']!r}, the contract says {expected_anchor!r}")
    keyid = row["Keyid"]
    if keyid == PENDING:
        return
    if purpose == "edge-image":
        raise InventoryError(f"{label}: edge-image is a P2 key; no keyid is recorded in P1")
    if not KEYID.fullmatch(keyid):
        raise InventoryError(f"{label}: {keyid!r} is neither {PENDING!r} nor a lowercase hex SHA-256")
    if keyid in forbidden:
        raise InventoryError(f"{label}: {keyid} is a TEST-ONLY contract key; no image may pin it (DEC-3.9)")


def validate(rows: list[dict[str, str]], forbidden: set[str], anchors: dict[str, str]) -> None:
    """Every rule of the inventory; the first breach is the error."""
    seen: set[tuple[str, int]] = set()
    keyids: dict[str, str] = {}
    for row in rows:
        check_row(row, forbidden, anchors)
        key = (row["Amaç"], int(row["Epoch"]))
        label = f"inventory row {key[0]}/{key[1]}"
        if key in seen:
            raise InventoryError(f"{label}: recorded twice")
        seen.add(key)
        keyid = row["Keyid"]
        if keyid == PENDING:
            continue
        if keyid in keyids:
            raise InventoryError(
                f"{label}: key {keyid} is already {keyids[keyid]}; every purpose has its own key"
            )
        keyids[keyid] = f"{key[0]}/{key[1]}"
    missing = sorted((set(anchors) | {"edge-image"}) - {p for p, _ in seen})
    if missing:
        raise InventoryError(f"the inventory has no row for {missing}")


def load(path: Path, contract: Path = CONTRACT) -> list[dict[str, str]]:
    rows = read_table(path)
    validate(rows, test_only_keyids(contract), contract_purposes(contract))
    return rows


def recorded(path: Path, contract: Path = CONTRACT) -> dict[tuple[str, int], str]:
    """(purpose, epoch) -> keyid, for the keys a ceremony has recorded."""
    return {(r["Amaç"], int(r["Epoch"])): r["Keyid"] for r in load(path, contract) if r["Keyid"] != PENDING}


def rust_const(path: Path) -> str:
    """PRODUCTION_KEYIDS as the installer source declares it."""
    pins = recorded(path)
    entries = sorted(
        ((p, e, k) for (p, e), k in pins.items() if p in RUST_PURPOSE),
        key=lambda t: (OS_PINNED.index(t[0]), t[1]),
    )
    if not entries:
        return f"{RUST_DECL}&[];\n"
    lines = [f"{RUST_DECL}&["]
    for purpose, epoch, keyid in entries:
        one = f'    (Purpose::{RUST_PURPOSE[purpose]}, {epoch}, "{keyid}"),'
        if len(one) <= 100:
            lines.append(one)
        else:
            lines += [
                "    (",
                f"        Purpose::{RUST_PURPOSE[purpose]},",
                f"        {epoch},",
                f'        "{keyid}",',
                "    ),",
            ]
    lines.append("];")
    return "\n".join(lines) + "\n"


def source_const(source: Path) -> str:
    text = source.read_text(encoding="utf-8")
    start = text.find(RUST_DECL)
    if start < 0:
        raise InventoryError(f"{source}: no {RUST_DECL.strip()}")
    end = text.find(";", start)
    return text[start : end + 1] + "\n"


def squeeze(text: str) -> str:
    """Whitespace and trailing commas are rustfmt's business, not the table's."""
    return re.sub(r",(?=[)\]])", "", re.sub(r"\s+", "", text))


def raw_public_key(path: Path) -> bytes:
    lines = path.read_text(encoding="ascii").strip().splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise InventoryError(f"{path}: not a PEM PUBLIC KEY block")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError as e:
        raise InventoryError(f"{path}: not base64: {e}") from None
    if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise InventoryError(f"{path}: not an Ed25519 SubjectPublicKeyInfo")
    return der[len(ED25519_SPKI_PREFIX) :]


def row_for(purpose: str, epoch: int, public_key: Path, origin: str) -> str:
    """The inventory row of an exported ceremony key, under the table's own rules."""
    anchors = contract_purposes()
    if purpose not in anchors:
        raise InventoryError(f"{purpose!r} is not an Ed25519 edge key purpose a P1 ceremony records")
    row = {
        "Amaç": purpose,
        "Epoch": str(epoch),
        "Keyid": hashlib.sha256(raw_public_key(public_key)).hexdigest(),
        "Köken": origin,
        "Saklama": CUSTODY[purpose],
        "Çapa": anchors[purpose],
    }
    check_row(row, test_only_keyids(), anchors)
    return "| " + " | ".join(row[c] for c in COLUMNS) + " |"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("check", "rust", "rust-check"):
        p = sub.add_parser(name)
        p.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    sub.choices["rust-check"].add_argument("--source", type=Path, default=DEFAULT_RUST_SOURCE)
    p = sub.add_parser("row")
    p.add_argument("--purpose", required=True)
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--public-key", type=Path, required=True)
    p.add_argument("--origin", required=True)
    args = ap.parse_args()
    try:
        if args.mode == "check":
            rows = load(args.inventory)
            done = sum(1 for r in rows if r["Keyid"] != PENDING)
            print(f"ok: {len(rows)} rows, {done} recorded, {len(rows) - done} {PENDING}")
        elif args.mode == "rust":
            load(args.inventory)
            sys.stdout.write(rust_const(args.inventory))
        elif args.mode == "rust-check":
            want, have = rust_const(args.inventory), source_const(args.source)
            if squeeze(want) != squeeze(have):
                raise InventoryError(
                    f"{args.source} declares\n{have}but the inventory records\n{want}"
                    "(print it with: edge_key_inventory.py rust)"
                )
            print("ok: PRODUCTION_KEYIDS is the inventory")
        else:
            print(row_for(args.purpose, args.epoch, args.public_key, args.origin))
    except (InventoryError, OSError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
