#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""RAUC compatible of every Suderra OS image (ADR-048 DEC-8.3).

One RAUC compatible per board, so RAUC refuses a bundle built for another
board (RevPi Connect 4 and RPi4/CM4 used to share suderra-os-aarch64,
EI-045). boards.json rauc_compatible is the vocabulary. The OTA target
contract (ci/evidence-contract.yml ota.targets.<build_target>.compatible) is
what the bundle tool signs into every bundle of a target and what
post-build.sh writes into that image's /etc/rauc/system.conf, so bundle and
device can never disagree; this tool checks that the contract equals
boards.json.

    rauc-compatible.py image <defconfig>   print the image's compatible
    rauc-compatible.py check               check every OTA target
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPATIBLE = re.compile(r"^suderra-os-[a-z0-9_]+(-[a-z0-9_]+)*$")


class ContractError(Exception):
    pass


def load(root: Path) -> tuple[dict, dict]:
    boards = json.loads((root / "contracts/suderra-edge/v1/boards.json").read_text(encoding="utf-8"))
    contract = json.loads((root / "ci/evidence-contract.yml").read_text(encoding="utf-8"))
    return boards, contract


def board_images(boards: dict) -> list[tuple[dict | None, dict]]:
    images: list[tuple[dict | None, dict]] = [
        (b, i) for b in boards["boards"] for i in b["os_images"]
    ]
    images += [(None, i) for f in boards["pending_board_families"] for i in f["os_images"]]
    images += [(None, e) for e in boards["excluded_os_images"]]
    return images


def compatible_of(build_target: str, board: dict | None, boards: dict, contract: dict) -> str:
    target = contract["ota"]["targets"].get(build_target)
    if target is None:
        raise ContractError(f"ci/evidence-contract.yml has no OTA target {build_target}")
    compatible = target["compatible"]
    if not COMPATIBLE.match(compatible):
        raise ContractError(f"OTA target {build_target} compatible {compatible!r} is not suderra-os-<name>")
    board_compatibles = {b["rauc_compatible"] for b in boards["boards"]}
    if board is not None:
        if compatible != board["rauc_compatible"]:
            raise ContractError(
                f"OTA target {build_target} compatible {compatible} differs from boards.json "
                f"rauc_compatible {board['rauc_compatible']} of {board['board_profile']}"
            )
    elif compatible in board_compatibles:
        raise ContractError(
            f"OTA target {build_target} declares no board but reuses a board's compatible {compatible}"
        )
    return compatible


def image(root: Path, defconfig: str) -> str:
    boards, contract = load(root)
    matches = [(b, i) for b, i in board_images(boards) if i["defconfig"] == defconfig]
    if len(matches) != 1:
        raise ContractError(f"{defconfig} is classified {len(matches)} times in boards.json; must be once")
    board, entry = matches[0]
    return compatible_of(entry["build_target"], board, boards, contract)


def check(root: Path) -> list[str]:
    boards, contract = load(root)
    problems = []
    seen: dict[str, str] = {}
    for b in boards["boards"]:
        expected = f"suderra-os-{b['board_profile']}"
        if b["rauc_compatible"] != expected:
            problems.append(f"boards.json {b['board_profile']}: rauc_compatible {b['rauc_compatible']} is not {expected}")
        if b["rauc_compatible"] in seen:
            problems.append(f"boards.json: {b['board_profile']} and {seen[b['rauc_compatible']]} share {b['rauc_compatible']}")
        seen[b["rauc_compatible"]] = b["board_profile"]
    classified = set()
    for board, entry in board_images(boards):
        classified.add(entry["build_target"])
        if board is None and entry["build_target"] not in contract["ota"]["targets"]:
            # An image with no board and no OTA target carries no RAUC.
            continue
        try:
            compatible_of(entry["build_target"], board, boards, contract)
        except ContractError as e:
            problems.append(str(e))
    for target in contract["ota"]["targets"]:
        if target not in classified:
            problems.append(f"OTA target {target} is no boards.json image's build_target")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    sub = ap.add_subparsers(dest="mode", required=True)
    i = sub.add_parser("image")
    i.add_argument("defconfig")
    sub.add_parser("check")
    args = ap.parse_args()
    try:
        if args.mode == "image":
            print(image(args.root.resolve(), args.defconfig))
            return 0
        problems = check(args.root.resolve())
    except ContractError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for p in problems:
        print(f"ERROR: {p}", file=sys.stderr)
    if problems:
        return 1
    print("RAUC compatible contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
