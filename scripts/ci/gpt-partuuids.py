#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""The GPT partition UUIDs of the production disk layouts (ADR-048 DEC-18.1).

board/suderra/common/gpt-partuuids.conf is the one list. This tool reads it for
the build and for the tests that hold every consumer to it:

  gpt-partuuids.py get <name>
      the UUID of a partition (rootfs-a, data, ...)
  gpt-partuuids.py render <file>...
      replace every @SUDERRA_PARTUUID_<NAME>@ in each file (NAME: the partition
      name upper-cased, '-' as '_'), in place and idempotently; fail on a
      placeholder that names no partition
  gpt-partuuids.py unrendered <file>...
      fail if a file still holds a @SUDERRA_PARTUUID_*@ placeholder
  gpt-partuuids.py check-genimage <genimage.cfg>...
      fail unless every partition section of the file whose name is in the list
      carries partition-uuid equal to the list's value
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = ROOT / "board/suderra/common/gpt-partuuids.conf"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PLACEHOLDER = re.compile(r"@SUDERRA_PARTUUID_([A-Z0-9_]+)@")


def load(conf: Path = CONF) -> dict[str, str]:
    table: dict[str, str] = {}
    for n, raw in enumerate(conf.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or not UUID.match(parts[1]):
            raise SystemExit(f"{conf}:{n}: expected '<name> <lowercase uuid>': {raw!r}")
        if parts[0] in table:
            raise SystemExit(f"{conf}:{n}: {parts[0]} is listed twice")
        table[parts[0]] = parts[1]
    if len(set(table.values())) != len(table):
        raise SystemExit(f"{conf}: two partitions share a UUID")
    if not table:
        raise SystemExit(f"{conf}: no partition")
    return table


def key(name: str) -> str:
    return name.upper().replace("-", "_")


def render(files: list[str], table: dict[str, str]) -> None:
    by_key = {key(name): uuid for name, uuid in table.items()}
    for path in files:
        p = Path(path)
        text = p.read_text(encoding="utf-8")

        def repl(m: re.Match[str]) -> str:
            if m.group(1) not in by_key:
                raise SystemExit(f"{p}: @SUDERRA_PARTUUID_{m.group(1)}@ names no partition of {CONF}")
            return by_key[m.group(1)]

        out = PLACEHOLDER.sub(repl, text)
        if out != text:
            p.write_text(out, encoding="utf-8")


def unrendered(files: list[str]) -> int:
    bad = [f for f in files if PLACEHOLDER.search(Path(f).read_text(encoding="utf-8"))]
    for f in bad:
        print(f"ERROR: {f} still holds a @SUDERRA_PARTUUID_*@ placeholder", file=sys.stderr)
    return 1 if bad else 0


def check_genimage(files: list[str], table: dict[str, str]) -> int:
    problems = []
    for path in files:
        text = Path(path).read_text(encoding="utf-8")
        seen = set()
        for m in re.finditer(r"^\s*partition\s+([A-Za-z0-9_-]+)\s*\{(.*?)^\s*\}", text, re.S | re.M):
            name, body = m.group(1), m.group(2)
            if name not in table:
                continue
            seen.add(name)
            u = re.search(r'^\s*partition-uuid\s*=\s*"([^"]*)"', body, re.M)
            if not u:
                problems.append(f"{path}: partition {name} has no partition-uuid (expected {table[name]})")
            elif u.group(1) != table[name]:
                problems.append(f"{path}: partition {name} has partition-uuid {u.group(1)}, the list says {table[name]}")
        if not seen:
            problems.append(f"{path}: no partition of {CONF.name} in it")
    for p in problems:
        print(f"ERROR: {p}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, args = argv[1], argv[2:]
    table = load()
    if cmd == "get" and len(args) == 1:
        if args[0] not in table:
            print(f"ERROR: no partition {args[0]} in {CONF}", file=sys.stderr)
            return 1
        print(table[args[0]])
        return 0
    if cmd == "render" and args:
        render(args, table)
        return 0
    if cmd == "unrendered" and args:
        return unrendered(args)
    if cmd == "check-genimage" and args:
        return check_genimage(args, table)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
