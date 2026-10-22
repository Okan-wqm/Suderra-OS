#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""The redundant U-Boot environment of the QEMU boot-chain test, as bytes.

U-Boot's flash environment (env/flash.c with CONFIG_SYS_REDUNDAND_ENVIRONMENT)
is two sectors, each: crc32 (little endian) of the data, one flag byte, then
NAME=VALUE entries separated by NUL and ended by an empty entry. The copy with a
valid CRC and the newer flag is the live one. This file builds such an image (to
plant a stored environment) and reads the live copy back (to see what U-Boot
wrote), so the test needs neither the target's tools nor a second U-Boot.

  envimage.py make <image> <size> <second> [NAME=VALUE]...   one valid copy at 0, the other blank
  envimage.py dump <image> <size> <second>                    the live copy's NAME=VALUE lines

<size> is CONFIG_ENV_SIZE and <second> the offset of the second copy
(CONFIG_ENV_ADDR_REDUND - CONFIG_ENV_ADDR).
"""

from __future__ import annotations

import struct
import sys
import zlib

BLANK = 0xFF


def encode(entries: list[str], size: int, flag: int) -> bytes:
    data = b"".join(e.encode() + b"\0" for e in entries) + b"\0"
    room = size - 5
    if len(data) > room:
        raise SystemExit(f"environment does not fit in {size} bytes")
    data = data.ljust(room, b"\0")
    return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF) + bytes([flag]) + data


def decode(sector: bytes) -> tuple[int, list[str]] | None:
    crc = struct.unpack("<I", sector[:4])[0]
    data = sector[5:]
    if zlib.crc32(data) & 0xFFFFFFFF != crc:
        return None
    entries = []
    for raw in data.split(b"\0"):
        if not raw:
            break
        entries.append(raw.decode("utf-8", "replace"))
    return sector[4], entries


def live(image: bytes, size: int, second: int) -> list[str] | None:
    """U-Boot's choice between the two copies (env/flash.c env_flash_init)."""
    one = decode(image[:size])
    two = decode(image[second:second + size])
    if one and not two:
        return one[1]
    if two and not one:
        return two[1]
    if not one and not two:
        return None
    f1, f2 = one[0], two[0]
    if f1 == 255 and f2 == 0:
        return two[1]
    if f2 == 255 and f1 == 0:
        return one[1]
    return two[1] if f2 > f1 else one[1]


def main(argv: list[str]) -> int:
    if len(argv) < 5 or argv[1] not in ("make", "dump"):
        print(__doc__, file=sys.stderr)
        return 2
    path, size, second = argv[2], int(argv[3], 0), int(argv[4], 0)
    if argv[1] == "make":
        flash = bytearray(bytes([BLANK]) * (64 * 1024 * 1024))
        flash[:size] = encode(argv[5:], size, 1)
        with open(path, "wb") as f:
            f.write(flash)
        return 0
    with open(path, "rb") as f:
        entries = live(f.read(second + size), size, second)
    if entries is None:
        print("no valid environment copy", file=sys.stderr)
        return 1
    print("\n".join(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
