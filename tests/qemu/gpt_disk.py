# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""A GPT disk image writer for the guest tests.

The guest tests need disks whose partitions carry given PARTUUIDs (the
production layouts' public identities, board/suderra/common/gpt-partuuids.conf)
without depending on sfdisk or sgdisk on the host: a protective MBR, the
primary and the backup header and entry array, CRCs as UEFI 2.x defines them.
The kernel of the guest parses it like the one the production disks carry.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from pathlib import Path

SECTOR = 512
MIB = 1024 * 1024
ENTRY_COUNT = 128
ENTRY_SIZE = 128
ENTRY_SECTORS = ENTRY_COUNT * ENTRY_SIZE // SECTOR
# The Linux filesystem data type: what the production rootfs and verity
# partitions carry (the data partition has a type of its own, which the guest
# tests do not need).
LINUX_FILESYSTEM = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
FIRST_ALIGNED_LBA = MIB // SECTOR


def write_gpt(
    path: Path,
    size_bytes: int,
    partitions: list[tuple[str, str, int]],
    disk_guid: str,
) -> list[tuple[int, int]]:
    """Create <path> of <size_bytes> with a GPT holding <partitions>, each
    (name, PARTUUID, size in bytes) placed one after the other on 1 MiB
    boundaries. Returns the (first LBA, last LBA) of each."""
    if size_bytes % SECTOR:
        raise ValueError("the disk size must be a multiple of the sector size")
    total = size_bytes // SECTOR
    first_usable = 2 + ENTRY_SECTORS
    last_usable = total - 1 - ENTRY_SECTORS - 1
    entries = bytearray(ENTRY_COUNT * ENTRY_SIZE)
    spans: list[tuple[int, int]] = []
    cursor = FIRST_ALIGNED_LBA
    for index, (name, partuuid, size) in enumerate(partitions):
        if size % MIB or size <= 0:
            raise ValueError(f"{name}: the size must be whole MiB")
        first = cursor
        last = first + size // SECTOR - 1
        if last > last_usable:
            raise ValueError(f"{name} does not fit on the disk")
        spans.append((first, last))
        raw_name = name.encode("utf-16-le")
        if len(raw_name) > 72:
            raise ValueError(f"{name}: partition name too long")
        entry = (
            LINUX_FILESYSTEM.bytes_le
            + uuid.UUID(partuuid).bytes_le
            + struct.pack("<QQQ", first, last, 0)
            + raw_name.ljust(72, b"\0")
        )
        entries[index * ENTRY_SIZE : (index + 1) * ENTRY_SIZE] = entry
        cursor = last + 1
        cursor += -cursor % FIRST_ALIGNED_LBA
    entries_crc = zlib.crc32(bytes(entries))

    def header(my_lba: int, other_lba: int, entries_lba: int) -> bytes:
        fields = [
            b"EFI PART",
            struct.pack("<I", 0x00010000),
            struct.pack("<I", 92),
            struct.pack("<I", 0),  # the header CRC, filled in below
            struct.pack("<I", 0),
            struct.pack("<QQQQ", my_lba, other_lba, first_usable, last_usable),
            uuid.UUID(disk_guid).bytes_le,
            struct.pack("<QIII", entries_lba, ENTRY_COUNT, ENTRY_SIZE, entries_crc),
        ]
        raw = bytearray(b"".join(fields))
        assert len(raw) == 92
        raw[16:20] = struct.pack("<I", zlib.crc32(bytes(raw)))
        return bytes(raw).ljust(SECTOR, b"\0")

    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack(
        "<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, min(total - 1, 0xFFFFFFFF)
    )
    mbr[510:512] = b"\x55\xaa"
    with path.open("wb") as handle:
        handle.truncate(size_bytes)
        handle.seek(0)
        handle.write(mbr)
        handle.write(header(1, total - 1, 2))
        handle.write(entries)
        handle.seek((total - 1 - ENTRY_SECTORS) * SECTOR)
        handle.write(entries)
        handle.write(header(total - 1, 1, total - 1 - ENTRY_SECTORS))
    return spans
