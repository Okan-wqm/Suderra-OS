#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""A disk image with an MBR and one FAT partition: mbr-disk.py <out> <fat-image>.

The QEMU boot-chain test boots from partition 1 of a virtio disk, as production
boots from partition 1 (the boot partition) of the eMMC or SD card; a FAT image
alone has no partition table, and the 1 MiB gap in front is where the Pi boot
disk keeps its raw environment.
"""

import struct
import sys

out, fat = sys.argv[1], sys.argv[2]
data = open(fat, "rb").read()
sectors = len(data) // 512
mbr = bytearray(512)
mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0x0C, b"\0\0\0", 2048, sectors)
mbr[510:512] = b"\x55\xaa"
with open(out, "wb") as f:
    f.write(mbr)
    f.write(b"\0" * (1024 * 1024 - 512))
    f.write(data)
