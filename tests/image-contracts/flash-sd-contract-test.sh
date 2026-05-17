#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
FLASH="${PROJECT_ROOT}/scripts/flash-sd.sh"

grep -q -- "--lab-allow-missing-hash" "${FLASH}" || {
    echo "ERROR: flash-sd.sh must require an explicit lab flag for missing hashes" >&2
    exit 1
}

grep -q "Hash dosyası bulunamadı" "${FLASH}" || {
    echo "ERROR: flash-sd.sh must report missing hash files" >&2
    exit 1
}

grep -q "LAB_ALLOW_MISSING_HASH" "${FLASH}" || {
    echo "ERROR: flash-sd.sh must gate missing hashes behind LAB_ALLOW_MISSING_HASH" >&2
    exit 1
}

if grep -q "Hash dosyası bulunamadı.*Doğrulama atlandı" "${FLASH}"; then
    echo "ERROR: flash-sd.sh must not silently skip missing hash verification" >&2
    exit 1
fi

grep -q "disk_parent_name()" "${FLASH}" || {
    echo "ERROR: flash-sd.sh must resolve root/target parent disks through a helper" >&2
    exit 1
}

grep -q "lsblk -no PKNAME" "${FLASH}" || {
    echo "ERROR: flash-sd.sh must use lsblk PKNAME for mmcblk/nvme root-disk safety" >&2
    exit 1
}

if grep -q "findmnt -no SOURCE / | sed 's/\\[0-9\\]\\*\\$//'" "${FLASH}"; then
    echo "ERROR: flash-sd.sh still has fragile numeric suffix root-disk stripping" >&2
    exit 1
fi
