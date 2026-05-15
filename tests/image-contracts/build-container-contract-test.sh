#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
DOCKERFILE="${PROJECT_ROOT}/ci/Dockerfile"

require_pattern() {
    local pattern="$1"
    local reason="$2"
    if ! grep -Eq "${pattern}" "${DOCKERFILE}"; then
        echo "ERROR: build container contract missing ${reason}" >&2
        exit 1
    fi
}

require_pattern 'ubuntu:24\.04@sha256:' 'pinned base image digest'
require_pattern 'libelf-dev' 'Linux objtool host elf headers'
require_pattern 'qemu-system-x86' 'x86 QEMU runtime gate'
require_pattern 'qemu-system-arm' 'ARM QEMU/runtime tooling'
require_pattern 'qemu-utils' 'image inspection/runtime utilities'
require_pattern 'parted' 'partition table image tooling'
require_pattern 'dosfstools' 'EFI/FAT image tooling'
require_pattern 'mtools' 'EFI/FAT image manipulation tooling'
require_pattern 'e2fsprogs' 'ext filesystem image tooling'
require_pattern 'openssl' 'signing and certificate tooling'
require_pattern 'shellcheck' 'strict shell lint tooling'
require_pattern 'getent group dbus' 'dbus group preflight'
require_pattern 'groupadd -r dbus' 'dbus group creation'
