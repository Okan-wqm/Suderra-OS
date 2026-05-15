#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
DOCKERFILE="${PROJECT_ROOT}/ci/Dockerfile"
RESOURCE_CHECK="${PROJECT_ROOT}/scripts/ci/check-runner-resources.sh"

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
require_pattern 'SHELL \["/bin/bash", "-o", "pipefail", "-c"\]' 'Dockerfile pipefail shell'
require_pattern '# hadolint ignore=DL3008' 'documented apt pinning exception'
grep -q 'PROJECT_ROOT}/dl:/workspace/dl:rw' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must bind repo-local dl/ for CI cache compatibility" >&2
        exit 1
    }
grep -q 'PROJECT_ROOT}/.ccache:/workspace/.ccache:rw' "${PROJECT_ROOT}/scripts/build-in-docker.sh" ||
    {
        echo "ERROR: build-in-docker must bind repo-local .ccache/ for CI cache compatibility" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_DISK_GIB' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit disk threshold" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_MEM_GIB' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit memory threshold" >&2
        exit 1
    }
grep -q 'SUDERRA_MIN_VCPU' "${RESOURCE_CHECK}" ||
    {
        echo "ERROR: runner resource gate must expose explicit vCPU threshold" >&2
        exit 1
    }
grep -q 'MATRIX_PREBUILD_DEFCONFIGS' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must consume matrix prebuild contracts" >&2
        exit 1
    }
grep -q 'MATRIX_PAYLOAD_IMAGE_EXPORTS' "${PROJECT_ROOT}/.github/workflows/build.yml" ||
    {
        echo "ERROR: build workflow must consume matrix payload export contracts" >&2
        exit 1
    }
