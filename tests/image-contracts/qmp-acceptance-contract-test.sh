#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
HARNESS="${PROJECT_ROOT}/tests/qemu/qmp-acceptance.py"
BOOT_TEST="${PROJECT_ROOT}/tests/qemu/boot-test.sh"

python3 -m py_compile "${HARNESS}"
"${HARNESS}" --help >/dev/null

if ! grep -q 'qmp-acceptance.py' "${BOOT_TEST}"; then
    echo "ERROR: boot-test.sh must use the QMP acceptance harness" >&2
    exit 1
fi
if grep -q 'timeout "${TIMEOUT}" qemu-system-x86_64' "${BOOT_TEST}"; then
    echo "ERROR: boot-test.sh still uses direct timeout/grep smoke execution" >&2
    exit 1
fi
