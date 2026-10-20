#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
GENIMAGE_CFG="${PROJECT_ROOT}/board/suderra/aarch64-rpi4-usb-installer/genimage.cfg"
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"

if awk '
    /^image payload\.ext4[[:space:]]*\{/ { capture = 1 }
    capture && /^image suderra-pi-cm4-revpi-usb-installer\.img[[:space:]]*\{/ { capture = 0 }
    capture && /files[[:space:]]*=/ { found = 1 }
    END { exit(found ? 0 : 1) }
' "${GENIMAGE_CFG}"; then
    echo "ERROR: installer payload ext4 must not use genimage files=; ext4 content must come from rootpath/mountpoint" >&2
    exit 1
fi

awk '
    /^image payload\.ext4[[:space:]]*\{/ { capture = 1 }
    capture && /^image suderra-pi-cm4-revpi-usb-installer\.img[[:space:]]*\{/ { capture = 0 }
    capture && /mountpoint[[:space:]]*=[[:space:]]*"\/"/ { found = 1 }
    END { exit(found ? 0 : 1) }
' "${GENIMAGE_CFG}" ||
    {
        echo "ERROR: installer payload ext4 must declare mountpoint=/ for the dedicated payload rootpath" >&2
        exit 1
    }

grep -q 'GENIMAGE_ROOTPATH="${TARGET_DIR:-${BINARIES_DIR}/../target}"' "${POST_IMAGE}" ||
    {
        echo "ERROR: post-image must centralize the genimage rootpath contract" >&2
        exit 1
    }
grep -q 'GENIMAGE_ROOTPATH="${payload_root}"' "${POST_IMAGE}" ||
    {
        echo "ERROR: installer payload preparation must switch genimage to the dedicated payload rootpath" >&2
        exit 1
    }
grep -q -- '--rootpath "${GENIMAGE_ROOTPATH}"' "${POST_IMAGE}" ||
    {
        echo "ERROR: post-image genimage invocation must consume GENIMAGE_ROOTPATH" >&2
        exit 1
    }
grep -q 'ln -f "${BINARIES_DIR}/${payload_file}" "${payload_root}/${payload_file}"' "${POST_IMAGE}" ||
    {
        echo "ERROR: installer payload root must materialize signed payload files without duplicating large images" >&2
        exit 1
    }

# The USB self-installer writes an OS image onto the internal disk: only the
# installer image ships it. The root-installer package installs it into every
# device image too, and a dev image's presets would enable it, so post-build
# deletes it from every image that is not a USB installer.
python3 - "${PROJECT_ROOT}/board/suderra/common/post-build.sh" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
case = re.search(r'case "\$\{DEFCONFIG_NAME\}" in\n    \*usb_installer\*\)\n(?P<installer>.*?)\n        ;;\n'
                 r'    \*\)\n(?P<device>.*?)\n        ;;\nesac', text, re.S)
if case is None:
    sys.exit("ERROR: post-build.sh must split usb_installer images from device images")
if "enable_unit suderra-os-install.service" not in case["installer"]:
    sys.exit("ERROR: only the installer image enables suderra-os-install.service")
for path in ("usr/sbin/suderra-os-install", "usr/lib/systemd/system/suderra-os-install.service"):
    if path not in case["device"] or "rm -f" not in case["device"]:
        sys.exit(f"ERROR: post-build.sh must delete {path} from device images")
PY
