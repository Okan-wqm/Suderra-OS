#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Scenarios of tests/qemu/data-unlock-vm-test.py with a second virtio disk in the
# guest, a "USB stick" whose blank partition carries the data PARTUUID
# (ADR-048 DEC-18.1; EI-044, EI-050). The PARTUUIDs of the production layouts are
# public, so the stick can claim the identity of /data; before the layout
# service existed suderra-data-unlock named the partition by a by-partuuid link,
# which udev gives to whichever claimant it saw last, classified the blank stick
# partition blank and provisioned it (luksFormat, TPM seal, mkfs, FACTORY). Now
# suderra-disk-layout refuses a PARTUUID that is carried twice or that is on
# another disk than the verified root, and the data unlock reports that as its
# alarm and touches nothing.
#
#   stick-duplicate  the boot disk has its data partition, the stick carries the
#                    same PARTUUID: it is on two partitions
#   stick-only       the boot disk has no data partition, the stick carries the
#                    PARTUUID: it is on another disk
#
# Every scenario prints `T-PASS <name>` or `T-FAIL <name>: <why>`.
set -u

# These scenarios write to /dev/vda3 and /dev/vdb1 and run as root in the guest of
# tests/qemu/data-unlock-vm-test.py (as /test/...): never on the host, whose
# /dev/vda is its own disk.
case "$0" in
    /test/*) ;;
    *)
        echo "ERROR: $0 runs in the guest of tests/qemu/data-unlock-vm-test.py only" >&2
        exit 2
        ;;
esac

UNLOCK=/usr/sbin/suderra-data-unlock
LAYOUT=/usr/sbin/suderra-disk-layout
INSTALLER_LOG=/run/installer.log
STICK=/dev/vdb1
FAILED=0

pass() { echo "T-PASS $1"; }
fail() {
    echo "T-FAIL $1: $2"
    FAILED=1
}

# No signature of its own (a file system, or a partition table inside it):
# nothing was ever written to the partition. Plain blkid also lists the PARTUUID
# of the partition entry, which every partition of the GPT disk has.
blank() { [ -z "$(blkid -p -s TYPE -s PTTYPE -o value "$1" 2> /dev/null)" ]; }

# The names (links) the layout made; the refusal file is not one.
names() {
    for entry in /run/suderra-os/disk/*; do
        if [ -L "${entry}" ]; then basename "${entry}"; fi
    done
}

# layout_refused <scenario> <reason pattern>: the layout service's script is
# refused with that reason, names nothing and leaves the refusal for the data unlock.
layout_refused() {
    name="$1"
    sh "${LAYOUT}" > /run/layout.out 2>&1
    rc=$?
    [ "${rc}" -ne 0 ] || {
        fail "${name}" "the layout was accepted"
        sed 's/^/    | /' /run/layout.out
        return 1
    }
    grep -q -- "$2" /run/layout.out || {
        fail "${name}" "refused without saying: $2"
        sed 's/^/    | /' /run/layout.out
        return 1
    }
    [ -z "$(names)" ] || {
        fail "${name}" "names exist after a refusal: $(names | tr '\n' ' ')"
        return 1
    }
    [ -s /run/suderra-os/disk/refusal ] || {
        fail "${name}" "no refusal file for the data unlock"
        return 1
    }
    return 0
}

# unlock_refused <scenario> <partition>...: the data unlock fails with the
# layout's reason as its alarm and none of the partitions was written to.
unlock_refused() {
    name="$1"
    shift
    : > "${INSTALLER_LOG}"
    sh "${UNLOCK}" > /run/unlock.out 2>&1
    rc=$?
    [ "${rc}" -ne 0 ] || {
        fail "${name}" "the data unlock succeeded"
        return
    }
    grep -q 'result --kind data-unlock --outcome alarm --reason data-unmountable' "${INSTALLER_LOG}" || {
        fail "${name}" "no data-unmountable alarm was recorded: $(cat "${INSTALLER_LOG}")"
        return
    }
    grep -q 'the disk layout was refused' "${INSTALLER_LOG}" || {
        fail "${name}" "the alarm does not carry the layout's refusal: $(cat "${INSTALLER_LOG}")"
        return
    }
    for partition in "$@"; do
        blank "${partition}" || {
            fail "${name}" "${partition} was written to"
            return
        }
    done
    [ ! -e /dev/mapper/suderra-data ] || {
        fail "${name}" "a volume was opened"
        return
    }
    ! grep -q 'lifecycle factory' "${INSTALLER_LOG}" || {
        fail "${name}" "the lifecycle entered FACTORY"
        return
    }
    [ ! -e /run/suderra-os/data-created ] || {
        fail "${name}" "the data-created evidence was written"
        return
    }
    pass "${name}"
}

[ -b "${STICK}" ] || echo "T-FAIL setup: the stick partition ${STICK} is missing"

case "${1:-}" in
    stick-duplicate)
        blank /dev/vda3 || echo "T-FAIL setup: the boot disk's data partition is not blank"
        layout_refused duplicate-data-partuuid-is-refused 'is carried by 2 partitions' &&
            pass duplicate-data-partuuid-is-refused
        unlock_refused refused-layout-provisions-nothing /dev/vda3 "${STICK}"
        ;;
    stick-only)
        [ ! -b /dev/vda3 ] || echo "T-FAIL setup: the boot disk has a data partition"
        layout_refused data-partuuid-on-another-disk-is-refused 'on vdb, not on vda' &&
            pass data-partuuid-on-another-disk-is-refused
        unlock_refused refused-layout-provisions-nothing-on-the-stick "${STICK}"
        ;;
    *)
        echo "T-FAIL setup: unknown scenario set '${1:-}'"
        ;;
esac
echo "T-DONE failed=${FAILED}"
