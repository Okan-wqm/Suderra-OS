#!/usr/bin/env bash
#
# The partitions the running system names are the ones on the disk of the
# verified root, each carried once (ADR-048 DEC-18.1; EI-044, EI-050).
#
# The PARTUUIDs of the production layouts are public, and a by-partuuid link is
# whichever claimant udev saw last: a USB stick whose blank partition carries the
# data PARTUUID, plugged in before boot, could be classified blank and
# provisioned by suderra-data-unlock. suderra-disk-layout therefore proves, before
# anything mounts or opens a partition, that every PARTUUID of the layout is
# carried by one partition and that partition is on the disk under
# /dev/mapper/suderra-root, and only then names it under /run/suderra-os/disk.
# The consumers (the /boot mount, RAUC's slots, /data) use those names and no
# by-partuuid path.
#
# This test holds the sources to that statement and runs the script's functions
# against a stand-in sysfs and blkid: one disk, a second disk that carries a
# PARTUUID of the first, a verified root that spans disks, a layout with a
# partition missing. tests/qemu/data-unlock-vm-test.py runs the same script in a
# guest with a real kernel, real blkid and a second virtio disk.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
SCRIPT="${OVERLAY}/usr/sbin/suderra-disk-layout"
TABLE="${OVERLAY}/usr/lib/suderra/partuuids.conf"
UNIT="${OVERLAY}/etc/systemd/system/suderra-disk-layout.service"
DATA_UNIT="${OVERLAY}/etc/systemd/system/suderra-data.service"
UNLOCK="${OVERLAY}/usr/sbin/suderra-data-unlock"
RAUC="${ROOT}/package/suderra-rauc-config"
TOOL="${ROOT}/scripts/ci/gpt-partuuids.py"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
CONF="${ROOT}/board/suderra/common/gpt-partuuids.conf"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# ---------------------------------------------------------------------------
# 1. The sources
# ---------------------------------------------------------------------------
echo "the partition table of the image"
for f in "${SCRIPT}" "${TABLE}" "${UNIT}"; do
    [ -f "${f}" ] || fail "missing ${f}"
done
[ -x "${SCRIPT}" ] || fail "${SCRIPT} is not executable"
# It lists every partition of gpt-partuuids.conf, by placeholder, and renders to
# the same UUIDs.
listed="$(grep -vE '^[[:space:]]*(#|$)' "${TABLE}" | cut -d ' ' -f 1 | sort | tr '\n' ' ')"
wanted="$(grep -vE '^[[:space:]]*(#|$)' "${CONF}" | cut -d ' ' -f 1 | sort | tr '\n' ' ')"
[ "${listed}" = "${wanted}" ] || fail "partuuids.conf lists [${listed}], gpt-partuuids.conf has [${wanted}]"
cp "${TABLE}" "${WORK}/partuuids.conf"
python3 -I "${TOOL}" render "${WORK}/partuuids.conf"
python3 -I "${TOOL}" unrendered "${WORK}/partuuids.conf"
while IFS=' ' read -r name uuid; do
    [ "${uuid}" = "$(python3 -I "${TOOL}" get "${name}")" ] || fail "${name} renders to ${uuid}, not to gpt-partuuids.conf's value"
done < <(grep -vE '^[[:space:]]*(#|$)' "${WORK}/partuuids.conf")
grep -qF 'usr/lib/suderra/partuuids.conf' "${POST_BUILD}" || fail "post-build.sh does not render partuuids.conf"
echo "  ${wanted}is rendered from gpt-partuuids.conf"

echo "the consumers name the verified links, never a PARTUUID"
consumers=(
    "${RAUC}/system.conf" "${RAUC}/system.conf.arm" "${RAUC}/boot.mount" "${RAUC}/boot.mount.arm" "${UNLOCK}"
)
for f in "${consumers[@]}"; do
    if grep -vE '^[[:space:]]*#' "${f}" | grep -qE 'by-partuuid|SUDERRA_PARTUUID|by-partlabel'; then
        fail "${f} names a partition by PARTUUID or label: it must use /run/suderra-os/disk/<name>"
    fi
    grep -qE '/run/suderra-os/disk/[a-z-]+' "${f}" || fail "${f} names no /run/suderra-os/disk/<name>"
    while read -r used; do
        # `refusal` is the layout's report, not a partition.
        [ "${used}" = /run/suderra-os/disk/refusal ] && continue
        grep -qE "^${used#/run/suderra-os/disk/} " "${TABLE}" || fail "${f} names ${used}, which partuuids.conf does not list"
    done < <(grep -vE '^[[:space:]]*#' "${f}" | grep -oE '/run/suderra-os/disk/[a-z-]+' | sort -u)
done
echo "  system.conf (x86, ARM), boot.mount (ESP, boot) and suderra-data-unlock"

# Every name a consumer uses is a partition of the layouts that use that consumer.
used_in() { grep -vE '^[[:space:]]*#' "$@" | grep -oE '/run/suderra-os/disk/[a-z-]+' | sed 's#.*/##' | grep -vx refusal | sort -u; }
for name in $(used_in "${RAUC}/system.conf.arm" "${RAUC}/boot.mount.arm" "${UNLOCK}"); do
    for cfg in aarch64-rpi4 aarch64-revpi-connect4; do
        grep -qE "partition ${name} \\{" "${ROOT}/board/suderra/${cfg}/genimage-prod.cfg" ||
            fail "the ARM consumers use ${name}, which ${cfg}/genimage-prod.cfg has no partition for"
    done
done
for name in $(used_in "${RAUC}/system.conf" "${RAUC}/boot.mount" "${UNLOCK}"); do
    grep -qE "partition ${name} \\{" "${ROOT}/board/suderra/x86_64/genimage.cfg" ||
        fail "the x86 consumers use ${name}, which x86_64/genimage.cfg has no partition for"
done
echo "  every name is a partition of the genimage layout of its architecture"

echo "ordering: nothing mounts, opens or writes a partition before the layout is proven"
grep -q '^ConditionPathExists=/dev/mapper/suderra-root$' "${UNIT}" || fail "the unit does not require the verified root device"
grep -qE '^After=.*systemd-repart.service' "${UNIT}" || fail "the unit does not come after systemd-repart (the final partition table)"
grep -qE '^Before=.*boot.mount' "${UNIT}" && grep -qE '^Before=.*rauc.service' "${UNIT}" &&
    grep -qE '^Before=.*suderra-data.service' "${UNIT}" || fail "the unit is not before boot.mount, rauc.service and suderra-data.service"
for mount in boot.mount boot.mount.arm; do
    grep -qx 'Requires=suderra-disk-layout.service' "${RAUC}/${mount}" || fail "${mount} does not require suderra-disk-layout.service"
    grep -qx 'After=suderra-disk-layout.service' "${RAUC}/${mount}" || fail "${mount} is not after suderra-disk-layout.service"
done
grep -qx 'Requires=suderra-disk-layout.service' "${RAUC}/rauc-disk-layout.conf" && grep -qx 'After=suderra-disk-layout.service' "${RAUC}/rauc-disk-layout.conf" ||
    fail "rauc.service is not held behind suderra-disk-layout.service"
grep -q 'rauc-disk-layout.conf.*rauc.service.d/10-suderra-disk-layout.conf' <(tr -d '\\\n\t' < "${RAUC}/suderra-rauc-config.mk") ||
    fail "suderra-rauc-config.mk does not install the rauc.service drop-in"
grep -q 'suderra-disk-layout.service' "${RAUC}/suderra-rauc-mark-good.service" || fail "mark-good is not ordered behind the layout"
grep -qE '^Wants=.*suderra-disk-layout.service' "${DATA_UNIT}" && grep -qE '^After=.*suderra-disk-layout.service' "${DATA_UNIT}" ||
    fail "suderra-data.service does not want and follow suderra-disk-layout.service (a refusal must reach the script's alarm, so Wants)"
grep -q 'enable_unit suderra-disk-layout.service sysinit.target' "${POST_BUILD}" || fail "post-build.sh does not enable suderra-disk-layout.service"
echo "  boot.mount, RAUC and mark-good require it; suderra-data.service wants it and follows it"

echo "suderra-data-unlock never provisions an unnamed partition"
grep -qx 'DATA_DEVICE=/run/suderra-os/disk/data' "${UNLOCK}" || fail "DATA_DEVICE is not the verified name"
[ "$(grep -c '^    require_data_device$' "${UNLOCK}")" -eq 2 ] || fail "provisioning and recovery must both require the verified data device"
grep -q 'DISK_LAYOUT_REFUSAL' "${UNLOCK}" || fail "a refusal of the layout is not reported by the data unlock"
echo "  the data device is the verified name, and a refusal is its alarm"

# ---------------------------------------------------------------------------
# 2. The script, run against a stand-in sysfs and blkid
# ---------------------------------------------------------------------------
echo "the script"
R="${WORK}/root"
UUID_ROOT="$(python3 -I "${TOOL}" get rootfs-a)"
UUID_HASH="$(python3 -I "${TOOL}" get rootfs-a-verity)"
UUID_DATA="$(python3 -I "${TOOL}" get data)"
UUID_BOOT="$(python3 -I "${TOOL}" get boot)"
UUID_OTHER="11111111-2222-4333-8444-555555555555"

# new_system: a stand-in /sys/class/block, /dev and the answers of blkid. The
# devices are plain files (a test cannot mknod), so is_block_device checks for
# existence.
new_system() {
    rm -rf "${R}"
    mkdir -p "${R}/sys/class/block" "${R}/dev" "${R}/out"
    : > "${R}/probe"
}
disk() { # <name>
    mkdir -p "${R}/sys/devices/pci/block/$1"
    ln -s "../../devices/pci/block/$1" "${R}/sys/class/block/$1"
    : > "${R}/dev/$1"
}
part() { # <disk> <name> [uuid]
    mkdir -p "${R}/sys/devices/pci/block/$1/$2"
    : > "${R}/sys/devices/pci/block/$1/$2/partition"
    ln -s "../../devices/pci/block/$1/$2" "${R}/sys/class/block/$2"
    : > "${R}/dev/$2"
    if [ -n "${3:-}" ]; then printf '%s %s\n' "$2" "$3" >> "${R}/probe"; fi
}
verified_root() { # <partition>...: the verity device over these partitions
    mkdir -p "${R}/sys/devices/virtual/block/dm-0/slaves" "${R}/sys/devices/virtual/block/dm-0/dm"
    ln -s "../../devices/virtual/block/dm-0" "${R}/sys/class/block/dm-0"
    printf 'suderra-root\n' > "${R}/sys/devices/virtual/block/dm-0/dm/name"
    : > "${R}/dev/dm-0"
    for p in "$@"; do ln -s "../../../../../class/block/${p}" "${R}/sys/devices/virtual/block/dm-0/slaves/${p}"; done
}
write_table() { cp "${WORK}/partuuids.conf" "${R}/table"; }

# layout <out>: runs layout_resolve of the script on the stand-in system, with the
# script copy $1 (a mutation, or the real one); prints the disk on success, the
# reasons on standard error.
run_layout() { # <script copy>
    sh -c '
        . "$1"
        STAND_IN="$2"
        SUDERRA_DEV="${STAND_IN}/dev"
        SUDERRA_SYS_BLOCK="${STAND_IN}/sys/class/block"
        is_block_device() { [ -e "$1" ]; }
        layout_probe() {
            _n="$(basename "$1")"
            _u="$(sed -n "s/^${_n} //p" "${STAND_IN}/probe")"
            [ -z "${_u}" ] || printf "ID_FS_TYPE=ext4\nPART_ENTRY_UUID=%s\nPART_ENTRY_SCHEME=gpt\n" "${_u}"
        }
        layout_resolve "${STAND_IN}/table" "${STAND_IN}/out"
    ' sh "$1" "${R}"
}
# The links in the output directory (the refusal file is not one).
links() { (cd "${R}/out" && for f in *; do [ -L "${f}" ] && printf '%s ' "${f}"; done; true); }
link_target() { readlink "${R}/out/$1"; }

one_disk() {
    new_system
    disk vda
    part vda vda1 "${UUID_ROOT}"
    part vda vda2 "${UUID_HASH}"
    part vda vda3 "${UUID_DATA}"
    verified_root vda1 vda2
    write_table
}

expect_ok() { # <label> <script copy> <expected links> [expected disk]
    local out
    out="$(run_layout "$2" 2> "${WORK}/err")" || {
        cat "${WORK}/err" >&2
        fail "$1: the layout was refused"
    }
    [ "${out}" = "${4:-vda}" ] || fail "$1: the boot disk is ${out}, not ${4:-vda}"
    [ "$(links)" = "$3 " ] || fail "$1: the links are [$(links)], not [$3]"
    echo "  accepts: $1"
}
expect_refused() { # <label> <script copy> <reason>
    local rc=0
    run_layout "$2" > /dev/null 2> "${WORK}/err" || rc=$?
    [ "${rc}" -ne 0 ] || fail "$1: the layout was accepted"
    grep -q -- "$3" "${WORK}/err" || {
        cat "${WORK}/err" >&2
        fail "$1: refused without saying: $3"
    }
    [ -z "$(links)" ] || fail "$1: refused, but left the links [$(links)]"
    echo "  refuses: $1"
}

one_disk
expect_ok "one disk: the partitions it has, and none it lacks" "${SCRIPT}" "data rootfs-a rootfs-a-verity"
[ "$(link_target data)" = "${R}/dev/vda3" ] || fail "the data link does not point at the partition node"

one_disk
part vda vda4 "${UUID_BOOT}"
expect_ok "a boot partition on the boot disk" "${SCRIPT}" "boot data rootfs-a rootfs-a-verity"

one_disk
disk vdb
part vdb vdb1 "${UUID_OTHER}"
expect_ok "a second disk whose partitions carry no PARTUUID of the layout" "${SCRIPT}" "data rootfs-a rootfs-a-verity"

one_disk
disk vdb
part vdb vdb1 "${UUID_DATA}"
expect_refused "a USB stick that carries the data PARTUUID too" "${SCRIPT}" "is carried by 2 partitions"
grep -q "the PARTUUID of data" "${WORK}/err" || fail "the refusal does not name the partition"

one_disk
disk vdb
part vdb vdb1 "${UUID_ROOT}"
expect_refused "a second disk that carries the root PARTUUID" "${SCRIPT}" "the PARTUUID of rootfs-a"

new_system
disk vda
part vda vda1 "${UUID_ROOT}"
part vda vda2 "${UUID_HASH}"
disk vdb
part vdb vdb1 "${UUID_DATA}"
verified_root vda1 vda2
write_table
expect_refused "the data PARTUUID only on another disk (the boot disk has none)" "${SCRIPT}" "is vdb1 on vdb, not on vda"

one_disk
disk vdb
part vdb vdb1 "${UUID_BOOT}"
expect_refused "a boot partition on another disk" "${SCRIPT}" "is vdb1 on vdb, not on vda"

one_disk
rm "${R}/sys/devices/virtual/block/dm-0/dm/name"
expect_refused "no verified root device (a boot that skipped the verity initramfs)" "${SCRIPT}" "there is no verified root device"

new_system
disk vda
disk vdb
part vda vda1 "${UUID_ROOT}"
part vdb vdb1 "${UUID_HASH}"
part vda vda3 "${UUID_DATA}"
verified_root vda1 vdb1
write_table
expect_refused "a verified root whose partitions are on two disks" "${SCRIPT}" "spans two disks"

new_system
disk vda
part vda vda1 "${UUID_ROOT}"
verified_root
write_table
expect_refused "a verified root device with no partition under it" "${SCRIPT}" "has no underlying partition"

# Links of an earlier boot's layout do not survive a refusal.
one_disk
run_layout "${SCRIPT}" > /dev/null 2>&1 || fail "the setup layout was refused"
[ -n "$(links)" ] || fail "no links to test the cleanup with"
disk vdb
part vdb vdb1 "${UUID_DATA}"
expect_refused "a layout that was fine and now has a duplicate (the old links are removed)" "${SCRIPT}" "is carried by 2 partitions"

# Real PARTUUID answers only: a partition blkid cannot read has no name.
one_disk
sed -i "/^vda3 /d" "${R}/probe"
expect_ok "a partition blkid gives no PARTUUID for is not named (its consumer fails, nothing is guessed)" "${SCRIPT}" "rootfs-a rootfs-a-verity"

# The whole of main: the link directory, the refusal file, the exit status.
main_run() { # <script copy>
    sh -c '
        . "$1"
        STAND_IN="$2"
        SUDERRA_DEV="${STAND_IN}/dev"
        SUDERRA_SYS_BLOCK="${STAND_IN}/sys/class/block"
        LAYOUT_TABLE="${STAND_IN}/table"
        LAYOUT_OUT="${STAND_IN}/out"
        is_block_device() { [ -e "$1" ]; }
        layout_probe() {
            _n="$(basename "$1")"
            _u="$(sed -n "s/^${_n} //p" "${STAND_IN}/probe")"
            [ -z "${_u}" ] || printf "PART_ENTRY_UUID=%s\n" "${_u}"
        }
        main
    ' sh "$1" "${R}"
}
one_disk
main_run "${SCRIPT}" > "${WORK}/main.out" 2>&1 || fail "main refused a good layout"
[ ! -e "${R}/out/refusal" ] || fail "a good layout left a refusal file"
disk vdb
part vdb vdb1 "${UUID_DATA}"
if main_run "${SCRIPT}" > "${WORK}/main.out" 2>&1; then fail "main accepted a duplicate"; fi
[ -s "${R}/out/refusal" ] || fail "a refused layout left no refusal file for suderra-data-unlock"
grep -q 'is carried by 2 partitions' "${R}/out/refusal" || fail "the refusal file does not hold the reason"
[ -z "$(links)" ] || fail "main left links after a refusal"
one_disk
main_run "${SCRIPT}" > "${WORK}/main.out" 2>&1 || fail "the next boot's good layout was refused"
[ ! -e "${R}/out/refusal" ] || fail "the refusal of the earlier boot survived a good layout"
echo "  main: the links on success; no links and a refusal file for the data unlock on refusal"

# ---------------------------------------------------------------------------
# 3. Mutations: each defect class must fail the behaviour above
# ---------------------------------------------------------------------------
echo "mutations"
sys_good() { one_disk; }
sys_duplicate() { one_disk; disk vdb; part vdb vdb1 "${UUID_DATA}"; }
sys_foreign() {
    new_system
    disk vda; part vda vda1 "${UUID_ROOT}"; part vda vda2 "${UUID_HASH}"
    disk vdb; part vdb vdb1 "${UUID_DATA}"
    verified_root vda1 vda2
    write_table
}
# The verified root over a partition of the layout and one of another disk that
# is not in the layout (so only the "spans two disks" rule, not the foreign
# partition rule, can refuse it).
sys_two_disks() {
    new_system
    disk vda; disk vdb
    part vda vda1 "${UUID_ROOT}"; part vdb vdb1 "${UUID_OTHER}"; part vda vda3 "${UUID_DATA}"
    verified_root vda1 vdb1
    write_table
}

# behaves <script copy>: whether the copy does everything the real script does:
# accepts the good layout with its three links, refuses every bad one and leaves
# no link, also over the links of an earlier good layout.
behaves() {
    local mutant="$1" bad out
    sys_good
    out="$(run_layout "${mutant}" 2> /dev/null)" || return 1
    [ "${out}" = vda ] && [ "$(links)" = "data rootfs-a rootfs-a-verity " ] || return 1
    for bad in sys_duplicate sys_foreign sys_two_disks; do
        "${bad}"
        if run_layout "${mutant}" > /dev/null 2>&1 || [ -n "$(links)" ]; then return 1; fi
    done
    # Links of a layout that was fine do not survive the next boot's refusal.
    sys_good
    run_layout "${mutant}" > /dev/null 2>&1 || return 1
    disk vdb
    part vdb vdb1 "${UUID_DATA}"
    if run_layout "${mutant}" > /dev/null 2>&1 || [ -n "$(links)" ]; then return 1; fi
    return 0
}
behaves "${SCRIPT}" || fail "the real script does not pass the behaviour the mutations are measured against"

mutate() { # <label> <old> <new>
    python3 -I - "${SCRIPT}" "${WORK}/mutant" "$2" "$3" <<'EOF'
import sys
text = open(sys.argv[1]).read()
out = text.replace(sys.argv[3], sys.argv[4], 1)
assert out != text, "the text to mutate is not in the script: " + sys.argv[3]
open(sys.argv[2], "w").write(out)
EOF
    if behaves "${WORK}/mutant"; then fail "mutation survived: $1"; fi
    echo "  rejects: $1"
}
mutate "a PARTUUID carried by two partitions is tolerated" \
    '" >&2
                _bad=1
                continue
                ;;' '" >&2
                continue
                ;;'
mutate "a partition on another disk is tolerated" \
    'the disk of the verified root" >&2
            _bad=1' 'the disk of the verified root" >&2'
mutate "the disk of a partition is not compared with the boot disk" \
    'if [ "${_on}" != "${_disk}" ]; then' 'if false; then'
mutate "a verified root that spans two disks is tolerated" \
    'elif [ "${_disk}" != "${_this}" ]; then' 'elif false; then'
mutate "links are made although the layout was refused" \
    '[ "${_bad}" -eq 0 ] || return 1' '[ "${_bad}" -eq 0 ] || true'
mutate "the links of an earlier layout survive" \
    'rm -f "${_out}"/*' ':'
mutate "the disk of a partition is the partition itself" \
    'basename "$(dirname "${_sys}")"' 'basename "${_sys}"'

echo "disk layout contract OK"
