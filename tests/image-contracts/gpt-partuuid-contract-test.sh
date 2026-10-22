#!/usr/bin/env bash
#
# Partition identity of the production images (ADR-048 DEC-18.1; EI-050).
#
# A partition label or a file-system label is whatever a removable disk says it
# is, so a USB stick labelled rootfs-a or data could be resolved instead of the
# boot disk's partition. Everything that names a partition of the production disk
# uses the GPT PARTUUID the image build writes (board/suderra/common/
# gpt-partuuids.conf), and this test holds each consumer to that one list:
#
#   - the genimage-prod configs (ARM) and the A/B x86 config give the partitions
#     their PARTUUID;
#   - RAUC's slots, the boot mounts and the /data device are named by it (a
#     placeholder post-build.sh renders), by no label;
#   - the signed kernel command line carries root_partuuid and hash_partuuid, and
#     the verity initramfs resolves the two partitions by them, refuses when a
#     second device carries the same PARTUUID, and maps the verity device so that
#     corruption restarts the machine instead of returning garbage.
#
# The initramfs is built by the production producer's own function and its
# resolver is run on stand-in device lists; the rest is static.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/scripts/ci/gpt-partuuids.py"
LIST="${ROOT}/board/suderra/common/gpt-partuuids.conf"
PA="${ROOT}/scripts/production-artifacts.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the list and the genimage configs ---------------------------------------
echo "the list and the genimage configs"
python3 -I "${TOOL}" check-genimage \
    "${ROOT}/board/suderra/aarch64-rpi4/genimage-prod.cfg" \
    "${ROOT}/board/suderra/aarch64-revpi-connect4/genimage-prod.cfg" \
    "${ROOT}/board/suderra/x86_64/genimage.cfg" || fail "a genimage config disagrees with ${LIST}"
# Every partition of the A/B layouts is in the list.
for name in boot efi rootfs-a rootfs-a-verity rootfs-b rootfs-b-verity data; do
    python3 -I "${TOOL}" get "${name}" >/dev/null || fail "${name} is not in ${LIST}"
done

mut_cfg="${WORK}/prod.cfg"
cp "${ROOT}/board/suderra/aarch64-rpi4/genimage-prod.cfg" "${mut_cfg}"
sed -i '0,/partition-uuid = "[^"]*"/s//partition-uuid = "00000000-0000-4000-8000-000000000000"/' "${mut_cfg}"
if python3 -I "${TOOL}" check-genimage "${mut_cfg}" >/dev/null 2>&1; then
    fail "check-genimage accepted a partition whose PARTUUID is not the list's"; fi
echo "  rejects: a genimage partition with another PARTUUID"
sed -i '/partition-uuid = /d' "${mut_cfg}"
if python3 -I "${TOOL}" check-genimage "${mut_cfg}" >/dev/null 2>&1; then
    fail "check-genimage accepted a layout with no PARTUUID at all"; fi
echo "  rejects: a genimage layout without PARTUUIDs"

# --- the image carries the list once; consumers use the verified names --------
# The PARTUUIDs are rendered into /usr/lib/suderra/partuuids.conf, which
# suderra-disk-layout reads; RAUC's slots, the boot mount and /data name the links
# it makes, and no consumer names a by-partuuid path (a public PARTUUID is only a
# claim: disk-layout-contract-test.sh holds every consumer to that and runs the
# script).
echo "consumers"
TABLE="${ROOT}/board/suderra/common/rootfs-overlay/usr/lib/suderra/partuuids.conf"
grep -q '@SUDERRA_PARTUUID_[A-Z_]*@' "${TABLE}" || fail "${TABLE} names no partition by PARTUUID placeholder"
cp "${TABLE}" "${WORK}/partuuids.conf"
python3 -I "${TOOL}" render "${WORK}/partuuids.conf"
python3 -I "${TOOL}" unrendered "${WORK}/partuuids.conf"
grep -qxF "rootfs-b-verity $(python3 -I "${TOOL}" get rootfs-b-verity)" "${WORK}/partuuids.conf" ||
    fail "render did not name slot B's verity partition"
grep -qxF "data $(python3 -I "${TOOL}" get data)" "${WORK}/partuuids.conf" || fail "render did not name the data partition"
grep -qxF "boot $(python3 -I "${TOOL}" get boot)" "${WORK}/partuuids.conf" || fail "render did not name the boot partition"
# Idempotent (Buildroot reruns post-build on a filled target).
cp "${WORK}/partuuids.conf" "${WORK}/again"
python3 -I "${TOOL}" render "${WORK}/again"
cmp -s "${WORK}/partuuids.conf" "${WORK}/again" || fail "render is not idempotent"
echo "  renders every placeholder, idempotently"
printf 'device=/dev/disk/by-partuuid/@SUDERRA_PARTUUID_ROOTFS_C@\n' > "${WORK}/unknown"
if python3 -I "${TOOL}" render "${WORK}/unknown" >/dev/null 2>&1; then fail "render accepted a placeholder that names no partition"; fi
echo "  rejects: a placeholder that names no partition"
python3 -I "${TOOL}" unrendered "${TABLE}" >/dev/null 2>&1 && fail "unrendered passed a file that still has placeholders"
echo "  rejects: a placeholder left in a target file"
grep -q 'gpt-partuuids.py" render' "${ROOT}/board/suderra/common/post-build.sh" || fail "post-build.sh does not render the partition PARTUUIDs"
grep -q 'gpt-partuuids.py" unrendered' "${ROOT}/board/suderra/common/post-build.sh" || fail "post-build.sh does not fail on a left placeholder"
RAUC="${ROOT}/package/suderra-rauc-config"
grep -q 'rootfs-a-verity' "${RAUC}/system.conf.arm" || fail "the verity slot is not named"
for f in "${RAUC}/system.conf" "${RAUC}/system.conf.arm" "${RAUC}/boot.mount" "${RAUC}/boot.mount.arm" \
    "${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"; do
    if grep -vE '^[[:space:]]*#' "${f}" | grep -qE 'by-partuuid|by-partlabel|SUDERRA_PARTUUID'; then
        fail "${f} names a partition by PARTUUID or label"; fi
    # The dev image mounts its MBR data partition by the SUDERRA-DATA file-system
    # label (EI-044's dev half: an MBR disk has no GPT PARTUUID, its names are the
    # disk signature, which the three dev layouts do not set yet).
    if grep -vE '^[[:space:]]*#' "${f}" | grep -v 'SUDERRA-DATA' | grep -qE 'by-label'; then
        fail "${f} still names a partition by a label"; fi
done
echo "  no consumer names a partition by a PARTUUID or a label"

# --- the verity initramfs: the signed command line, the resolver, the table ----
echo "verity initramfs"
need() { command -v "$1" >/dev/null 2>&1 || { echo "SKIP: $1 is missing" >&2; exit 77; }; }
for t in cpio gzip veritysetup mke2fs; do need "${t}"; done

# shellcheck disable=SC1090
. "${PA}"
BIN="${WORK}/images"
TGT="${WORK}/target"
mkdir -p "${BIN}" "${TGT}/bin" "${TGT}/sbin" "${TGT}/lib"
for f in bin/busybox bin/mount bin/sleep sbin/blkid sbin/dmsetup sbin/switch_root; do
    printf 'x' > "${TGT}/${f}"
    chmod 0755 "${TGT}/${f}"
done
printf 'lib' > "${TGT}/lib/placeholder"
dd if=/dev/zero of="${BIN}/rootfs.ext4" bs=1M count=8 status=none
mke2fs -q -F -t ext4 "${BIN}/rootfs.ext4"
generate_verity "${BIN}" >/dev/null

for arch in arm x86; do
    case "${arch}" in
        arm) write_arm_verity_cmdline "${BIN}" A ;;
        x86) write_x86_verity_cmdline "${BIN}" A ;;
    esac
    cmdline="$(cat "${BIN}/suderra-A.cmdline")"
    for token in \
        "suderra.verity.root_partuuid=$(python3 -I "${TOOL}" get rootfs-a)" \
        "suderra.verity.hash_partuuid=$(python3 -I "${TOOL}" get rootfs-a-verity)"; do
        case " ${cmdline} " in *" ${token} "*) ;; *) fail "${arch} command line lacks ${token}" ;; esac
    done
    case "${cmdline}" in *partlabel*) fail "${arch} command line still names a partition by label" ;; esac
    write_${arch}_verity_cmdline "${BIN}" B
    case " $(cat "${BIN}/suderra-B.cmdline") " in
        *" suderra.verity.root_partuuid=$(python3 -I "${TOOL}" get rootfs-b) "*) ;;
        *) fail "${arch} slot B's command line does not name rootfs-b" ;;
    esac
    echo "  ${arch}: the signed command line names the slot's partitions by PARTUUID"
done

build_verity_initramfs "${BIN}" "${TGT}" A "${BIN}/A.initrd" >/dev/null
mkdir "${WORK}/initrd"
(cd "${WORK}/initrd" && gzip -dc "${BIN}/A.initrd" | cpio -id --quiet)
INIT="${WORK}/initrd/init"
[ -s "${INIT}" ] || fail "no /init in the initramfs"
grep -q 'partlabel\|PARTLABEL' "${INIT}" && fail "the initramfs still resolves partitions by label"
grep -qF 'suderra.verity.root_partuuid' "${INIT}" || fail "the initramfs does not read root_partuuid"
grep -qF 'suderra.verity.hash_partuuid' "${INIT}" || fail "the initramfs does not read hash_partuuid"
# Corruption becomes a restart (a reboot of A/B), not garbage returned to the reader.
grep -qE '^table=.* 1 restart_on_corruption"$' "${INIT}" || fail "the verity table has no restart_on_corruption (EI-050)"
echo "  /init reads the PARTUUIDs and maps the verity device with restart_on_corruption"

# Run the resolver on stand-in blkid answers.
python3 -I - "${INIT}" "${WORK}/resolver.sh" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r"^find_partuuid\(\) \{\n.*?^\}\n", text, re.S | re.M)
assert m, "find_partuuid is not in /init"
body = m.group(0)
# The stand-in devices are plain files, not block devices.
assert '[ -b "${candidate}" ]' in body, "the resolver no longer checks for a block device"
body = body.replace('[ -b "${candidate}" ]', '[ -e "${candidate}" ]')
open(sys.argv[2], "w").write(body)
EOF
mkdir "${WORK}/shim"
cat > "${WORK}/shim/blkid" <<'EOF'
#!/bin/sh
# blkid -t PARTUUID=<uuid> -o device: the devices listed for <uuid> in $SHIM_DEVICES
uuid="${2#PARTUUID=}"
sed -n "s/^${uuid} //p" "${SHIM_DEVICES}" | tr ' ' '\n'
EOF
printf '#!/bin/sh\nexit 0\n' > "${WORK}/shim/sleep"
chmod 0755 "${WORK}/shim/blkid" "${WORK}/shim/sleep"
sed -i "s#/sbin/blkid#${WORK}/shim/blkid#; s#/usr/sbin/blkid#${WORK}/shim/blkid#" "${WORK}/resolver.sh"
grep -q "${WORK}/shim/blkid" "${WORK}/resolver.sh" || fail "the resolver does not call the blkid path of the initramfs"
touch "${WORK}/disk-a" "${WORK}/disk-b"
resolve() { # <uuid> <devices-file>
    SHIM_DEVICES="$2" PATH="${WORK}/shim:${PATH}" sh -c ". '${WORK}/resolver.sh'; find_partuuid '$1'" 2>"${WORK}/resolve.err"
}
ROOT_UUID="$(python3 -I "${TOOL}" get rootfs-a)"
printf '%s %s\n' "${ROOT_UUID}" "${WORK}/disk-a" > "${WORK}/one"
[ "$(resolve "${ROOT_UUID}" "${WORK}/one")" = "${WORK}/disk-a" ] || fail "the resolver did not return the one device with the PARTUUID"
echo "  resolves the one device that carries the PARTUUID"
printf '%s %s %s\n' "${ROOT_UUID}" "${WORK}/disk-a" "${WORK}/disk-b" > "${WORK}/two"
if out="$(resolve "${ROOT_UUID}" "${WORK}/two")"; then fail "the resolver accepted two devices with the same PARTUUID: ${out}"; fi
grep -q 'on 2 devices' "${WORK}/resolve.err" || fail "the resolver refused two devices without saying so"
echo "  refuses when a second device carries the PARTUUID"
: > "${WORK}/none"
if resolve "${ROOT_UUID}" "${WORK}/none" >/dev/null; then fail "the resolver returned a device for an absent PARTUUID"; fi
echo "  fails when no device carries the PARTUUID"
printf '%s %s\n' "$(python3 -I "${TOOL}" get rootfs-b)" "${WORK}/disk-b" > "${WORK}/other"
if resolve "${ROOT_UUID}" "${WORK}/other" >/dev/null; then fail "the resolver took a device with another PARTUUID"; fi
echo "  does not take a device with another PARTUUID"

echo "partition identity contract OK"
