#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Scenarios of tests/qemu/data-unlock-vm-test.py, run as root in the guest it
# builds: the real board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock
# on a blank virtio disk (/dev/vda, linked as /dev/disk/by-partlabel/data) with
# a software TPM, the real cryptsetup, systemd-cryptenroll and mkfs.ext4, and a
# test double of suderra-installer that records what the script asks of it.
#
# Every scenario prints `T-PASS <name>` or `T-FAIL <name>: <why>`; the host
# reads them from the serial console.
set -u

UNLOCK=/usr/sbin/suderra-data-unlock
DEV=/dev/vda
MAPPER=/dev/mapper/suderra-data
INSTALLER_LOG=/run/installer.log
FAILED=0

pass() { echo "T-PASS $1"; }
fail() {
    echo "T-FAIL $1: $2"
    FAILED=1
}

# --- helpers -----------------------------------------------------------------
release_volume() {
    for target in /var/log/suderra /var/lib/suderra /opt/suderra/edge /etc/dropbear \
        /var/lib/suderra-site /var/lib/chrony /var/lib/suderra-installer /var/lib/suderra-os; do
        umount "${target}" 2>/dev/null || true
    done
    umount /data 2>/dev/null || true
    [ -e "${MAPPER}" ] && cryptsetup close suderra-data
    return 0
}

blank_disk() {
    release_volume
    dd if=/dev/zero of="${DEV}" bs=1M count=32 conv=fsync status=none
    rm -f /run/suderra-os/data-created /run/suderra-data-key.* "${INSTALLER_LOG}"
    : > "${INSTALLER_LOG}"
    rm -rf /test-bin
    mkdir -p /test-bin
}

# Runs the script under test; the exit status is left in $RC, its output in
# /run/unlock.out.
run_unlock() {
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" > /run/unlock.out 2>&1
    RC=$?
}

# A command that is shadowed on PATH while a scenario runs.
shadow() {
    command_name="$1"
    status="$2"
    printf '#!/bin/sh\necho "%s: simulated failure (%s)" >&2\nexit %s\n' "${command_name}" "${status}" "${status}" > "/test-bin/${command_name}"
    chmod 0755 "/test-bin/${command_name}"
}

luks_label() { cryptsetup luksDump "${DEV}" | sed -n 's/^Label:[[:space:]]*//p' | head -n 1; }
luks_uuid() { cryptsetup luksDump "${DEV}" | sed -n 's/^UUID:[[:space:]]*//p' | head -n 1; }
fs_type() { blkid -s TYPE -o value "$1" 2>/dev/null; }
has_record() { grep -q -- "$1" "${INSTALLER_LOG}"; }

expect() {
    # expect <scenario> <description> <command...>
    scenario="$1"
    description="$2"
    shift 2
    if ! "$@"; then
        fail "${scenario}" "${description}"
        return 1
    fi
    return 0
}

dump_output() { sed 's/^/    | /' /run/unlock.out; }

blank_partition() { ! blkid "${DEV}" > /dev/null 2>&1; }
no_mapper() { [ ! -e "${MAPPER}" ]; }
no_keyfile() { ! ls /run/suderra-data-key.* > /dev/null 2>&1; }
no_data_created() { [ ! -e /run/suderra-os/data-created ]; }

# --- S1: a blank partition is provisioned ------------------------------------
s1_fresh_provisioning() {
    name=fresh-provisioning
    blank_disk
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "exit ${RC}"; dump_output; return; }
    expect "${name}" "/data is not mounted" mountpoint -q /data || return
    expect "${name}" "the filesystem is not ext4 on the mapper (mkfs.ext4 path)" \
        test "$(fs_type "${MAPPER}")" = ext4 || return
    expect "${name}" "the filesystem label" \
        test "$(blkid -s LABEL -o value "${MAPPER}")" = SUDERRA-DATA || return
    expect "${name}" "the LUKS label is not the committed label" \
        test "$(luks_label)" = SUDERRA-DATA || return
    expect "${name}" "the volume has no TPM2 token" \
        sh -c "cryptsetup luksDump ${DEV} | grep -q 'systemd-tpm2'" || return
    expect "${name}" "the ephemeral key file survived" no_keyfile || return
    expect "${name}" "no lifecycle factory call" has_record 'lifecycle factory' || return
    expect "${name}" "no data-unlock ok result" has_record 'result --kind data-unlock --outcome ok' || return
    expect "${name}" "the data-created evidence is missing" test -s /run/suderra-os/data-created || return
    expect "${name}" "/var/lib/suderra-os is not bound from /data" mountpoint -q /var/lib/suderra-os || return
    expect "${name}" "the lifecycle store is not on /data" test -f /data/suderra/os/lifecycle || return
    expect "${name}" "/data is not nosuid,nodev,noexec" \
        sh -c "grep ' /data ' /proc/mounts | grep -q 'nosuid' && grep ' /data ' /proc/mounts | grep -q 'nodev' && grep ' /data ' /proc/mounts | grep -q 'noexec'" || return
    echo marker > /data/suderra/os/marker
    pass "${name}"
}

# --- S2: an existing volume unlocks and keeps its data -------------------------
s2_existing_unlocks() {
    name=existing-volume-unlocks
    release_volume
    rm -f /run/suderra-os/data-created
    : > "${INSTALLER_LOG}"
    uuid_before="$(luks_uuid)"
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "exit ${RC}"; dump_output; return; }
    expect "${name}" "the volume was not unlocked and mounted" mountpoint -q /data || return
    expect "${name}" "the data written before is gone (the volume was formatted again)" \
        test "$(cat /data/suderra/os/marker 2> /dev/null)" = marker || return
    expect "${name}" "the volume was replaced" test "$(luks_uuid)" = "${uuid_before}" || return
    expect "${name}" "an unlock must not claim that /data was created" no_data_created || return
    expect "${name}" "an unlock must not create the lifecycle store" \
        sh -c "! grep -q 'lifecycle factory' ${INSTALLER_LOG}" || return
    pass "${name}"
}

# --- S3: mkfs.ext4 fails (EI-078): the volume is rolled back --------------------
s3_mkfs_failure_rolls_back() {
    name=mkfs-failure-rolls-back
    blank_disk
    shadow mkfs.ext4 127
    run_unlock
    [ "${RC}" -ne 0 ] || { fail "${name}" "the script succeeded although mkfs.ext4 failed"; return; }
    expect "${name}" "the partition is not blank again (a sealed volume without a filesystem is left)" blank_partition || return
    expect "${name}" "the mapper is still open" no_mapper || return
    expect "${name}" "the data-created evidence survived the rollback" no_data_created || return
    expect "${name}" "the ephemeral key file survived" no_keyfile || return
    expect "${name}" "the alarm names no reason of the contract" \
        has_record 'result --kind data-unlock --outcome alarm --reason data-unmountable' || return
    expect "${name}" "the alarm does not say the volume was rolled back" has_record 'rolled back' || return
    # The next boot provisions it again.
    rm -rf /test-bin
    mkdir -p /test-bin
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the retry exit ${RC}"; dump_output; return; }
    expect "${name}" "the retry did not create the filesystem" test "$(fs_type "${MAPPER}")" = ext4 || return
    pass "${name}"
}

# --- S4: the TPM enrolment fails: the volume is rolled back ---------------------
s4_enrol_failure_rolls_back() {
    name=enrol-failure-rolls-back
    blank_disk
    shadow systemd-cryptenroll 1
    run_unlock
    [ "${RC}" -ne 0 ] || { fail "${name}" "the script succeeded although the enrolment failed"; return; }
    expect "${name}" "the partition is not blank again (the retry never happens)" blank_partition || return
    expect "${name}" "the alarm names no reason of the contract" \
        has_record 'result --kind data-unlock --outcome alarm --reason tpm-unseal-failed' || return
    rm -rf /test-bin
    mkdir -p /test-bin
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the retry exit ${RC}"; dump_output; return; }
    pass "${name}"
}

# --- S5: an unfinished provisioning (power cut) is provisioned again -------------
s5_interrupted_is_redone() {
    name=interrupted-provisioning-is-redone
    blank_disk
    head -c 64 /dev/urandom > /run/lost.key
    cryptsetup luksFormat --type luks2 --label suderra-provisioning --batch-mode \
        --key-file /run/lost.key "${DEV}" || { fail "${name}" "cannot create the unfinished volume"; return; }
    rm -f /run/lost.key
    uuid_before="$(luks_uuid)"
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "exit ${RC}"; dump_output; return; }
    expect "${name}" "the unfinished volume was kept" test "$(luks_uuid)" != "${uuid_before}" || return
    expect "${name}" "the volume is not committed" test "$(luks_label)" = SUDERRA-DATA || return
    expect "${name}" "the filesystem is missing" test "$(fs_type "${MAPPER}")" = ext4 || return
    pass "${name}"
}

# --- S6: a partition with another signature is never formatted --------------------
s6_foreign_signature_refused() {
    name=foreign-signature-refused
    blank_disk
    mkfs.ext4 -q -F -L PRECIOUS "${DEV}" || { fail "${name}" "cannot prepare the foreign filesystem"; return; }
    run_unlock
    [ "${RC}" -ne 0 ] || { fail "${name}" "the script succeeded on a foreign filesystem"; return; }
    expect "${name}" "the foreign filesystem was touched" test "$(blkid -s LABEL -o value "${DEV}")" = PRECIOUS || return
    expect "${name}" "the refusal is not recorded" \
        has_record 'result --kind data-unlock --outcome alarm --reason data-unmountable' || return
    pass "${name}"
}

# --- S7: an existing volume whose TPM policy no longer unseals is never provisioned again
s7_unseal_failure_keeps_the_volume() {
    name=unseal-failure-keeps-the-volume
    blank_disk
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the setup provisioning failed (exit ${RC})"; dump_output; return; }
    release_volume
    rm -f /run/suderra-os/data-created
    : > "${INSTALLER_LOG}"
    uuid_before="$(luks_uuid)"
    # A firmware update changes PCR 7: the sealed key no longer unseals.
    tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000001 \
        || { fail "${name}" "cannot extend PCR 7"; return; }
    run_unlock
    [ "${RC}" -ne 0 ] || { fail "${name}" "the volume unlocked although PCR 7 changed"; return; }
    expect "${name}" "the alarm names no reason of the contract" \
        has_record 'result --kind data-unlock --outcome alarm --reason tpm-unseal-failed' || return
    expect "${name}" "the volume was replaced: an existing volume must never be provisioned again" \
        test "$(luks_uuid)" = "${uuid_before}" || return
    expect "${name}" "the volume lost its committed label" test "$(luks_label)" = SUDERRA-DATA || return
    expect "${name}" "the volume lost its TPM2 token" \
        sh -c "cryptsetup luksDump ${DEV} | grep -q 'systemd-tpm2'" || return
    expect "${name}" "an unseal failure must not claim that /data was created" no_data_created || return
    expect "${name}" "the mapper is open without its key" no_mapper || return
    pass "${name}"
}

# --- run -------------------------------------------------------------------------
for scenario in s1_fresh_provisioning s2_existing_unlocks s3_mkfs_failure_rolls_back \
    s4_enrol_failure_rolls_back s5_interrupted_is_redone s6_foreign_signature_refused \
    s7_unseal_failure_keeps_the_volume; do
    echo "T-RUN ${scenario}"
    "${scenario}"
done
echo "T-DONE failed=${FAILED}"
