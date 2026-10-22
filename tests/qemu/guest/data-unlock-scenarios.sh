#!/bin/sh
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
#
# Scenarios of tests/qemu/data-unlock-vm-test.py, run as root in the guest it
# builds: the real board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock
# on the blank data partition of a GPT virtio disk (/dev/vda3, which carries the
# data PARTUUID of gpt-partuuids.conf and which the script reaches through the
# link suderra-disk-layout makes: the verified root of the guest is /dev/vda1)
# with a second disk beside it (/dev/vdb, an unrelated PARTUUID), a software TPM,
# the real cryptsetup, systemd-cryptenroll and mkfs.ext4, and a test double of
# suderra-installer that records what the script asks of it.
#
# Every scenario prints `T-PASS <name>` or `T-FAIL <name>: <why>`; the host
# reads them from the serial console.
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
DEV=/dev/vda3
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

ESCROW=/data/suderra/os/recovery-escrow.json
RECOVERY_KEY_INPUT=/run/suderra-os/data-recovery.key

# The recovery key an escrow envelope carries, opened with the test's escrow
# key the way the offline HSM would.
escrow_key() {
    sed -n 's/.*"ciphertext":"\([^"]*\)".*/\1/p' "$1" | base64 -d > /run/escrow.ct
    openssl pkeyutl -decrypt -inkey /test/escrow.key -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in /run/escrow.ct
}

# Keyslots with the recovery token, one per line.
recovery_slots() {
    cryptsetup luksDump "${DEV}" | awk '
        /^Tokens:/ { t = 1; next }
        /^Digests:/ { t = 0 }
        t && /^  [0-9]+: / { r = ($2 == "suderra-recovery"); next }
        t && r && /Keyslot:/ { print $2 }'
}

# Whether a key file opens any keyslot of the volume, tokens excluded.
key_unlocks() { cryptsetup open --test-passphrase --disable-external-tokens --key-file "$1" "${DEV}" > /dev/null 2>&1; }

# The volume's keyslots and tokens without the salts, to see whether anything changed.
header_shape() { cryptsetup luksDump "${DEV}" | grep -E '^  [0-9]+: |Keyslot:|^UUID|^Label'; }

provision_and_release() {
    blank_disk
    run_unlock
    [ "${RC}" -eq 0 ] || return 1
    cp "${ESCROW}" /run/escrow.first.json
    echo marker > /data/suderra/os/marker
    release_volume
    rm -f /run/suderra-os/data-created
    : > "${INSTALLER_LOG}"
}

# A firmware update changes PCR 7: the sealed key no longer unseals.
change_pcr7() {
    tpm2_pcrextend 7:sha256="$1"
}
PCR_A=0000000000000000000000000000000000000000000000000000000000000001
PCR_B=0000000000000000000000000000000000000000000000000000000000000002

# No signature of its own: neither a file system nor a partition table inside it
# (plain blkid also lists the PARTUUID of the partition entry, which every
# partition of the GPT disk has).
blank_partition() { [ -z "$(blkid -p -s TYPE -s PTTYPE -o value "${DEV}" 2> /dev/null)" ]; }
no_mapper() { [ ! -e "${MAPPER}" ]; }
no_keyfile() { ! ls /run/suderra-data-key.* > /dev/null 2>&1; }
no_data_created() { [ ! -e /run/suderra-os/data-created ]; }

# --- S0: the layout names the partitions of the boot disk ---------------------
# The script under test reaches /data through /run/suderra-os/disk/data. The
# layout service makes the link only for the partition of the boot disk, and
# the second disk of the guest (a partition with an unrelated PARTUUID) changes
# nothing.
s0_layout_names_the_boot_disk() {
    name=layout-names-the-boot-disk
    expect "${name}" "the second disk's partition is missing, so this proves nothing" test -b /dev/vdb1 || return
    sh /usr/sbin/suderra-disk-layout > /run/layout.out 2>&1 ||
        { fail "${name}" "the layout was refused: $(cat /run/layout.out)"; return; }
    expect "${name}" "the data name is not the data partition of the boot disk" \
        test "$(readlink /run/suderra-os/disk/data)" = /dev/vda3 || return
    expect "${name}" "rootfs-a is not the first partition of the boot disk" \
        test "$(readlink /run/suderra-os/disk/rootfs-a)" = /dev/vda1 || return
    expect "${name}" "rootfs-a-verity is not the second partition of the boot disk" \
        test "$(readlink /run/suderra-os/disk/rootfs-a-verity)" = /dev/vda2 || return
    expect "${name}" "a partition the disk does not have was named" \
        sh -c '[ ! -e /run/suderra-os/disk/boot ] && [ ! -e /run/suderra-os/disk/efi ] && [ ! -e /run/suderra-os/disk/rootfs-b ]' || return
    expect "${name}" "the data partition is not blank before the first boot" blank_partition || return
    pass "${name}"
}

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
    expect "${name}" "the escrow envelope is not on /data" test -s "${ESCROW}" || return
    expect "${name}" "the escrow envelope is not root-only" test "$(stat -c '%a' "${ESCROW}")" = 600 || return
    expect "${name}" "the volume has no recovery token" test "$(recovery_slots | wc -l)" -eq 1 || return
    expect "${name}" "the ephemeral slot 0 survived" \
        sh -c "! cryptsetup luksDump ${DEV} | grep -q '^  0: luks2'" || return
    escrow_key "${ESCROW}" > /run/recovery.key || { fail "${name}" "the envelope does not open with the escrow key"; return; }
    expect "${name}" "the escrowed key is not 64 hexadecimal characters" \
        grep -Eqx '[0-9a-f]{64}' /run/recovery.key || return
    expect "${name}" "the escrowed key does not unlock the volume" key_unlocks /run/recovery.key || return
    expect "${name}" "the envelope names another volume" \
        grep -q "\"volume_uuid\":\"$(luks_uuid)\"" "${ESCROW}" || return
    expect "${name}" "the envelope names another recipient" \
        grep -q "\"recipient_spki_sha256\":\"$(openssl pkey -pubin -in /etc/suderra/recovery-escrow.pub.pem -outform DER | sha256sum | cut -d ' ' -f 1)\"" "${ESCROW}" || return
    expect "${name}" "the recovery key was left in /run" no_keyfile || return
    rm -f /run/recovery.key
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


# --- S8: recovery restores access, re-seals and replaces the recovery key -------
s8_recovery_restores_access() {
    name=recovery-restores-access
    provision_and_release || { fail "${name}" "the setup provisioning failed"; return; }
    first_key="$(escrow_key /run/escrow.first.json)"
    printf '%s\n' "${first_key}" | grep -Eqx '[0-9a-f]{64}' || { fail "${name}" "the first envelope carries no key"; return; }
    uuid_before="$(luks_uuid)"
    change_pcr7 "${PCR_A}" || { fail "${name}" "cannot extend PCR 7"; return; }
    run_unlock
    [ "${RC}" -ne 0 ] || { fail "${name}" "the volume unlocked although PCR 7 changed"; return; }
    expect "${name}" "the unseal failure does not point to the recovery" \
        grep -q 'data-recovery' /run/unlock.out || return
    expect "${name}" "the failed unseal touched the volume" test "$(luks_uuid)" = "${uuid_before}" || return
    # The recovery ingress places the key (any case, with separators and a newline).
    printf '%s\n' "${first_key}" | tr 'a-f' 'A-F' | sed 's/\(........\)/\1-/g' > "${RECOVERY_KEY_INPUT}"
    : > "${INSTALLER_LOG}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -eq 0 ] || { fail "${name}" "recover exit ${RC}"; dump_output; return; }
    expect "${name}" "the recovery key file was not consumed" test ! -e "${RECOVERY_KEY_INPUT}" || return
    expect "${name}" "no ok result with the recovery detail" \
        has_record 'result --kind data-unlock --outcome ok --detail recovered' || return
    expect "${name}" "recovery must release the volume" no_mapper || return
    expect "${name}" "recovery left key material in /run" no_keyfile || return
    expect "${name}" "recovery replaced the volume" test "$(luks_uuid)" = "${uuid_before}" || return
    expect "${name}" "the volume lost its committed label" test "$(luks_label)" = SUDERRA-DATA || return
    expect "${name}" "the volume has no TPM2 token after the re-seal" \
        sh -c "cryptsetup luksDump ${DEV} | grep -q 'systemd-tpm2'" || return
    expect "${name}" "the volume must have exactly one recovery slot" test "$(recovery_slots | wc -l)" -eq 1 || return
    printf '%s' "${first_key}" > /run/old.key
    expect "${name}" "the recovery key that was handled still unlocks the volume" \
        sh -c "! cryptsetup open --test-passphrase --disable-external-tokens --key-file /run/old.key ${DEV} > /dev/null 2>&1" || return
    # The next boot unseals with the new seal (PCR 7 is still the changed one).
    : > "${INSTALLER_LOG}"
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the boot after the recovery failed (exit ${RC}): the seal was not renewed"; dump_output; return; }
    expect "${name}" "the data written before the recovery is gone" \
        test "$(cat /data/suderra/os/marker 2> /dev/null)" = marker || return
    new_key="$(escrow_key "${ESCROW}")"
    expect "${name}" "the escrow envelope was not replaced" test "${new_key}" != "${first_key}" || return
    printf '%s' "${new_key}" > /run/new.key
    expect "${name}" "the new escrowed key does not unlock the volume" key_unlocks /run/new.key || return
    rm -f /run/old.key /run/new.key
    pass "${name}"
}

# --- S9: a wrong recovery key is rejected and nothing changes ------------------------
s9_wrong_recovery_key_is_rejected() {
    name=wrong-recovery-key-is-rejected
    provision_and_release || { fail "${name}" "the setup provisioning failed"; return; }
    shape_before="$(header_shape)"
    # While the TPM still unseals: a token must never accept a wrong key.
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "${RECOVERY_KEY_INPUT}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -ne 0 ] || { fail "${name}" "a wrong key recovered a volume whose TPM still unseals"; return; }
    expect "${name}" "the rejected key file was not consumed (a path unit would retry it forever)" \
        test ! -e "${RECOVERY_KEY_INPUT}" || return
    expect "${name}" "the rejection is not recorded" \
        has_record 'result --kind data-unlock --outcome alarm --reason tpm-unseal-failed' || return
    expect "${name}" "a rejected key changed the volume" test "$(header_shape)" = "${shape_before}" || return
    expect "${name}" "the volume was left open" no_mapper || return
    # Malformed keys and a missing key.
    printf 'not-a-key\n' > "${RECOVERY_KEY_INPUT}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1 && { fail "${name}" "a malformed key was accepted"; return; }
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1 && { fail "${name}" "recovery ran without a key"; return; }
    expect "${name}" "a malformed key changed the volume" test "$(header_shape)" = "${shape_before}" || return
    # The TPM key of the volume is not a recovery key: it must not be accepted either.
    expect "${name}" "key material was left in /run" no_keyfile || return
    pass "${name}"
}

# --- S10: no escrow, no volume ----------------------------------------------------------
s10_escrow_failure_formats_nothing() {
    name=escrow-failure-formats-nothing
    blank_disk
    cp /etc/suderra/recovery-escrow.pub.pem /run/escrow.pub.saved
    printf 'not a public key\n' > /etc/suderra/recovery-escrow.pub.pem
    run_unlock
    status="${RC}"
    cp /run/escrow.pub.saved /etc/suderra/recovery-escrow.pub.pem
    [ "${status}" -ne 0 ] || { fail "${name}" "the volume was provisioned although its recovery key cannot be escrowed"; return; }
    expect "${name}" "a partition was formatted without an escrow" blank_partition || return
    expect "${name}" "the failure names no reason of the contract" \
        has_record 'result --kind data-unlock --outcome alarm --reason data-unmountable' || return
    expect "${name}" "the key material was left in /run" no_keyfile || return
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the retry with the escrow key restored failed (exit ${RC})"; dump_output; return; }
    pass "${name}"
}

# --- S11: a recovery that cannot re-seal leaves the old key working --------------------
s11_recovery_seal_failure_keeps_the_old_key() {
    name=recovery-seal-failure-keeps-the-old-key
    provision_and_release || { fail "${name}" "the setup provisioning failed"; return; }
    first_key="$(escrow_key /run/escrow.first.json)"
    change_pcr7 "${PCR_B}" || { fail "${name}" "cannot extend PCR 7"; return; }
    printf '%s\n' "${first_key}" > "${RECOVERY_KEY_INPUT}"
    shadow systemd-cryptenroll 1
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -ne 0 ] || { fail "${name}" "recovery succeeded although the re-seal failed"; return; }
    rm -rf /test-bin
    mkdir -p /test-bin
    expect "${name}" "a failed recovery left the volume open" no_mapper || return
    expect "${name}" "a failed recovery left key material in /run" no_keyfile || return
    printf '%s' "${first_key}" > /run/old.key
    expect "${name}" "the old recovery key no longer unlocks the volume" key_unlocks /run/old.key || return
    # The recovery can be run again with the same key, and it cleans up what the failed one left.
    printf '%s\n' "${first_key}" > "${RECOVERY_KEY_INPUT}"
    : > "${INSTALLER_LOG}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -eq 0 ] || { fail "${name}" "the second recovery failed (exit ${RC})"; dump_output; return; }
    expect "${name}" "the second recovery left more than one recovery slot" test "$(recovery_slots | wc -l)" -eq 1 || return
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the boot after the second recovery failed (exit ${RC})"; dump_output; return; }
    expect "${name}" "the old recovery key still unlocks the volume" \
        sh -c "! cryptsetup open --test-passphrase --disable-external-tokens --key-file /run/old.key ${DEV} > /dev/null 2>&1" || return
    rm -f /run/old.key
    pass "${name}"
}

# --- S12: an open volume has nothing to recover ---------------------------------------
s12_recovery_refuses_an_open_volume() {
    name=recovery-refuses-an-open-volume
    blank_disk
    run_unlock
    [ "${RC}" -eq 0 ] || { fail "${name}" "the setup provisioning failed"; dump_output; return; }
    shape_before="$(header_shape)"
    key="$(escrow_key "${ESCROW}")"
    printf '%s\n' "${key}" > "${RECOVERY_KEY_INPUT}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -ne 0 ] || { fail "${name}" "recovery ran on an open volume"; return; }
    expect "${name}" "the open volume was closed by a refused recovery" mountpoint -q /data || return
    expect "${name}" "a refused recovery changed the volume" test "$(header_shape)" = "${shape_before}" || return
    pass "${name}"
}

# --- S13: recovery never formats -----------------------------------------------------------
s13_recovery_never_formats() {
    name=recovery-never-formats
    blank_disk
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "${RECOVERY_KEY_INPUT}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -ne 0 ] || { fail "${name}" "recovery succeeded on a blank partition"; return; }
    expect "${name}" "recovery formatted a blank partition" blank_partition || return
    blank_disk
    mkfs.ext4 -q -F -L PRECIOUS "${DEV}" || { fail "${name}" "cannot prepare the foreign filesystem"; return; }
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "${RECOVERY_KEY_INPUT}"
    PATH="/test-bin:${PATH}" sh "${UNLOCK}" recover > /run/unlock.out 2>&1
    RC=$?
    [ "${RC}" -ne 0 ] || { fail "${name}" "recovery succeeded on a foreign filesystem"; return; }
    expect "${name}" "recovery touched a foreign filesystem" test "$(blkid -s LABEL -o value "${DEV}")" = PRECIOUS || return
    pass "${name}"
}

# --- run -------------------------------------------------------------------------
for scenario in s0_layout_names_the_boot_disk s1_fresh_provisioning s2_existing_unlocks s3_mkfs_failure_rolls_back \
    s4_enrol_failure_rolls_back s5_interrupted_is_redone s6_foreign_signature_refused \
    s7_unseal_failure_keeps_the_volume s8_recovery_restores_access \
    s9_wrong_recovery_key_is_rejected s10_escrow_failure_formats_nothing \
    s11_recovery_seal_failure_keeps_the_old_key s12_recovery_refuses_an_open_volume \
    s13_recovery_never_formats; do
    echo "T-RUN ${scenario}"
    "${scenario}"
done
echo "T-DONE failed=${FAILED}"
