#!/bin/sh
# data-luks-provision-contract-test — /data LUKS2 provisioning sözleşmesi (RT-1, RT-5).
#
# İki katman doğrular:
#   1. STATİK: suderra-data-provision + suderra-data-unlock beklenen güvenlik
#      özelliklerini taşıyor mu (idempotency, fail-closed, TPM2-default, keyfile
#      opt-in, provision-or-unlock wiring) + prod defconfig'lerde systemd-cryptsetup.
#   2. RUNTIME (mümkünse): loopback bir cihazda gerçek LUKS2 header döngüsü
#      (format → keyslot ekle/çıkar → isLuks/v2). device-mapper yoksa (bazı
#      konteynerler) mapper open/mkfs adımı AÇIKÇA atlanır — sessiz geçiş YOK;
#      o adım CI QEMU-swtpm lane'i ve G5 donanım kanıtıyla kapanır.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROVISION="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-provision"
UNLOCK="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"
fail() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. STATİK sözleşme
# ---------------------------------------------------------------------------
[ -f "${PROVISION}" ] || fail "missing suderra-data-provision"
[ -x "${PROVISION}" ] || fail "suderra-data-provision must be executable"

grep -q 'cryptsetup isLuks' "${PROVISION}" \
    || fail "provision must idempotency-check via cryptsetup isLuks"
grep -q 'already provisioned' "${PROVISION}" \
    || fail "provision must no-op when already LUKS2 (idempotent)"
grep -q 'luksFormat --type luks2' "${PROVISION}" \
    || fail "provision must create LUKS2 (not LUKS1)"
grep -q 'systemd-cryptenroll' "${PROVISION}" \
    || fail "provision must support TPM2 seal via systemd-cryptenroll"
grep -q 'tpm2-pcrs' "${PROVISION}" \
    || fail "TPM2 seal must bind to PCR policy (boot-state)"
grep -q 'luksRemoveKey' "${PROVISION}" \
    || fail "provision must remove the bootstrap key so only the real key opens"
# Fail-closed: TPM yoksa ve mod açıkça keyfile değilse zayıf tier'a düşmemeli.
grep -q 'refusing to provision a weak keyfile' "${PROVISION}" \
    || fail "provision must fail-closed (no silent weak keyfile tier) when no TPM"

# F2 (crash-safety): gerçek anahtar mkfs'ten ÖNCE enroll edilmeli — enroll satırı
# mkfs satırından önce gelmeli, aksi halde format→enroll penceresi mkfs'i kapsar.
enroll_ln="$(grep -n 'systemd-cryptenroll' "${PROVISION}" | head -n1 | cut -d: -f1)"
mkfs_ln="$(grep -n 'mkfs.ext4' "${PROVISION}" | head -n1 | cut -d: -f1)"
if [ -z "${enroll_ln}" ] || [ -z "${mkfs_ln}" ] || [ "${enroll_ln}" -ge "${mkfs_ln}" ]; then
    fail "provision must enroll the real key BEFORE mkfs (crash-safe ordering, F2)"
fi

# F3: mevcut fs/imza taşıyan partition'ı ezmemeli (blkid guard).
if ! grep -q 'blkid' "${PROVISION}" || ! grep -q 'refusing to format' "${PROVISION}"; then
    fail "provision must refuse to format a partition carrying an existing signature (F3)"
fi

# data-unlock provision-or-unlock olmalı ve string sözleşmesini korumalı.
grep -q 'suderra-data-provision' "${UNLOCK}" \
    || fail "data-unlock must invoke suderra-data-provision on first boot"
grep -q 'cryptsetup isLuks' "${UNLOCK}" \
    || fail "data-unlock must still gate on cryptsetup isLuks"
grep -q 'systemd-cryptsetup attach' "${UNLOCK}" \
    || fail "data-unlock must keep TPM2-backed systemd-cryptsetup unlock path"

# F1: keyfile ile provision edilmiş cihaz keyfile ile de AÇILABİLMELİ (simetri).
grep -q 'cryptsetup open --key-file' "${UNLOCK}" \
    || fail "data-unlock must support keyfile-backed unlock, symmetric with provisioning (F1)"

# F8: prod-varyant sözleşmesi post-image gate + Rust ile hizalı olmalı; yalnız
# exact 'prod' eşleyip 'production'/'prod-*'ı plaintext dev-mount'a düşürmemeli.
if ! grep -q 'production' "${UNLOCK}" || ! grep -q 'prod-\*' "${UNLOCK}"; then
    fail "data-unlock prod-variant case must match prod/production/prod-* (F8 alignment)"
fi

# RT-5: prod defconfig'lerde systemd-cryptsetup açık olmalı.
for dc in suderra_aarch64_rpi4_prod_ab suderra_aarch64_revpi4_prod_ab suderra_qemu_x86_64_prod_ab; do
    grep -q '^BR2_PACKAGE_SYSTEMD_CRYPTSETUP=y' "${ROOT}/configs/${dc}_defconfig" \
        || fail "${dc}: production defconfig must enable BR2_PACKAGE_SYSTEMD_CRYPTSETUP (RT-5)"
done
echo "PASS: static /data LUKS2 provisioning contract"

# ---------------------------------------------------------------------------
# 2. RUNTIME loopback doğrulaması (mümkünse)
# ---------------------------------------------------------------------------
if [ "$(id -u)" != "0" ] || ! command -v cryptsetup >/dev/null 2>&1 \
   || ! command -v losetup >/dev/null 2>&1; then
    echo "SKIP: runtime loopback needs root + cryptsetup + losetup (static contract still enforced)"
    exit 0
fi

WORK="$(mktemp -d)"
LOOP=""
cleanup() {
    [ -n "${LOOP}" ] && { cryptsetup close ct-provtest 2>/dev/null || true; losetup -d "${LOOP}" 2>/dev/null || true; }
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

dd if=/dev/zero of="${WORK}/disk.img" bs=1M count=48 status=none
LOOP="$(losetup --find --show "${WORK}/disk.img")"
head -c 64 /dev/urandom > "${WORK}/key.bin"; chmod 600 "${WORK}/key.bin"

# Header seviyesi: bu her ortamda çalışır (mapper gerektirmez).
cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 \
    --pbkdf-force-iterations 1000 "${LOOP}" "${WORK}/key.bin" \
    || fail "runtime: luksFormat luks2 failed"
cryptsetup isLuks "${LOOP}" || fail "runtime: isLuks negative after format"
ver="$(cryptsetup luksDump "${LOOP}" | sed -n 's/^Version:[[:space:]]*//p' | head -n1)"
[ "${ver}" = "2" ] || fail "runtime: expected LUKS2, got version '${ver}'"

# İkinci bir anahtar enroll + bootstrap çıkar (provision'ın enroll akışı).
head -c 64 /dev/urandom > "${WORK}/key2.bin"; chmod 600 "${WORK}/key2.bin"
cryptsetup luksAddKey --batch-mode --key-file "${WORK}/key.bin" \
    "${LOOP}" "${WORK}/key2.bin" || fail "runtime: luksAddKey failed"
cryptsetup luksRemoveKey "${LOOP}" "${WORK}/key.bin" || fail "runtime: luksRemoveKey failed"
# Eski anahtar artık açmamalı, yeni anahtar tanınmalı (test-passphrase ile).
cryptsetup luksOpen --test-passphrase --key-file "${WORK}/key.bin" "${LOOP}" 2>/dev/null \
    && fail "runtime: removed bootstrap key still unlocks (keyslot not removed)"
echo "PASS: runtime LUKS2 header provisioning cycle (format + enroll/rotate + isLuks/v2)"

# Mapper open + mkfs: yalnız device-mapper işlevselse. dm yoksa (bazı konteyner
# kernel'leri) bu adım AÇIKÇA atlanır — sessiz geçiş değil; CI QEMU-swtpm + G5 kapatır.
if open_err="$(cryptsetup open --key-file "${WORK}/key2.bin" "${LOOP}" ct-provtest 2>&1)"; then
    mkfs.ext4 -q -L SUDERRA-DATA /dev/mapper/ct-provtest || fail "runtime: mkfs on mapper failed"
    cryptsetup close ct-provtest
    echo "PASS: runtime mapper open + mkfs (device-mapper available)"
elif printf '%s' "${open_err}" | grep -qi 'device-mapper\|dm_mod'; then
    echo "SKIP: device-mapper unavailable here; mapper open/mkfs exercised by CI QEMU-swtpm + G5 hardware"
else
    fail "runtime: open failed unexpectedly: ${open_err}"
fi
