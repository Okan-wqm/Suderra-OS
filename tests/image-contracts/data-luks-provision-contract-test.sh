#!/usr/bin/env bash
#
# /data at-rest LUKS2 provisioning sözleşmesi (RT-1).
#
# suderra-data-unlock'un PROD yolunda /data'yı ilk boot'ta LUKS2 olarak provision
# edip anahtarı TPM2'ye seal ettiğini (fail-closed, blank-only) ve gerekli paket
# desteğinin prod defconfig'lerde açık olduğunu STATİK olarak kanıtlar. Gerçek
# TPM seal/unseal donanım/swtpm ister (G5) — burada değil. LUKS mekaniği
# (format/open/mkfs) loopback ile ayrıca doğrulanır (bkz. commit / CI).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
UNLOCK="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"

[ -f "${UNLOCK}" ] || { echo "ERROR: suderra-data-unlock yok" >&2; exit 1; }

script="$(cat "${UNLOCK}")"
need() {
    # need <insan-açıklaması> <grep-deseni>
    grep -Eq -- "$2" <<<"${script}" || { echo "ERROR: suderra-data-unlock eksik: $1" >&2; exit 1; }
}

# 1. Provisioning mantığı mevcut ve fail-closed.
need "provision_luks_data fonksiyonu"            'provision_luks_data\(\)'
need "blank-only güvenlik guard'ı (blkid reddi)" 'blkid .* >/dev/null'
need "TPM2 zorunlu (fail-closed) kontrolü"       '/dev/tpmrm0|/dev/tpm0'
need "LUKS2 formatlama"                          'cryptsetup luksFormat --type luks2'
need "TPM2 seal (systemd-cryptenroll)"           'systemd-cryptenroll'
need "TPM2 device auto"                          '--tpm2-device=auto'
need "PCR7 binding"                              'tpm2-pcrs=7'
need "ephemeral passphrase slot'unun silinmesi"  'wipe-slot=password'
need "fresh volume'da mkfs.ext4"                 'mkfs.ext4 .* "\$\{mapper_dev\}"'

# 2. Ephemeral anahtar KALICI depoya yazılmamalı — yalnız /run (tmpfs).
grep -Eq 'mktemp /run/' <<<"${script}" || {
    echo "ERROR: ephemeral anahtar /run (tmpfs) dışında üretiliyor olabilir" >&2; exit 1; }

# 3. Prod defconfig'ler TPM2 LUKS unlock/seal desteğini içermeli. NOT: ayrı bir
# BR2_PACKAGE_SYSTEMD_CRYPTSETUP sembolü YOKTUR — cryptsetup + tpm2-tss, systemd'yi
# -Dlibcryptsetup=enabled + -Dtpm2=enabled ile derletir (buildroot systemd.mk),
# yani systemd-cryptsetup/systemd-cryptenroll --tpm2 bunlardan üretilir.
for dc in suderra_x86_64_defconfig suderra_aarch64_rpi4_prod_ab_defconfig \
          suderra_aarch64_revpi4_prod_ab_defconfig suderra_qemu_x86_64_prod_ab_defconfig; do
    f="${ROOT}/configs/${dc}"
    [ -f "${f}" ] || { echo "ERROR: ${dc} yok" >&2; exit 1; }
    for pkg in BR2_PACKAGE_CRYPTSETUP BR2_PACKAGE_TPM2_TSS BR2_PACKAGE_TPM2_TOOLS; do
        grep -q "^${pkg}=y" "${f}" || { echo "ERROR: ${dc} eksik: ${pkg}" >&2; exit 1; }
    done
done

# 4. DEV defconfig'ler cryptsetup/TPM İÇERMEMELİ (dev = düz ext4, tasarım gereği).
for dc in suderra_aarch64_rpi4_defconfig suderra_aarch64_revpi4_defconfig; do
    f="${ROOT}/configs/${dc}"
    if grep -qE '^BR2_PACKAGE_CRYPTSETUP=y|^BR2_PACKAGE_TPM2_TSS=y' "${f}"; then
        echo "ERROR: dev ${dc} cryptsetup/tpm2 içermemeli (dev /data düz ext4)" >&2; exit 1; fi
done

echo "/data LUKS provisioning contract passed"
