#!/usr/bin/env bash
#
# ARM signed-FIT üretici sözleşmesi (PR-A3, gates G1/G2).
#
# production-artifacts.sh arm-pre-genimage'in GERÇEK imzalı FIT + dm-verity
# ürettiğini gerçek araçlarla (mkimage/dtc/veritysetup/openssl) kanıtlar:
#   - imzalı FIT (kernel+fdt+ramdisk, config imzalı)
#   - FIT doğrulama pubkey'i u-boot.dtb'ye gömülü
#   - detached .sig/.cert sidecar'lar (.sig openssl ile doğrulanır)
#   - rootfs.verity roothash veritysetup verify ile eşleşir
# Gerçek boot (U-Boot FIT enforcement) G3/G4 — burada değil.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PA="${ROOT}/scripts/production-artifacts.sh"

for tool in mkimage dtc veritysetup openssl mkfs.ext4; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "SKIP: ${tool} yok (Image Build kapsıyor)"; exit 0; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
BIN="${WORK}/images"
TGT="${WORK}/target"
KEYS="${WORK}/keys"
mkdir -p "${BIN}" "${TGT}/bin" "${TGT}/sbin" "${TGT}/lib" "${KEYS}"

# Dev FIT signing key (mkimage -k dir ister: fit-signing.{key,crt}).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEYS}/fit-signing.key" 2>/dev/null
openssl req -batch -new -x509 -key "${KEYS}/fit-signing.key" -days 30 \
    -out "${KEYS}/fit-signing.crt" -subj "/CN=Suderra CI FIT" 2>/dev/null

# Sentetik build çıktıları.
printf 'KERNELIMAGE-Image' > "${BIN}/Image"
# Çok-kartlı FIT (HIGH1): her kartın kendi DTB'si + farklı compatible. Üretici
# her biri için ayrı imzalı config yaymalı; U-Boot çalışan kartın compatible'ıyla
# doğru config'i otomatik seçer (alfabetik-ilk DTB'ye sabitlenmez).
printf '/dts-v1/; / { model="Pi 4 B"; compatible="raspberrypi,4-model-b","brcm,bcm2711"; };' > "${WORK}/b1.dts"
dtc -O dtb -o "${BIN}/bcm2711-rpi-4-b.dtb" "${WORK}/b1.dts" 2>/dev/null
printf '/dts-v1/; / { model="CM4"; compatible="raspberrypi,4-compute-module","brcm,bcm2711"; };' > "${WORK}/b2.dts"
dtc -O dtb -o "${BIN}/bcm2711-rpi-cm4.dtb" "${WORK}/b2.dts" 2>/dev/null
printf '/dts-v1/; / { model="CM4 IO"; compatible="raspberrypi,4-compute-module","brcm,bcm2711"; };' > "${WORK}/b3.dts"
dtc -O dtb -o "${BIN}/bcm2711-rpi-cm4-io.dtb" "${WORK}/b3.dts" 2>/dev/null
printf '/dts-v1/; / { };' > "${WORK}/u-boot.dts"; dtc -O dtb -o "${BIN}/u-boot.dtb" "${WORK}/u-boot.dts" 2>/dev/null
dd if=/dev/zero of="${BIN}/rootfs.ext4" bs=1M count=8 status=none
mkfs.ext4 -q -F "${BIN}/rootfs.ext4" 2>/dev/null || true

# Sahte initramfs bağımlılıkları (kopyalanır, çalıştırılmaz).
for f in bin/busybox bin/mount bin/sleep sbin/blkid sbin/dmsetup sbin/switch_root; do
    printf 'x' > "${TGT}/${f}"; chmod 0755 "${TGT}/${f}"
done
printf 'lib' > "${TGT}/lib/placeholder"

SUDERRA_FIT_KEYS_DIR="${KEYS}" SUDERRA_KEYS_DIR="${KEYS}" \
    bash "${PA}" arm-pre-genimage "${BIN}" "${TGT}" >/dev/null

for slot in A B; do
    fit="${BIN}/suderra-${slot}.fit"
    [ -s "${fit}" ] || { echo "ERROR: ${slot} slot FIT üretilmedi" >&2; exit 1; }
    [ -s "${fit}.sig" ] || { echo "ERROR: ${slot} slot FIT .sig yok" >&2; exit 1; }
    [ -s "${fit}.cert" ] || { echo "ERROR: ${slot} slot FIT .cert yok" >&2; exit 1; }
    # FIT listesini BİR KEZ al: 'mkimage -l | grep -q' deseni pipefail altında
    # SIGPIPE yarışına açık (grep -q erken eşleşip çıkınca mkimage 141 döner →
    # pipefail hatası). Listeyi değişkene alıp here-string ile grep'lemek bunu
    # tamamen ortadan kaldırır (mkimage tamamlanır, tek çağrı).
    listing="$(mkimage -l "${fit}" 2>/dev/null)"
    # FIT imzalı config içermeli.
    grep -qiE 'Sign algo:.*rsa2048' <<<"${listing}" || {
        echo "ERROR: ${slot} FIT config imzalı değil" >&2; exit 1; }
    # kernel + fdt + ramdisk mevcut.
    for img in Kernel 'Flat Device Tree' RAMDisk; do
        grep -qi "${img}" <<<"${listing}" || {
            echo "ERROR: ${slot} FIT eksik image: ${img}" >&2; exit 1; }
    done
    # Çok-kartlı (HIGH1): her board DTB için ayrı config, hepsi imzalı.
    for board in bcm2711-rpi-4-b bcm2711-rpi-cm4 bcm2711-rpi-cm4-io; do
        grep -q "conf-${board}" <<<"${listing}" || {
            echo "ERROR: ${slot} FIT ${board} config'i yok (çok-kartlı değil)" >&2; exit 1; }
    done
    nsig="$(grep -ciE 'Sign algo:.*rsa2048' <<<"${listing}")"
    [ "${nsig}" -ge 3 ] || {
        echo "ERROR: ${slot} FIT'te >=3 imzalı config beklenirdi, ${nsig} bulundu" >&2; exit 1; }
    # Detached sidecar cert'e karşı doğrulanmalı.
    openssl dgst -sha256 -verify \
        <(openssl x509 -in "${fit}.cert" -pubkey -noout 2>/dev/null) \
        -signature "${fit}.sig" "${fit}" >/dev/null 2>&1 || {
        echo "ERROR: ${slot} FIT sidecar imzası doğrulanmadı" >&2; exit 1; }
    # bootargs ARM konsolu + verity taşımalı, module.sig_enforce TAŞIMAMALI.
    cmdline="${BIN}/suderra-${slot}.cmdline"
    grep -q 'console=ttyAMA0' "${cmdline}" || { echo "ERROR: ${slot} ARM console yok" >&2; exit 1; }
    grep -q 'suderra.verity.root_hash=' "${cmdline}" || { echo "ERROR: ${slot} verity roothash yok" >&2; exit 1; }
    if grep -q 'module.sig_enforce' "${cmdline}"; then
        echo "ERROR: ${slot} ARM cmdline module.sig_enforce içermemeli (modüller açık)" >&2; exit 1; fi
    grep -q "rauc.slot=${slot}" "${cmdline}" || { echo "ERROR: ${slot} rauc.slot yok" >&2; exit 1; }
done

# FIT doğrulama pubkey'i u-boot.dtb kontrol FDT'sine gömülmeli VE required olmalı.
# 'required = "conf"' olmadan U-Boot imzayı zorlamaz (fit_config_verify_required_sigs
# hiçbir required anahtar bulamaz) → sessiz fail-open. ADR-0007 root-of-trust.
uboot_dts="$(dtc -I dtb -O dts "${BIN}/u-boot.dtb" 2>/dev/null)"
printf '%s' "${uboot_dts}" | grep -q 'key-name-hint = "fit-signing"' || {
    echo "ERROR: FIT pubkey u-boot.dtb'ye gömülmedi" >&2; exit 1; }
printf '%s' "${uboot_dts}" | grep -q 'required = "conf"' || {
    echo "ERROR: u-boot.dtb fit-signing anahtarı required değil — boot'ta imza zorlanmaz (fail-open)" >&2; exit 1; }

# roothash veritysetup verify ile eşleşmeli.
. "${BIN}/rootfs.verity.env"
veritysetup verify "${BIN}/rootfs.ext4" "${BIN}/rootfs.verity" "${ROOT_HASH}" >/dev/null 2>&1 || {
    echo "ERROR: veritysetup verify başarısız" >&2; exit 1; }

echo "ARM signed-FIT contract passed"
