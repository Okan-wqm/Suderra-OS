#!/usr/bin/env bash
#
# ARM signed-FIT üretici sözleşmesi (PR-A3, gates G1/G2).
#
# production-artifacts.sh arm-pre-genimage'in GERÇEK imzalı FIT + dm-verity
# ürettiğini gerçek araçlarla (mkimage/dtc/veritysetup/openssl) kanıtlar:
#   - imzalı FIT (kernel+fdt+ramdisk, config imzalı)
#   - the slot's kernel command line in /chosen/bootargs of every device tree of
#     the FIT (U-Boot reads no FIT configuration bootargs), no key node there
#   - FIT doğrulama pubkey'i, firmware'in yüklediği her device tree'nin keyed
#     kopyasında (firmware-dtb/), required = "conf", ve her iki slot FIT'i U-Boot'un
#     kendi fit_check_sign'ı ile o anahtara karşı doğrulanır
#   - the boot-chain gate (arm-boot-gate) rejects the defects it exists for
#   - detached .sig/.cert sidecar'lar (.sig openssl ile doğrulanır)
#   - rootfs.verity roothash veritysetup verify ile eşleşir
# Gerçek boot (U-Boot FIT enforcement): tests/qemu/arm-fit-signature-boot.sh.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PA="${ROOT}/scripts/production-artifacts.sh"

for tool in mkimage dumpimage dtc fdtget fdtput veritysetup openssl mkfs.ext4; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "SKIP: ${tool} yok (Image Build kapsıyor)" >&2; exit 77; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
# fit_check_sign is U-Boot's own FIT verifier: Buildroot's host-uboot-tools
# installs it, a distribution package does not, so build it from the pinned
# sources (scripts/ci/uboot-build.sh) when it is not on the PATH.
if ! command -v fit_check_sign >/dev/null 2>&1; then
    bash "${ROOT}/scripts/ci/uboot-build.sh" tools "${SUDERRA_UBOOT_BUILD:-${WORK}/uboot}" >/dev/null || {
        echo "SKIP: fit_check_sign yok ve U-Boot araçları derlenemedi" >&2; exit 77; }
    export PATH="${SUDERRA_UBOOT_BUILD:-${WORK}/uboot}/bin:${PATH}"
fi
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

# No u-boot.dtb: nothing loads it (U-Boot's control FDT is the firmware's tree).
[ ! -e "${BIN}/u-boot.dtb" ] || { echo "ERROR: a loose u-boot.dtb was produced" >&2; exit 1; }

# The FIT verification pubkey is in a copy of EVERY stock tree the firmware may
# load, as a required = "conf" key (without it U-Boot enforces nothing: silent
# fail-open), and the stock trees themselves stay unkeyed (the FIT's own trees).
for board in bcm2711-rpi-4-b bcm2711-rpi-cm4 bcm2711-rpi-cm4-io; do
    keyed="${BIN}/firmware-dtb/${board}.dtb"
    [ -s "${keyed}" ] || { echo "ERROR: no keyed firmware device tree for ${board}" >&2; exit 1; }
    [ "$(fdtget -t s "${keyed}" /signature/key-fit-signing required)" = conf ] || {
        echo "ERROR: ${board} keyed tree: the key is not required = conf" >&2; exit 1; }
    [ "$(fdtget -t s "${keyed}" /signature/key-fit-signing key-name-hint)" = fit-signing ] || {
        echo "ERROR: ${board} keyed tree: not the fit-signing key" >&2; exit 1; }
    if fdtget -l "${BIN}/${board}.dtb" / | grep -Fxq signature; then
        echo "ERROR: ${board} stock tree was keyed in place" >&2; exit 1; fi
    # The keyed copy is the stock tree plus the key and nothing else.
    diff <(dtc -I dtb -O dts "${BIN}/${board}.dtb" 2>/dev/null | grep -v '^$') \
         <(dtc -I dtb -O dts "${keyed}" 2>/dev/null | awk '/^\tsignature \{/ {skip=1} !skip {print} skip && /^\t\};/ {skip=0}' | grep -v '^$') >/dev/null || {
        echo "ERROR: ${board} keyed tree differs from the stock tree by more than the key" >&2; exit 1; }
done

# The command line is in the signed device trees, not in a FIT property.
for slot in A B; do
    fit="${BIN}/suderra-${slot}.fit"
    if fdtget -l "${fit}" /configurations | while read -r c; do fdtget -p "${fit}" "/configurations/${c}"; done | grep -Fxq bootargs; then
        echo "ERROR: ${slot} FIT has a configuration bootargs property (U-Boot reads none)" >&2; exit 1; fi
    n=0
    while read -r entry; do
        [ -n "${entry}" ] || continue
        dumpimage -T flat_dt -p "${entry%% *}" -o "${WORK}/fdt-${slot}-${n}.dtb" "${fit}" >/dev/null
        [ "$(fdtget -t s "${WORK}/fdt-${slot}-${n}.dtb" /chosen bootargs)" = "$(cat "${BIN}/suderra-${slot}.cmdline")" ] || {
            echo "ERROR: ${slot} FIT device tree ${n} /chosen/bootargs is not the slot's command line" >&2; exit 1; }
        n=$((n + 1))
    done < <(i=0; for img in $(fdtget -l "${fit}" /images); do
                 [ "$(fdtget -t s "${fit}" "/images/${img}" type)" = flat_dt ] && echo "${i} ${img}"; i=$((i + 1)); done)
    [ "${n}" -eq 3 ] || { echo "ERROR: ${slot} FIT has ${n} device trees, expected 3" >&2; exit 1; }
done

# U-Boot's own verifier accepts both slot FITs with each keyed tree, and rejects
# a FIT signed by another key (what the gate relies on).
for keyed in "${BIN}"/firmware-dtb/*.dtb; do
    for slot in A B; do
        fit_check_sign -f "${BIN}/suderra-${slot}.fit" -k "${keyed}" >/dev/null 2>&1 || {
            echo "ERROR: fit_check_sign: slot ${slot} does not verify against ${keyed##*/}" >&2; exit 1; }
    done
done
ATT="${WORK}/attacker"
mkdir -p "${ATT}/keys" "${ATT}/target"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${ATT}/keys/fit-signing.key" 2>/dev/null
openssl req -batch -new -x509 -key "${ATT}/keys/fit-signing.key" -days 30 -out "${ATT}/keys/fit-signing.crt" \
    -subj "/CN=attacker" 2>/dev/null
cp -a "${TGT}/." "${ATT}/target/"
mkdir -p "${ATT}/bin"
cp "${BIN}"/*.dtb "${BIN}/Image" "${BIN}/rootfs.ext4" "${ATT}/bin/"
SUDERRA_FIT_KEYS_DIR="${ATT}/keys" SUDERRA_KEYS_DIR="${ATT}/keys" \
    bash "${PA}" arm-pre-genimage "${ATT}/bin" "${ATT}/target" >/dev/null
if fit_check_sign -f "${ATT}/bin/suderra-A.fit" -k "${BIN}/firmware-dtb/bcm2711-rpi-cm4.dtb" >/dev/null 2>&1; then
    echo "ERROR: fit_check_sign accepted a FIT signed by another key" >&2; exit 1; fi

# The gate passes the real output and rejects each defect it exists for.
bash "${PA}" arm-boot-gate "${BIN}" >/dev/null
mutate() { # <label> <expected message> <command...>: on a copy of BIN
    local label="$1" want="$2" out
    shift 2
    rm -rf "${WORK}/mut"
    cp -a "${BIN}" "${WORK}/mut"
    "$@"
    if out="$(bash "${PA}" arm-boot-gate "${WORK}/mut" 2>&1)"; then
        echo "ERROR: arm-boot-gate accepted: ${label}" >&2; exit 1; fi
    grep -qF -- "${want}" <<<"${out}" || { echo "${out}" >&2; echo "ERROR: arm-boot-gate failed for ${label} without: ${want}" >&2; exit 1; }
    echo "  rejects: ${label}"
}
fdtput_del() { fdtput -d "${WORK}/mut/firmware-dtb/bcm2711-rpi-cm4.dtb" "$@"; }
mutate "a firmware device tree without the key" "required" \
    fdtput_del /signature/key-fit-signing required
mutate "a firmware device tree whose key node is gone" "missing or not required" \
    sh -c 'cp "$1/bcm2711-rpi-cm4.dtb" "$2/firmware-dtb/bcm2711-rpi-cm4.dtb"' _ "${WORK}/mut" "${WORK}/mut"
resign_with_attacker_key() { # slot A's FIT source, signed by the other key
    printf '/dts-v1/;\n/ {\n};\n' | dtc -I dts -O dtb -o "${WORK}/attacker-key.dtb" 2>/dev/null
    mkimage -f "${BIN}/suderra-A.its" -k "${ATT}/keys" -K "${WORK}/attacker-key.dtb" -r \
        "${WORK}/mut/suderra-A.fit" >/dev/null
}
mutate "a slot FIT signed by another key" "does not verify against the key" resign_with_attacker_key
mutate "a command line without lockdown" "differs from" \
    sh -c 'sed -i "s/lockdown=confidentiality/lockdown=none/" "$1/suderra-A.cmdline"' _ "${WORK}/mut"
mutate "no keyed firmware device trees at all" "were never keyed" \
    rm -rf "${WORK}/mut/firmware-dtb"

# roothash veritysetup verify ile eşleşmeli.
. "${BIN}/rootfs.verity.env"
veritysetup verify "${BIN}/rootfs.ext4" "${BIN}/rootfs.verity" "${ROOT_HASH}" >/dev/null 2>&1 || {
    echo "ERROR: veritysetup verify başarısız" >&2; exit 1; }

echo "ARM signed-FIT contract passed"
