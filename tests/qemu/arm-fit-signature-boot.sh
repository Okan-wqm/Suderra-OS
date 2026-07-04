#!/usr/bin/env bash
#
# ARM signed-FIT U-Boot boot smoke (PR-A8, gate G3 gözlemsel).
#
# Gerçek U-Boot'un CONFIG_FIT_SIGNATURE icrasını qemu-system-aarch64 -M virt
# üzerinde gözlemler: enrolled fit-signing pubkey'i gömülü bir U-Boot ile
#   - GEÇERLI imzalı FIT boot EDER (kernel'e devreder),
#   - kurcalanmış/yanlış-anahtar FIT U-Boot tarafından REDDEDİLİR (boot etmez).
#
# Bu, deterministik host-side kripto smoke'un (tests/image-contracts/
# arm-fit-signature-smoke-contract-test.sh) gözlemsel tamamlayıcısıdır. En olası
# flake noktası (virt U-Boot != BCM2711); bu yüzden BLOCKING DEĞİL — emülatör ve
# virt U-Boot yoksa temiz atlar. G3'ün deterministik dayanağı host-side smoke +
# A3 FIT/verity contract'ıdır; gerçek Pi/RevPi boot G4 (donanım).
#
# Ortam:
#   SUDERRA_ARM_FIT_UBOOT   qemu_arm64 için fit-signing pubkey'i gömülü u-boot.bin
#   SUDERRA_ARM_FIT_A       geçerli imzalı suderra-A.fit
#   SUDERRA_ARM_FIT_TAMPER  kurcalanmış FIT (opsiyonel; verilmezse üretilir)
#
set -euo pipefail
IFS=$'\n\t'

skip() { echo "NOTE: $*; QEMU FIT boot smoke atlandı (G3 host-side smoke + A3 kapsıyor)"; exit 0; }

command -v qemu-system-aarch64 >/dev/null 2>&1 || skip "qemu-system-aarch64 yok"
UBOOT="${SUDERRA_ARM_FIT_UBOOT:-}"
FIT_A="${SUDERRA_ARM_FIT_A:-}"
[ -n "${UBOOT}" ] && [ -s "${UBOOT}" ] || skip "SUDERRA_ARM_FIT_UBOOT (enrolled virt u-boot.bin) yok"
[ -n "${FIT_A}" ] && [ -s "${FIT_A}" ] || skip "SUDERRA_ARM_FIT_A (imzalı FIT) yok"

W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT
tamper="${SUDERRA_ARM_FIT_TAMPER:-}"
if [ -z "${tamper}" ]; then
    tamper="${W}/tampered.fit"
    cp "${FIT_A}" "${tamper}"
    python3 -c "import sys; d=bytearray(open('${tamper}','rb').read()); d[len(d)//2]^=0xFF; open('${tamper}','wb').write(d)"
fi

# U-Boot'u virt'te çalıştır, FAT boot diskinden FIT'i bootm et; seri çıktıyı yakala.
# Geçerli FIT: U-Boot imzayı doğrular ve kernel'e devreder. Kurcalanmış FIT:
# U-Boot "Bad" / "signature" hatası verir ve devretmez.
run_uboot() {
    fit="$1"; label="$2"
    bootdir="${W}/${label}-boot"; mkdir -p "${bootdir}"
    cp "${fit}" "${bootdir}/suderra-A.fit"
    # boot.scr: FIT'i yükle + bootm (imza zorunlu). Basit tek-slot smoke.
    cat > "${W}/boot.cmd" <<'CMD'
load virtio 0:1 0x02000000 suderra-A.fit
bootm 0x02000000
CMD
    # FAT imaj oluştur (mkfs.vfat + mcopy varsa).
    if ! command -v mkfs.vfat >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
        skip "mkfs.vfat/mcopy yok (FAT boot diski üretilemiyor)"
    fi
    dd if=/dev/zero of="${W}/${label}.img" bs=1M count=64 status=none
    mkfs.vfat "${W}/${label}.img" >/dev/null 2>&1
    mcopy -i "${W}/${label}.img" "${bootdir}/suderra-A.fit" ::suderra-A.fit
    timeout 90 qemu-system-aarch64 \
        -M virt -cpu cortex-a72 -m 512 -nographic -no-reboot \
        -bios "${UBOOT}" \
        -drive file="${W}/${label}.img",format=raw,if=virtio \
        > "${W}/${label}.log" 2>&1 || true
    cat "${W}/${label}.log"
}

echo "==> valid FIT: U-Boot imza doğrulaması boot etmeli"
run_uboot "${FIT_A}" valid > "${W}/valid.out" 2>&1 || true
if grep -qiE 'Verifying Hash Integrity|sha256.*OK|Starting kernel' "${W}/valid.out"; then
    echo "G3: valid FIT U-Boot tarafından kabul edildi"
else
    echo "ERROR: valid FIT boot kanıtı görülmedi (virt U-Boot flake olabilir)" >&2
    echo "--- valid.out ---" >&2; tail -20 "${W}/valid.out" >&2
    exit 1
fi

echo "==> tampered FIT: U-Boot imza doğrulaması REDDETMELİ"
run_uboot "${tamper}" tampered > "${W}/tampered.out" 2>&1 || true
if grep -qiE 'Bad Data Hash|signature|verification failed|Bad FIT|hash.*BAD' "${W}/tampered.out" \
   && ! grep -qi 'Starting kernel' "${W}/tampered.out"; then
    echo "G3: kurcalanmış FIT U-Boot tarafından reddedildi"
else
    echo "ERROR: kurcalanmış FIT reddedilmedi (fail-closed ihlali)" >&2
    echo "--- tampered.out ---" >&2; tail -20 "${W}/tampered.out" >&2
    exit 1
fi

echo "ARM signed-FIT U-Boot boot smoke passed"
