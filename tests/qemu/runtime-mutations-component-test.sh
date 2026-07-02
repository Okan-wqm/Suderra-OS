#!/usr/bin/env bash
#
# runtime_mutations.py bileşen testi (gerçek araçlar, hermetik).
#
# Mutation üreticilerinin GERÇEKTEN mutasyon ürettiğini kanıtlar — sahte
# "rejected" çıktısı değil. Build artefaktı gerektirmeyen üreticiler burada
# gerçek araçlarla (sbsign/sbattach/objcopy/mkfs.ext4/openssl) test edilir;
# rauc bundle üreticileri build slot imajları + rauc host tool ister ve
# production-runtime workflow'unda doğrulanır (burada explicit-fail beklenir).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
MUT="${ROOT}/tests/qemu/runtime_mutations.py"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "SKIP: $1 yok"; exit 0; }; }
need sbsign; need sbverify; need sbattach; need objcopy; need mkfs.ext4; need openssl

python3 -m py_compile "${MUT}"

# Ortak: throwaway db anahtarı + gerçek bir PE (imzalanabilir).
openssl req -newkey rsa:3072 -nodes -keyout "${WORK}/db.key" -x509 -sha256 -days 1 \
    -out "${WORK}/db.crt" -subj "/CN=Suderra CI db/" 2>/dev/null
if [ -f /boot/grub/x86_64-efi/core.efi ]; then
    cp /boot/grub/x86_64-efi/core.efi "${WORK}/base.efi"
elif command -v grub-mkimage >/dev/null 2>&1; then
    grub-mkimage -O x86_64-efi -o "${WORK}/base.efi" -p /EFI/BOOT normal 2>/dev/null
elif command -v grub2-mkimage >/dev/null 2>&1; then
    grub2-mkimage -O x86_64-efi -o "${WORK}/base.efi" -p /EFI/BOOT normal 2>/dev/null
fi
[ -s "${WORK}/base.efi" ] || { echo "SKIP: imzalanacak PE üretilemedi"; exit 0; }
sbsign --key "${WORK}/db.key" --cert "${WORK}/db.crt" --output "${WORK}/signed-uki.efi" "${WORK}/base.efi" 2>/dev/null

# 1) unsigned-boot-rejection: imza sökülmeli, cert'e karşı doğrulanmamalı.
python3 "${MUT}" --scenario unsigned-boot-rejection --work-dir "${WORK}/u" \
    --input signed_uki="${WORK}/signed-uki.efi" >/dev/null
if sbverify --cert "${WORK}/db.crt" "${WORK}/u/unsigned-suderra.efi" >/dev/null 2>&1; then
    echo "ERROR: unsigned UKI hâlâ doğrulanıyor" >&2; exit 1
fi

# 2) cmdline-tamper-rejection: geçerli imzalı KALMALI (firmware kabul), cmdline bozuk.
printf 'root=/dev/mapper/suderra-root suderra.verity.root_hash=TAMPEREDdeadbeef ro\n' > "${WORK}/cmdline.tampered"
printf 'PRETTY_NAME="Suderra"\n' > "${WORK}/os-release"
printf 'dummy-initrd' > "${WORK}/initrd.img"
python3 "${MUT}" --scenario cmdline-tamper-rejection --work-dir "${WORK}/c" \
    --input stub="${WORK}/base.efi" --input kernel="${WORK}/base.efi" \
    --input osrel="${WORK}/os-release" --input initrd="${WORK}/initrd.img" \
    --input cmdline_tampered="${WORK}/cmdline.tampered" \
    --input sign_key="${WORK}/db.key" --input sign_cert="${WORK}/db.crt" >/dev/null
sbverify --cert "${WORK}/db.crt" "${WORK}/c/cmdline-tamper-suderra.efi" >/dev/null 2>&1 || {
    echo "ERROR: cmdline-tamper UKI geçerli imzalı olmalı (firmware kabul etmeli)" >&2; exit 1
}
objcopy -O binary --only-section=.cmdline "${WORK}/c/cmdline-tamper-suderra.efi" /dev/stdout 2>/dev/null \
    | grep -q 'TAMPERED' || { echo "ERROR: bozuk cmdline gömülmedi" >&2; exit 1; }

# 3) dm-verity-rootfs-tamper-rejection: rootfs baytları değişmeli.
dd if=/dev/zero of="${WORK}/rootfs.img" bs=1M count=8 status=none
mkfs.ext4 -q -F "${WORK}/rootfs.img" 2>/dev/null || true
orig="$(sha256sum "${WORK}/rootfs.img" | awk '{print $1}')"
python3 "${MUT}" --scenario dm-verity-rootfs-tamper-rejection --work-dir "${WORK}/r" \
    --input image="${WORK}/rootfs.img" --input offset=2097152 --input length=128 \
    --input before_source="${WORK}/rootfs.img" >/dev/null
mutated="$(sha256sum "${WORK}/r/rootfs-tamper.img" | awk '{print $1}')"
[ "${orig}" != "${mutated}" ] || { echo "ERROR: rootfs tamper baytları değiştirmedi" >&2; exit 1; }

# 4) anti-rollback-downgrade-rejection: version < floor; floor >= version reddedilmeli.
openssl genpkey -algorithm ED25519 -out "${WORK}/ota.key" 2>/dev/null
python3 "${MUT}" --scenario anti-rollback-downgrade-rejection --work-dir "${WORK}/d" \
    --input package=suderra-os --input downgrade_version=1.2.0 --input rollback_floor=2.0.0 \
    --input sign_key="${WORK}/ota.key" >/dev/null
[ -f "${WORK}/d/downgrade-manifest.json.sig" ] || { echo "ERROR: downgrade manifest imzalanmadı" >&2; exit 1; }
if python3 "${MUT}" --scenario anti-rollback-downgrade-rejection --work-dir "${WORK}/d2" \
    --input package=x --input downgrade_version=2.5.0 --input rollback_floor=2.0.0 \
    --input sign_key="${WORK}/ota.key" >/dev/null 2>&1; then
    echo "ERROR: floor >= version reddedilmeliydi (fail-closed)" >&2; exit 1
fi

# 5) data-luks-swtpm: swtpm state snapshot alınmalı.
mkdir -p "${WORK}/swtpm"; printf 'tpmstate' > "${WORK}/swtpm/tpm2-00.permall"
python3 "${MUT}" --scenario data-luks-swtpm --work-dir "${WORK}/s" \
    --input swtpm_state="${WORK}/swtpm" >/dev/null
[ -f "${WORK}/s/swtpm-state-before/tpm2-00.permall" ] || { echo "ERROR: swtpm snapshot alınmadı" >&2; exit 1; }

# 6) signed-boot: mutasyon yok (null).
out="$(python3 "${MUT}" --scenario signed-boot --work-dir "${WORK}/p")"
[ "${out}" = "null" ] || { echo "ERROR: signed-boot mutasyon üretmemeli" >&2; exit 1; }

echo "runtime-mutations component test passed"
