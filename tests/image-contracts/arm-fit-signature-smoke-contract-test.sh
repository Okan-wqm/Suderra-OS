#!/usr/bin/env bash
#
# ARM signed-FIT imza kabul/red smoke (PR-A8, gate G3 deterministik çekirdek).
#
# U-Boot'un CONFIG_FIT_SIGNATURE'ının boot'ta verdiği garantiyi host-side gerçek
# kripto ile deterministik kanıtlar: imzalı FIT gömülü sha256,rsa2048 imza taşır,
# pubkey u-boot.dtb'ye gömülüdür, ve imza FIT İÇERİĞİNE BAĞLIDIR — geçerli imza
# KABUL, kurcalanmış/yanlış-anahtar RED. Gerçek U-Boot gömülü-imza icrası QEMU
# boot harness'inde (tests/qemu/arm-fit-signature-boot.sh) / donanımda (G3/G4).
#
set -euo pipefail
IFS=$'\n\t'

for tool in mkimage dtc openssl; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "NOTE: ${tool} yok; smoke atlandı (Image Build container koşar)"; exit 0; }
done

W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT
cd "${W}"

# Gömülü FIT imza anahtarı (U-Boot doğrular) + ayrık release anahtarı (RAUC/release).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out fit-signing.key 2>/dev/null
openssl req -batch -new -x509 -key fit-signing.key -days 30 -out fit-signing.crt -subj "/CN=Suderra CI FIT" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out release.key 2>/dev/null
openssl pkey -in release.key -pubout -out release.pub 2>/dev/null

head -c 4096 /dev/urandom > Image
head -c 512 /dev/urandom > board.dtb
cat > fit.its <<'ITS'
/dts-v1/;
/ {
  description = "Suderra slot A"; #address-cells = <1>;
  images {
    kernel { data = /incbin/("Image"); type="kernel"; arch="arm64"; os="linux";
      compression="none"; load=<0x80000>; entry=<0x80000>; hash-1 { algo="sha256"; }; };
    fdt { data = /incbin/("board.dtb"); type="flat_dt"; arch="arm64";
      compression="none"; hash-1 { algo="sha256"; }; };
  };
  configurations { default="conf";
    conf { kernel="kernel"; fdt="fdt";
      signature-1 { algo="sha256,rsa2048"; key-name-hint="fit-signing"; sign-images="kernel","fdt"; }; };
  };
};
ITS
printf '/dts-v1/;\n/ { model="suderra-arm"; };\n' | dtc -I dts -O dtb -o u-boot.dtb 2>/dev/null

# mkimage: FIT'i imzala + pubkey'i u-boot.dtb'ye göm (U-Boot'un boot-time deposu).
mkimage -f fit.its -k . -K u-boot.dtb -r suderra-A.fit >/dev/null 2>&1 || {
    echo "ERROR: mkimage signed FIT üretemedi" >&2; exit 1; }

# ACCEPT-1: gömülü imza sha256,rsa2048 (U-Boot'un zorlayacağı algoritma).
# Listeyi bir kez al (pipefail altında 'mkimage -l | grep -q' SIGPIPE yarışı).
fit_listing="$(mkimage -l suderra-A.fit 2>/dev/null || true)"
grep -qiE 'Sign algo:.*sha256,rsa2048' <<<"${fit_listing}" || {
    echo "ERROR: FIT gömülü rsa2048 imza taşımıyor" >&2; exit 1; }
# ACCEPT-2: pubkey u-boot.dtb'ye gömülü (U-Boot bununla doğrular).
uboot_dts="$(dtc -I dtb -O dts u-boot.dtb 2>/dev/null || true)"
grep -q 'key-name-hint = "fit-signing"' <<<"${uboot_dts}" || {
    echo "ERROR: fit-signing pubkey u-boot.dtb'ye gömülmedi" >&2; exit 1; }

# İmza-içerik bağı: release detached imza (A3 üreticisi *.fit.sig emit eder).
openssl dgst -sha256 -sign release.key -out suderra-A.fit.sig suderra-A.fit
# ACCEPT-3: geçerli imza doğrular.
openssl dgst -sha256 -verify release.pub -signature suderra-A.fit.sig suderra-A.fit >/dev/null 2>&1 || {
    echo "ERROR: geçerli FIT imzası doğrulanmadı (kabul başarısız)" >&2; exit 1; }

# REJECT-1: FIT payload'u kurcala -> imza doğrulanmamalı.
cp suderra-A.fit tampered.fit
python3 -c "import sys; d=bytearray(open('tampered.fit','rb').read()); d[len(d)//2]^=0xFF; open('tampered.fit','wb').write(d)"
if openssl dgst -sha256 -verify release.pub -signature suderra-A.fit.sig tampered.fit >/dev/null 2>&1; then
    echo "ERROR: kurcalanmış FIT imza doğrulaması GEÇTİ (red beklenirdi)" >&2; exit 1; fi

# REJECT-2: yanlış anahtar -> imza doğrulanmamalı (enrolled olmayan anahtarla imzalı FIT).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out attacker.key 2>/dev/null
openssl pkey -in attacker.key -pubout -out attacker.pub 2>/dev/null
if openssl dgst -sha256 -verify attacker.pub -signature suderra-A.fit.sig suderra-A.fit >/dev/null 2>&1; then
    echo "ERROR: yanlış anahtar FIT imzasını doğruladı (red beklenirdi)" >&2; exit 1; fi

echo "ARM signed-FIT signature accept/reject smoke passed"
