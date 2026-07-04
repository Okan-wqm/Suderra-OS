#!/usr/bin/env bash
#
# USB installer signed-FIT de-conflict sözleşmesi (PR-A7, ADR-0007).
#
# Installer'ın imzalı-FIT (prod) imajını tanıyıp boot içeriğini MUTASYONA
# UĞRATMADIĞINI (imza/verity bütünlüğü) korur; dev (cmdline.txt) imajda PARTUUID
# pin'i sürer. Gerçek flash donanım/USB'de (G4).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
INST="${ROOT}/package/suderra-os-installer/suderra-os-install"

bash -n "${INST}"

# Prod signed-FIT tespiti + zincir doğrulaması.
grep -q 'suderra-A.fit' "${INST}" || { echo "ERROR: installer signed-FIT imajı tespit etmiyor" >&2; exit 1; }
for f in 'suderra-A.fit' 'suderra-B.fit' 'u-boot.bin' 'boot.scr'; do
    grep -qF -e "${f}" "${INST}" || { echo "ERROR: installer FIT zinciri doğrulamıyor: ${f}" >&2; exit 1; }
done

# İmzalı-FIT imajı mutable cmdline.txt taşımamalı (bütünlük).
grep -q 'must not carry a mutable cmdline.txt' "${INST}" || {
    echo "ERROR: installer signed-FIT'te cmdline.txt'yi reddetmeli" >&2; exit 1; }

# PARTUUID sed mutasyonu YALNIZ dev (cmdline.txt) dalında olmalı — prod'da asla.
# awk: signed-FIT bloğunda sed root=PARTUUID GÖRÜLMEMELİ; cmdline.txt bloğunda görülMELİ.
python3 - "${INST}" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
# signed-FIT branch: from 'if [ -f "${mount_dir}/suderra-A.fit" ]' to the 'elif [ -f "${mount_dir}/cmdline.txt" ]'
m = re.search(r'if \[ -f "\$\{mount_dir\}/suderra-A\.fit" \];(.*?)elif \[ -f "\$\{mount_dir\}/cmdline\.txt" \];', s, re.S)
assert m, "signed-FIT branch not found"
fit_branch = m.group(1)
assert 'sed -i "s#root=' not in fit_branch, "PARTUUID mutation must NOT run in the signed-FIT branch"
# dev branch: from that elif to the trailing else
m2 = re.search(r'elif \[ -f "\$\{mount_dir\}/cmdline\.txt" \];(.*?)\n    else\n', s, re.S)
assert m2, "dev cmdline.txt branch not found"
dev_branch = m2.group(1)
assert 'sed -i "s#root=' in dev_branch, "dev branch must keep the PARTUUID cmdline mutation"
print("branch separation OK")
PY

# Log artık 'PARTUUID boot identity' iddia etmemeli (prod'da PARTUUID yok).
if grep -q 'PARTUUID boot identity' "${INST}"; then
    echo "ERROR: installer log hâlâ PARTUUID boot identity diyor (prod'da geçersiz)" >&2; exit 1; fi
