#!/usr/bin/env bash
#
# OVMF Secure Boot enrollment sözleşmesi (statik, hermetik).
#
# Bu test araç çalıştırmaz (enroll helper'ının GERÇEK koşusu
# .github/workflows/secureboot-enroll.yml bileşen testinde). Burada, enrollment
# yapısının sessizce gerilemeyeceğini kod düzeyinde garanti ederiz:
#   1. enroll helper var, virt-fw-vars ile PK/KEK/db enroll edip Secure Boot açar.
#   2. production-runtime suite builder enrollment hash'lerini SAHTELEMEZ
#      (enroll edilmemiş vars dosyasının hash'ini "enrolled" göstermez).
#   3. runtime-plan + workflow enrollment alanlarını uçtan uca taşır.
#   4. gen-dev-keys PK ve KEK üretir (db ile birlikte tam SB hiyerarşisi).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ENROLL="${ROOT}/scripts/qemu/enroll-secureboot-vars"
RUNTIME_PY="${ROOT}/tests/qemu/production-runtime.py"
EVIDENCE_PY="${ROOT}/scripts/evidence/evidence_contract.py"
WORKFLOW="${ROOT}/.github/workflows/production-runtime-qemu.yml"
GEN_KEYS="${ROOT}/scripts/gen-dev-keys.sh"

[ -x "${ENROLL}" ] || {
    echo "ERROR: enroll-secureboot-vars eksik veya çalıştırılabilir değil" >&2
    exit 1
}

for token in 'virt-fw-vars' '--set-pk' '--add-kek' '--add-db' '--secure-boot' 'secure_boot_db_sha256' 'enrolled_vars_sha256'; do
    grep -qF -e "${token}" "${ENROLL}" || {
        echo "ERROR: enroll helper eksik token: ${token}" >&2
        exit 1
    }
done

# Fail-closed doğrulama betikte olmalı (enrollment etkisizse hata).
grep -q 'enrolled_vars_sha256.*!=.*blank_sha256\|blank_sha256.*enrolled' "${ENROLL}" \
    || grep -q 'enrollment etkisiz' "${ENROLL}" || {
    echo "ERROR: enroll helper enrolled==blank durumunu fail-closed kontrol etmeli" >&2
    exit 1
}

# Sahte fallback yasağı: enrollment hash'leri vars dosyasından türetilmemeli.
if grep -nE 'ovmf_enrolled_vars_sha256".*sha256_file|secure_boot_db_sha256".*sha256_file' "${RUNTIME_PY}"; then
    echo "ERROR: production-runtime.py enrollment hash'lerini vars dosyasından üretmemeli (sahte)" >&2
    exit 1
fi
# Enrollment alanları plandan zorunlu okunmalı.
grep -q "require_string(plan, \"ovmf_enrollment_mode\"" "${RUNTIME_PY}" || {
    echo "ERROR: production-runtime.py ovmf_enrollment_mode'u plandan zorunlu okumalı" >&2
    exit 1
}

# runtime-plan üreticisi enrollment alanlarını üretmeli.
for token in 'ovmf_enrollment_mode' 'ovmf_enrolled_vars_sha256' 'secure_boot_db_sha256'; do
    grep -qF -e "${token}" "${EVIDENCE_PY}" || {
        echo "ERROR: evidence_contract.py runtime-plan eksik enrollment alanı: ${token}" >&2
        exit 1
    }
done

# Workflow enrollment adımını çağırmalı ve enrolled vars kullanmalı.
for token in 'enroll-secureboot-vars' 'OVMF_VARS.enrolled.fd' '--ovmf-enrolled-vars-sha256' '--secure-boot-db-sha256'; do
    grep -qF -e "${token}" "${WORKFLOW}" || {
        echo "ERROR: production-runtime-qemu.yml eksik enrollment wiring: ${token}" >&2
        exit 1
    }
done
# Workflow enroll edilmemiş düz OVMF_VARS'ı plana VERMEMELİ.
if grep -qE -- '--ovmf-vars runtime-inputs/OVMF_VARS\.fd' "${WORKFLOW}"; then
    echo "ERROR: workflow plana enroll edilmemiş OVMF_VARS.fd veriyor" >&2
    exit 1
fi

# gen-dev-keys tam SB hiyerarşisi üretmeli.
for token in 'uefi-pk.key' 'uefi-kek.key' 'uefi-db.key'; do
    grep -qF -e "${token}" "${GEN_KEYS}" || {
        echo "ERROR: gen-dev-keys.sh eksik SB anahtarı: ${token}" >&2
        exit 1
    }
done
