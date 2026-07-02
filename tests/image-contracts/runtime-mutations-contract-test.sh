#!/usr/bin/env bash
#
# runtime_mutations.py sözleşmesi (statik, hermetik).
#
# Üreticilerin GERÇEK koşusu tests/qemu/runtime-mutations-component-test.sh +
# .github/workflows/runtime-mutations.yml içinde. Burada modül yapısının
# sessizce gerilemeyeceğini garanti ederiz: 8 negatif senaryonun her biri için
# üretici var, pozitif senaryo mutasyon üretmez, rauc üreticileri SESSİZCE
# STUB'LANMAZ (build artefaktı yoksa gürültülü hata verir), ve anti-rollback
# fail-closed sürüm kontrolü yerinde.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
MUT="${ROOT}/tests/qemu/runtime_mutations.py"

[ -f "${MUT}" ] || { echo "ERROR: runtime_mutations.py eksik" >&2; exit 1; }
python3 -m py_compile "${MUT}"

for scenario in \
    unsigned-boot-rejection \
    cmdline-tamper-rejection \
    dm-verity-rootfs-tamper-rejection \
    rauc-bad-signature-rejection \
    rauc-good-update \
    rauc-health-rollback \
    anti-rollback-downgrade-rejection \
    data-luks-swtpm
do
    grep -qF -e "\"${scenario}\"" "${MUT}" || {
        echo "ERROR: runtime_mutations.py eksik senaryo üreticisi: ${scenario}" >&2
        exit 1
    }
done

# Pozitif senaryo mutasyon üretmemeli.
grep -q 'NO_MUTATION = {"signed-boot"}' "${MUT}" || {
    echo "ERROR: signed-boot NO_MUTATION olarak işaretlenmeli" >&2
    exit 1
}

# rauc üreticileri sessizce stub'lanmamalı — build ortamı yoksa gürültülü hata.
grep -q 'must be produced by' "${MUT}" || {
    echo "ERROR: rauc üreticileri build ortamı yoksa explicit fail vermeli (stub yasak)" >&2
    exit 1
}

# anti-rollback fail-closed: version floor'un altında olmalı.
grep -q 'must be strictly below floor' "${MUT}" || {
    echo "ERROR: downgrade üreticisi version<floor'u fail-closed zorlamalı" >&2
    exit 1
}

# Modül gerçekten çağrılabilir bir produce() + CLI sunmalı.
grep -q 'def produce(' "${MUT}" || { echo "ERROR: produce() eksik" >&2; exit 1; }

# signed-boot null döndürmeli (mutasyon yok) — hızlı davranışsal kontrol.
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
out="$(python3 "${MUT}" --scenario signed-boot --work-dir "${tmp}/w")"
[ "${out}" = "null" ] || { echo "ERROR: signed-boot null döndürmeli, dönen: ${out}" >&2; exit 1; }
