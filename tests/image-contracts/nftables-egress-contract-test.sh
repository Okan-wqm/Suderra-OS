#!/bin/sh
# nftables-egress-contract-test — appliance egress fail-closed sözleşmesi (NEW-2).
#
# Endüstriyel least-privilege (IEC 62443): cihaz yalnız açıkça beyan edilmiş
# hedeflere çıkabilir. Bu test:
#   1. STATİK: egress named-set'lerle hedefe göre kısıtlı; portlar keyfi hedefe
#      açık DEĞİL; egress config yalnız imzalı RO rootfs'ten include edilir; örnek
#      şablon glob'a girmez.
#   2. RUNTIME (nft varsa): ruleset'i `nft -c` ile gerçekten parse eder; ayrıca
#      commissioned (element-add'li) bir kopyayı da doğrular.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NFT="${ROOT}/board/suderra/common/rootfs-overlay/etc/nftables.conf"
EGRESS_DIR="${ROOT}/board/suderra/common/rootfs-overlay/etc/suderra/egress.d"
fail() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. STATİK sözleşme
# ---------------------------------------------------------------------------
[ -f "${NFT}" ] || fail "missing nftables.conf"

# Üç zincir de default-drop.
[ "$(grep -c 'policy drop' "${NFT}")" -ge 3 ] \
    || fail "input/forward/output chains must all be 'policy drop'"

# Egress named-set'lerle beyan edilmiş olmalı (fail-closed allow-list).
for s in egress_update egress_cloud egress_field egress_infra; do
    grep -q "set ${s} " "${NFT}" || fail "missing egress set declaration: ${s}"
    grep -q "@${s}" "${NFT}" || fail "egress set ${s} declared but never referenced in a rule"
done

# Egress portları YALNIZ bir hedef-set ile gate'li kabul edilmeli — keyfi hedefe
# açık 'tcp dport <p> accept' (daddr @set olmadan) OLMAMALI.
for p in 443 8883 502 4840; do
    if grep -E "dport (\{[^}]*\<${p}\>[^}]*\}|${p})" "${NFT}" \
        | grep 'accept' | grep -qv '@egress_'; then
        fail "port ${p} egress accepted without a destination set (not fail-closed)"
    fi
done

# Config yalnız imzalı RO rootfs'ten include edilmeli; /data'dan ASLA (fail-open riski).
grep -q 'include "/etc/suderra/egress.d/\*.nft"' "${NFT}" \
    || fail "egress config must be included from the signed RO /etc/suderra/egress.d"
if grep -q 'include "/data' "${NFT}"; then
    fail "egress config must NOT be included from writable /data (malformed file would fail-OPEN)"
fi

# egress.d dizini imajda olmalı (deterministik boş-glob) ve örnek şablon
# GLOB'A GİRMEMELİ (.example uzantısı, *.nft ile eşleşmez).
[ -d "${EGRESS_DIR}" ] || fail "egress.d overlay directory must ship in the image"
for f in "${EGRESS_DIR}"/*.nft; do
    [ -e "${f}" ] && fail "no active *.nft egress file must ship by default (fail-closed): ${f}"
done
[ -f "${EGRESS_DIR}/00-example.nft.example" ] \
    || fail "an operator egress template (.example) must ship for commissioning"
echo "PASS: static nftables egress fail-closed contract"

# ---------------------------------------------------------------------------
# 2. RUNTIME nft -c doğrulaması (nft varsa)
# ---------------------------------------------------------------------------
if ! command -v nft >/dev/null 2>&1; then
    echo "SKIP: nft not installed; static contract still enforced (CI has nft)"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT INT TERM

# Cihazda /etc/suderra/egress.d/ overlay ile HER ZAMAN vardır (boş olsa da), ama CI
# repo checkout'unda o absolute path YOKTUR. nft sürümleri "olmayan dizin glob'unu"
# farklı ele alır (kimi tolere eder, kimi reddeder). Ruleset SÖZDİZİMİNİ sağlam
# doğrulamak için include'u VAR OLAN boş bir temp dizine yönlendiririz — bu, cihaz
# gerçeğini (dizin var, aktif *.nft yok = fail-closed) birebir yansıtır.
mkdir -p "${WORK}/empty"
sed "s#/etc/suderra/egress.d/\\*.nft#${WORK}/empty/*.nft#" "${NFT}" > "${WORK}/shipped.nft"
if ! err="$(nft -c -f "${WORK}/shipped.nft" 2>&1)"; then
    fail "runtime: nft -c rejected the shipped ruleset (empty egress.d): ${err}"
fi
echo "PASS: runtime nft -c parse of shipped ruleset (fail-closed)"

# Commissioned (element-add'li) kopya da geçerli olmalı.
mkdir -p "${WORK}/egress.d"
sed "s#/etc/suderra/egress.d/\\*.nft#${WORK}/egress.d/*.nft#" "${NFT}" > "${WORK}/commissioned.nft"
cat > "${WORK}/egress.d/10-site.nft" <<'EOF'
add element inet filter egress_update { 203.0.113.10 }
add element inet filter egress_cloud  { 198.51.100.0/24 }
add element inet filter egress_field  { 10.10.0.0/16 }
add element inet filter egress_infra  { 10.10.0.1, 10.10.0.2 }
EOF
if ! err="$(nft -c -f "${WORK}/commissioned.nft" 2>&1)"; then
    fail "runtime: commissioned ruleset (populated sets) failed nft -c: ${err}"
fi
echo "PASS: runtime nft -c parse of commissioned ruleset (sets populate)"
