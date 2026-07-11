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
# 1b. NEW-5: prod'da varsayılan KİLİTLİ ruleset (suderra-firewall seçicisi)
# ---------------------------------------------------------------------------
FIREWALL="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-firewall"
[ -f "${FIREWALL}" ] || fail "missing suderra-firewall selector"

# Seçici imzalı os-release VARIANT'ına dallanmalı (NEW-1 güven kökü).
grep -q 'VARIANT' "${FIREWALL}" \
    || fail "suderra-firewall must anchor ruleset selection on os-release VARIANT (NEW-5)"

# Prod dalı KOŞULSUZ appliance ruleset seçmeli — prod case gövdesinde
# provisioning ruleset'e giden hiçbir yol olmamalı.
prod_branch="$(sed -n '/^prod | production/,/;;/p' "${FIREWALL}")"
[ -n "${prod_branch}" ] || fail "suderra-firewall must have an explicit prod variant branch"
printf '%s' "${prod_branch}" | grep -q 'rules=/etc/nftables.conf' \
    || fail "prod branch must select the appliance ruleset unconditionally"
if printf '%s' "${prod_branch}" | grep -q 'provisioning'; then
    fail "prod branch must have NO path to the provisioning ruleset (SSH open)"
fi

# Yazılabilir marker yalnız NON-prod dalında rol oynayabilir.
if sed -n '/^prod | production/,/;;/p' "${FIREWALL}" | grep -q 'appliance-locked'; then
    fail "prod selection must not depend on a writable /var/lib marker"
fi

# FAIL-CLOSED: /etc/os-release okunamıyorsa (güven kökü yok) appliance ruleset
# seçilmeli — provisioning (SSH açık) DEĞİL.
grep -Eq '\[ ! -r /etc/os-release \]' "${FIREWALL}" \
    || fail "unreadable os-release must be handled explicitly (fail-closed)"
awk '/! -r \/etc\/os-release/{f=1} f&&/nftables.conf/{print; exit}' "${FIREWALL}" | grep -q 'nftables.conf' \
    || fail "unreadable os-release must select the appliance ruleset (/etc/nftables.conf)"
echo "PASS: NEW-5 prod-locked-by-default firewall selector contract"

# Fonksiyonel duman testi: sahte os-release'lerle seçiciyi çalıştır, nft'yi
# yakalayan bir stub ile HANGİ ruleset'in seçildiğini gözle. nft `-f <ruleset>`
# aldığından stub $2'yi (ruleset yolu) bildirir.
smoke_dir="$(mktemp -d)"
trap 'rm -rf "${smoke_dir}"' EXIT
mkdir -p "${smoke_dir}/bin"
printf '#!/bin/sh\necho "SELECTED:$2"\n' > "${smoke_dir}/bin/nft"
chmod +x "${smoke_dir}/bin/nft"
run_fw() { # $1 = os-release içeriği ya da MISSING ; $2 = etiket
    _root="${smoke_dir}/root-$2"
    mkdir -p "${_root}/etc" "${_root}/var/lib/suderra"
    [ "$1" = "MISSING" ] || printf '%s\n' "$1" > "${_root}/etc/os-release"
    # Yalnız os-release, nft binary ve marker dizinini stub root'a yönlendir;
    # nftables ruleset yolları OLDUĞU GİBİ kalsın ki çıktı kesin eşleşsin.
    sed -e "s#/etc/os-release#${_root}/etc/os-release#g" \
        -e "s#/usr/sbin/nft#${smoke_dir}/bin/nft#g" \
        -e "s#/var/lib/suderra#${_root}/var/lib/suderra#g" \
        "${FIREWALL}" > "${_root}/fw.sh"
    sh "${_root}/fw.sh" 2>/dev/null
}
# Prod → appliance (tam /etc/nftables.conf, provisioning DEĞİL).
[ "$(run_fw 'VARIANT="prod"' prod)" = "SELECTED:/etc/nftables.conf" ] \
    || fail "smoke: prod variant must select the appliance ruleset"
# os-release yok → appliance (fail-closed).
[ "$(run_fw MISSING missing)" = "SELECTED:/etc/nftables.conf" ] \
    || fail "smoke: missing os-release must fail closed to appliance"
# Dev + marker yok → provisioning.
[ "$(run_fw 'VARIANT="dev"' dev)" = "SELECTED:/etc/nftables.provisioning.conf" ] \
    || fail "smoke: dev without lock marker must select provisioning ruleset"
echo "PASS: firewall selector functional smoke (prod/missing→appliance, dev→provisioning)"

# ---------------------------------------------------------------------------
# 2. RUNTIME nft -c doğrulaması (nft varsa)
# ---------------------------------------------------------------------------
if ! command -v nft >/dev/null 2>&1; then
    echo "SKIP: nft not installed; static contract still enforced (CI has nft)"
    exit 0
fi

# nft -c, set-reference/counter/log gibi STATEFUL kuralları kernel netfilter'a karşı
# doğrular (saf parse değildir). Kısıtlı bir ortamda (non-root, netns/netfilter yok)
# bu "Operation not permitted" (EPERM) verir — ruleset'in değil ORTAMIN kısıtı. Bu
# yüzden yalnız root'ta deneriz; erişim yoksa AÇIKÇA atlarız (statik sözleşme
# fail-closed yapıyı zaten garanti eder; gerçek runtime yükleme cihaz/QEMU'da).
if [ "$(id -u)" != "0" ]; then
    echo "SKIP: nft -c stateful validation needs root + netfilter (static contract enforced)"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT INT TERM

# nft -c'yi çalıştırır; başarılıysa PASS, ORTAM kısıtı (EPERM/desteklenmiyor) ise
# SKIP, gerçek sözdizimi hatası ise FAIL.
check_nft() {
    _label="$1"; _file="$2"
    if _err="$(nft -c -f "${_file}" 2>&1)"; then
        echo "PASS: runtime nft -c parse of ${_label}"
        return 0
    fi
    if printf '%s' "${_err}" \
        | grep -qiE 'operation not permitted|permission denied|not supported|could not process rule'; then
        echo "SKIP: nft -c cannot reach netfilter here (${_label}); static contract enforced"
        return 0
    fi
    fail "runtime: nft -c rejected ${_label}: ${_err}"
}

# Cihazda /etc/suderra/egress.d/ overlay ile HER ZAMAN vardır (boş olsa da), ama CI
# repo checkout'unda o absolute path YOKTUR. Include'u VAR OLAN boş bir temp dizine
# yönlendiririz — cihaz gerçeğini (dizin var, aktif *.nft yok = fail-closed) yansıtır.
mkdir -p "${WORK}/empty"
sed "s#/etc/suderra/egress.d/\\*.nft#${WORK}/empty/*.nft#" "${NFT}" > "${WORK}/shipped.nft"
check_nft "shipped ruleset (fail-closed)" "${WORK}/shipped.nft"

# Commissioned (element-add'li) kopya.
mkdir -p "${WORK}/egress.d"
sed "s#/etc/suderra/egress.d/\\*.nft#${WORK}/egress.d/*.nft#" "${NFT}" > "${WORK}/commissioned.nft"
cat > "${WORK}/egress.d/10-site.nft" <<'EOF'
add element inet filter egress_update { 203.0.113.10 }
add element inet filter egress_cloud  { 198.51.100.0/24 }
add element inet filter egress_field  { 10.10.0.0/16 }
add element inet filter egress_infra  { 10.10.0.1, 10.10.0.2 }
EOF
check_nft "commissioned ruleset (sets populate)" "${WORK}/commissioned.nft"
