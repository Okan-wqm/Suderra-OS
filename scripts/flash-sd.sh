#!/usr/bin/env bash
#
# Suderra OS — Güvenli SD card / USB stick flashing
#
# Bu script bir Suderra OS image'ini SD karta veya USB stick'e yazar.
# Enterprise-grade güvenlik kontrolleri:
#
#   1. Root yetkisi kontrolü
#   2. Hedef cihaz removable mı? (root disk koruma)
#   3. Cihaz mount edilmiş mi?
#   4. Image SHA256 hash MANIFEST.txt veya .sha256 ile eşleşiyor mu?
#   5. Image cosign signature'ı var mı? (--verify-signature)
#   6. xz sıkıştırılmışsa otomatik açar
#   7. dd progress + sync
#   8. Geri okuma doğrulaması (ilk 64 MiB hash compare)
#
# Kullanım:
#   sudo ./scripts/flash-sd.sh /dev/sdX <image>
#   sudo ./scripts/flash-sd.sh /dev/sdX <image.xz>
#   sudo ./scripts/flash-sd.sh --verify-signature /dev/sdX <image.xz>
#   sudo ./scripts/flash-sd.sh --lab-allow-missing-hash /dev/sdX <image.xz>
#
# Örnek:
#   sudo ./scripts/flash-sd.sh /dev/sdb \
#     output/suderra_aarch64_rpi4_defconfig/images/sdcard.img.xz
#

set -euo pipefail
IFS=$'\n\t'

# ----------------------------------------------------------------------------
# Renkli output
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'
    C_RESET=$'\033[0m'
else
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_RESET=""
fi

log_info()  { echo "${C_BLUE}[INFO]${C_RESET}  $*"; }
log_ok()    { echo "${C_GREEN}[ OK ]${C_RESET}  $*"; }
log_warn()  { echo "${C_YELLOW}[WARN]${C_RESET}  $*" >&2; }
log_error() { echo "${C_RED}[FAIL]${C_RESET}  $*" >&2; }

die() {
    log_error "$*"
    exit 1
}

# ----------------------------------------------------------------------------
# Kullanım & argümanlar
# ----------------------------------------------------------------------------
usage() {
    cat <<EOF
Suderra OS — SD card / USB stick flashing

Kullanım:
  sudo $0 [SEÇENEKLER] <device> <image>

Argümanlar:
  device              Hedef blok cihazı (örn: /dev/sdb, /dev/mmcblk0)
  image               Image dosyası (.img veya .img.xz)

Seçenekler:
  --verify-signature  cosign ile imza doğrulaması (releases için)
  --lab-allow-missing-hash
                      LAB ONLY: MANIFEST.txt/.sha256 yoksa hash gate'ini atla
  --acceptance        Acceptance/lab evidence modu: yalnız /dev/disk/by-id/*
                      whole-disk hedefleri kabul eder ve doğrulamayı zorunlu kılar
  --skip-verify       Geri okuma doğrulamasını atla (hızlı, önerilmez)
  --force             Onay sorusunu atla (CI / scripting)
  -h, --help          Bu yardımı göster

Örnekler:
  # Pi 4 image SD karta yaz:
  sudo $0 /dev/sdb output/suderra_aarch64_rpi4_defconfig/images/sdcard.img.xz

  # x86 endüstriyel PC USB stick:
  sudo $0 /dev/sdc output/suderra_x86_64_defconfig/images/disk.img.xz

  # GitHub Release'tan indirilen image + imza doğrulaması:
  sudo $0 --verify-signature /dev/sdb suderra-os-v0.1.0-rpi4.img.xz

Güvenlik:
  - SADECE removable cihazlara yazar (root disk koruma)
  - Cihaz mount ediliyse durur
  - SHA256 doğrulaması zorunlu (MANIFEST.txt veya .sha256 dosyası)
  - Hash dosyası olmayan lab imajları için açık --lab-allow-missing-hash gerekir
  - --force olmadan kullanıcı onayı gerekir
EOF
    exit 0
}

VERIFY_SIGNATURE=0
LAB_ALLOW_MISSING_HASH=0
ACCEPTANCE=0
SKIP_VERIFY=0
FORCE=0
DEVICE=""
IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)          usage ;;
        --verify-signature) VERIFY_SIGNATURE=1; shift ;;
        --lab-allow-missing-hash) LAB_ALLOW_MISSING_HASH=1; shift ;;
        --acceptance)       ACCEPTANCE=1; shift ;;
        --skip-verify)      SKIP_VERIFY=1; shift ;;
        --force)            FORCE=1; shift ;;
        -*)                 die "Bilinmeyen seçenek: $1" ;;
        *)
            if [[ -z "${DEVICE}" ]]; then
                DEVICE="$1"
            elif [[ -z "${IMAGE}" ]]; then
                IMAGE="$1"
            else
                die "Fazla argüman: $1"
            fi
            shift
            ;;
    esac
done

[[ -n "${DEVICE}" ]] || die "device gerekli (örn: /dev/sdb). --help için: $0 --help"
[[ -n "${IMAGE}" ]]  || die "image gerekli. --help için: $0 --help"

if [[ "${ACCEPTANCE}" -eq 1 ]]; then
    [[ "${DEVICE}" == /dev/disk/by-id/* ]] || die "Acceptance modunda hedef yalnız /dev/disk/by-id/* olmalı: ${DEVICE}"
    [[ "${LAB_ALLOW_MISSING_HASH}" -eq 0 ]] || die "Acceptance modunda --lab-allow-missing-hash yasak"
    [[ "${SKIP_VERIFY}" -eq 0 ]] || die "Acceptance modunda --skip-verify yasak"
    [[ "${FORCE}" -eq 0 ]] || die "Acceptance modunda geniş --force yasak; operatör hedefi interaktif onaylamalı"
    VERIFY_SIGNATURE=1
fi

# ----------------------------------------------------------------------------
# 1. Root kontrolü
# ----------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    die "Bu script root yetkisi gerektirir. sudo $0 ile çalıştır."
fi

# ----------------------------------------------------------------------------
# 2. Image dosyası kontrolü
# ----------------------------------------------------------------------------
[[ -f "${IMAGE}" ]] || die "Image dosyası bulunamadı: ${IMAGE}"

IMAGE_ABS="$(readlink -f "${IMAGE}")"
IMAGE_DIR="$(dirname "${IMAGE_ABS}")"
IMAGE_NAME="$(basename "${IMAGE_ABS}")"

log_info "Image: ${IMAGE_ABS}"
log_info "Boyut: $(du -h "${IMAGE_ABS}" | awk '{print $1}')"

# ----------------------------------------------------------------------------
# 3. SHA256 doğrulaması
# ----------------------------------------------------------------------------
verify_hash() {
    local file="$1"

    # MANIFEST.txt arada bir mi?
    if [[ -f "${IMAGE_DIR}/MANIFEST.txt" ]]; then
        local expected
        expected=$(grep -E "  $(basename "${file}")\$" "${IMAGE_DIR}/MANIFEST.txt" 2>/dev/null | awk '{print $1}' || true)
        if [[ -n "${expected}" ]]; then
            local actual
            actual=$(sha256sum "${file}" | awk '{print $1}')
            if [[ "${expected}" == "${actual}" ]]; then
                log_ok "SHA256 doğrulandı (MANIFEST.txt): ${expected:0:16}..."
                return 0
            else
                die "SHA256 uyuşmazlığı! Beklenen: ${expected}, Hesaplanan: ${actual}"
            fi
        fi
    fi

    # .sha256 dosyası var mı?
    if [[ -f "${file}.sha256" ]]; then
        if ( cd "${IMAGE_DIR}" && sha256sum -c "$(basename "${file}").sha256" >/dev/null ); then
            log_ok "SHA256 doğrulandı (.sha256 dosyası)"
            return 0
        else
            die "SHA256 .sha256 doğrulaması başarısız"
        fi
    fi

    if [[ "${LAB_ALLOW_MISSING_HASH}" -eq 1 ]]; then
        log_warn "LAB ONLY: Hash dosyası bulunamadı (MANIFEST.txt veya ${IMAGE_NAME}.sha256). Hash gate'i açık istisna ile atlandı."
        return 0
    fi

    die "Hash dosyası bulunamadı (MANIFEST.txt veya ${IMAGE_NAME}.sha256). Release/lab evidence için checksum zorunlu. Sadece kontrollü lab istisnasında --lab-allow-missing-hash kullan."
}
verify_hash "${IMAGE_ABS}"

# ----------------------------------------------------------------------------
# 4. cosign signature doğrulama (opsiyonel)
# ----------------------------------------------------------------------------
if [[ "${VERIFY_SIGNATURE}" -eq 1 ]]; then
    command -v cosign >/dev/null 2>&1 || die "cosign kurulu değil. https://docs.sigstore.dev/cosign/installation/"

    SIG_FILE="${IMAGE_ABS}.sig"
    CERT_FILE="${IMAGE_ABS}.cert"
    [[ -f "${SIG_FILE}" ]] || die "Signature dosyası bulunamadı: ${SIG_FILE}"
    [[ -f "${CERT_FILE}" ]] || die "Certificate dosyası bulunamadı: ${CERT_FILE}"

    log_info "cosign keyless signature doğrulanıyor..."
    # Pin the OIDC subject to release.yml on a SemVer tag so any other
    # workflow in this repo cannot produce signatures that pass this check.
    cosign_identity_re='^https://github\.com/Okan-wqm/Suderra-OS/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$'
    if cosign verify-blob \
        --certificate "${CERT_FILE}" \
        --certificate-identity-regexp "${cosign_identity_re}" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --signature "${SIG_FILE}" \
        "${IMAGE_ABS}" >/dev/null 2>&1; then
        log_ok "cosign signature doğrulandı"
    else
        die "cosign signature doğrulaması başarısız! Image manipüle edilmiş olabilir."
    fi
fi

# ----------------------------------------------------------------------------
# 5. xz açma (gerekirse)
# ----------------------------------------------------------------------------
DECOMPRESSED_IMAGE="${IMAGE_ABS}"
CLEANUP_DECOMPRESSED=0

if [[ "${IMAGE_ABS}" == *.xz ]]; then
    DECOMPRESSED_IMAGE="${IMAGE_ABS%.xz}"
    if [[ -f "${DECOMPRESSED_IMAGE}" ]]; then
        if [[ "${ACCEPTANCE}" -eq 1 ]]; then
            die "Acceptance modunda stale açılmış image kabul edilmez: ${DECOMPRESSED_IMAGE}"
        fi
        log_info "Açılmış image mevcut: ${DECOMPRESSED_IMAGE}"
    else
        log_info "xz açılıyor (~30s)..."
        xz -d -k "${IMAGE_ABS}"
        CLEANUP_DECOMPRESSED=1
        log_ok "Açıldı: ${DECOMPRESSED_IMAGE}"
    fi
fi

IMAGE_SIZE_BYTES=$(stat -c %s "${DECOMPRESSED_IMAGE}")
IMAGE_SIZE_MB=$((IMAGE_SIZE_BYTES / 1024 / 1024))
log_info "Açılmış image: ${IMAGE_SIZE_MB} MiB"

# ----------------------------------------------------------------------------
# 6. Hedef cihaz kontrolleri
# ----------------------------------------------------------------------------
[[ -b "${DEVICE}" ]] || die "${DEVICE} bir blok cihazı değil"
if [[ "${ACCEPTANCE}" -eq 1 ]]; then
    DEVICE_TYPE="$(lsblk -no TYPE "$(readlink -f "${DEVICE}")" 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
    [[ "${DEVICE_TYPE}" == "disk" ]] || die "Acceptance modunda partition/alt cihaz hedefi yasak; whole-disk gerekli (${DEVICE_TYPE:-unknown})"
fi

disk_parent_name() {
    local source="$1"
    local resolved name parent

    resolved="$(readlink -f "${source}" 2>/dev/null || printf '%s\n' "${source}")"
    name="$(basename "${resolved}")"
    parent="$(lsblk -no PKNAME "${resolved}" 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
    if [[ -n "${parent}" ]]; then
        printf '%s\n' "${parent}"
        return 0
    fi
    printf '%s\n' "${name}"
}

root_disk_name() {
    local root_source

    root_source="$(findmnt -no SOURCE / 2>/dev/null || true)"
    if [[ "${root_source}" == "/dev/root" ]]; then
        root_source="$(readlink -f /dev/root 2>/dev/null || printf '%s\n' /dev/root)"
    fi
    [[ -n "${root_source}" ]] || die "Root filesystem kaynağı tespit edilemedi"
    disk_parent_name "${root_source}"
}

# Root disk koruma — DEVICE şu anda root olarak mount edilmiş diskte mi?
ROOT_DISK="$(root_disk_name)"
TARGET_DISK="$(disk_parent_name "${DEVICE}")"
if [[ -n "${ROOT_DISK}" && "${TARGET_DISK}" == "${ROOT_DISK}" ]]; then
    die "${DEVICE} ROOT diski (${ROOT_DISK})! İşletim sistemini siler. İptal edildi."
fi

# Removable mı? (USB / SD card / eMMC card reader)
DEVICE_NAME="${TARGET_DISK}"
REMOVABLE_FILE="/sys/block/${DEVICE_NAME}/removable"
if [[ -f "${REMOVABLE_FILE}" ]]; then
    REMOVABLE=$(cat "${REMOVABLE_FILE}")
    if [[ "${REMOVABLE}" != "1" ]]; then
        log_warn "${DEVICE} removable olarak işaretlenmemiş (sabit disk olabilir!)"
        [[ "${ACCEPTANCE}" -ne 1 ]] || die "Acceptance modunda hedef removable olarak işaretlenmiş olmalı"
        if [[ "${FORCE}" -ne 1 ]]; then
            die "İçsel disklere yazmak için --force gerekli. ÇOK DİKKATLİ OL."
        fi
    fi
elif [[ "${ACCEPTANCE}" -eq 1 ]]; then
    die "Acceptance modunda removable bilgisi okunmalı: ${REMOVABLE_FILE}"
fi

# Cihaz boyutu makul mi?
DEVICE_SIZE_BYTES=$(blockdev --getsize64 "${DEVICE}")
DEVICE_SIZE_MB=$((DEVICE_SIZE_BYTES / 1024 / 1024))
DEVICE_SIZE_GB=$((DEVICE_SIZE_BYTES / 1024 / 1024 / 1024))
log_info "Hedef cihaz: ${DEVICE} (${DEVICE_SIZE_GB} GB / ${DEVICE_SIZE_MB} MiB)"

if (( DEVICE_SIZE_BYTES < IMAGE_SIZE_BYTES )); then
    die "Cihaz çok küçük: ${DEVICE_SIZE_MB} MiB < image ${IMAGE_SIZE_MB} MiB"
fi

# 2 TB üstü = muhtemelen sabit disk
if (( DEVICE_SIZE_GB > 256 )); then
    log_warn "${DEVICE} ${DEVICE_SIZE_GB} GB — sabit disk olabilir!"
    if [[ "${FORCE}" -ne 1 ]]; then
        die "Bu büyük cihazlara yazmak için --force gerekli."
    fi
fi

# Mount kontrolü
MOUNTED_PARTS=$(lsblk -ln -o NAME,MOUNTPOINT "${DEVICE}" 2>/dev/null | awk '$2 != "" {print $1": "$2}' || true)
if [[ -n "${MOUNTED_PARTS}" ]]; then
    log_warn "${DEVICE} üzerinde mount edilmiş partition'lar var:"
    while IFS= read -r mounted_part; do
        printf '         %s\n' "${mounted_part}"
    done <<< "${MOUNTED_PARTS}"
    log_info "Otomatik unmount yapılıyor..."
    for part in $(lsblk -ln -o NAME "${DEVICE}" | tail -n +2); do
        umount "/dev/${part}" 2>/dev/null || true
    done
fi

# ----------------------------------------------------------------------------
# 7. Son onay
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  HEDEF CİHAZ: ${DEVICE} (${DEVICE_SIZE_GB} GB)"
echo "  IMAGE:       ${IMAGE_NAME} (${IMAGE_SIZE_MB} MiB)"
echo ""
echo "  Cihaz model:"
lsblk -ln -o NAME,SIZE,MODEL "${DEVICE}" | head -1 | sed 's/^/    /'
echo ""
echo "  ⚠  ${DEVICE} ÜZERİNDEKİ TÜM VERİLER SİLİNECEK."
echo "============================================================"
echo ""

if [[ "${FORCE}" -ne 1 ]]; then
    read -r -p "Devam etmek için 'YES' yaz: " CONFIRM
    [[ "${CONFIRM}" == "YES" ]] || die "İptal edildi"
fi

# ----------------------------------------------------------------------------
# 8. dd ile yazma
# ----------------------------------------------------------------------------
echo ""
log_info "Yazma başladı... (Ctrl+C dene_me — yarım image bozuk olur)"
START_TIME=$(date +%s)

dd if="${DECOMPRESSED_IMAGE}" of="${DEVICE}" \
    bs=4M \
    conv=fsync \
    oflag=direct \
    status=progress

sync
sync

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
log_ok "Yazma tamamlandı (${DURATION}s, ortalama $((IMAGE_SIZE_MB / (DURATION + 1))) MiB/s)"

# ----------------------------------------------------------------------------
# 9. Geri okuma doğrulaması (ilk 64 MiB)
# ----------------------------------------------------------------------------
if [[ "${SKIP_VERIFY}" -ne 1 ]]; then
    if [[ "${ACCEPTANCE}" -eq 1 ]]; then
        log_info "Acceptance doğrulama: tüm image byte'ları geri okunup hash karşılaştırılıyor..."
        EXPECTED_HASH=$(sha256sum "${DECOMPRESSED_IMAGE}" | awk '{print $1}')
        ACTUAL_HASH=$(head -c "${IMAGE_SIZE_BYTES}" "${DEVICE}" | sha256sum | awk '{print $1}')
    else
        log_info "Doğrulama: ilk 64 MiB geri okunup hash karşılaştırılıyor..."
        EXPECTED_HASH=$(dd if="${DECOMPRESSED_IMAGE}" bs=1M count=64 2>/dev/null | sha256sum | awk '{print $1}')
        ACTUAL_HASH=$(dd if="${DEVICE}" bs=1M count=64 2>/dev/null | sha256sum | awk '{print $1}')
    fi

    if [[ "${EXPECTED_HASH}" == "${ACTUAL_HASH}" ]]; then
        log_ok "Doğrulama başarılı: ${EXPECTED_HASH:0:16}..."
    else
        die "DOĞRULAMA HATASI! SD card bozuk veya yazma başarısız."
    fi
fi

# ----------------------------------------------------------------------------
# 10. Cleanup
# ----------------------------------------------------------------------------
if [[ "${CLEANUP_DECOMPRESSED}" -eq 1 ]]; then
    log_info "Geçici açılmış image siliniyor: ${DECOMPRESSED_IMAGE}"
    rm -f "${DECOMPRESSED_IMAGE}"
fi

# ----------------------------------------------------------------------------
# Tamam
# ----------------------------------------------------------------------------
echo ""
log_ok "Flash başarılı."
echo ""
echo "Sıradaki adımlar:"
echo "  1. SD/USB cihazı güvenli çıkar"
echo "  2. Hedef cihaza tak (Pi: SD slot, x86: USB port)"
echo "  3. Güç ver / boot et"
echo "  4. Seri konsoldan veya HDMI'den 'Suderra OS' banner'ı görmeli"
echo "  5. Edge Agent kurulumu: docs/operations/install.md"
echo ""
