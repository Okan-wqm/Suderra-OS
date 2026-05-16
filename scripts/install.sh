#!/usr/bin/env sh
#
# Suderra OS — Edge Agent kurulum helper (Ubuntu apt-style curl|sh)
#
# Kullanım:
#   curl -fsSL https://get.suderra.com | sudo sh
#   curl -fsSL https://get.suderra.com | sudo sh -s -- --version v0.1.0
#   curl -fsSL https://get.suderra.com | sudo sh -s -- --mirror suderra
#
# Veya repo'dan:
#   curl -fsSL https://raw.githubusercontent.com/Okan-wqm/suderra-os/main/scripts/install.sh | sudo sh
#
# Ne yapar:
#   1. Mimari + OS tespit (Suderra OS mu, başka mı)
#   2. suderra-installer binary varsa onu çağırır
#   3. suderra-installer yoksa GitHub Releases'tan indirir + SHA256 + cosign doğrular
#   4. `suderra-installer install edge` çalıştırır
#
# Güvenlik:
#   - POSIX sh, internet'ten alınıp çalıştırılır — kısa ve audit edilebilir
#   - Tüm download SHA256 + cosign keyless ile doğrulanır
#   - Sudo zorunlu
#

set -eu

# ----------------------------------------------------------------------------
# Konfigürasyon (env override desteklenir)
# ----------------------------------------------------------------------------
REPO="${SUDERRA_REPO:-Okan-wqm/suderra-os}"
VERSION="${SUDERRA_VERSION:-latest}"
PACKAGE="${SUDERRA_PACKAGE:-edge}"
MIRROR="${SUDERRA_MIRROR:-github}"
INSTALLER_PATH="${SUDERRA_INSTALLER_PATH:-/usr/local/bin/suderra-installer}"

# ----------------------------------------------------------------------------
# CLI parse
# ----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --version)    VERSION="$2"; shift 2 ;;
        --version=*)  VERSION="${1#*=}"; shift ;;
        --package)    PACKAGE="$2"; shift 2 ;;
        --package=*)  PACKAGE="${1#*=}"; shift ;;
        --mirror)     MIRROR="$2"; shift 2 ;;
        --mirror=*)   MIRROR="${1#*=}"; shift ;;
        -h|--help)
            cat <<'HELP'
Suderra OS — Edge Agent kurulum helper

Kullanım:
  curl -fsSL https://get.suderra.com | sudo sh [-- SEÇENEKLER]

Seçenekler:
  --version <VER>   Belirli sürüm (default: latest)
  --package <PKG>   Paket adı (default: edge)
  --mirror <NAME>   github / suderra / auto (default: github)
  -h, --help        Bu yardımı göster

Ortam değişkenleri:
  SUDERRA_REPO              GitHub repo (default: Okan-wqm/suderra-os)
  SUDERRA_VERSION           Sürüm
  SUDERRA_PACKAGE           Paket adı
  SUDERRA_MIRROR            Mirror tercihi
  SUDERRA_INSTALLER_PATH    suderra-installer kurulum yolu

Örnekler:
  curl -fsSL https://get.suderra.com | sudo sh
  curl -fsSL https://get.suderra.com | sudo sh -s -- --version v0.1.0
  SUDERRA_VERSION=v0.1.0 curl -fsSL https://get.suderra.com | sudo sh
HELP
            exit 0
            ;;
        *)  echo "Bilinmeyen seçenek: $1" >&2; exit 1 ;;
    esac
done

# ----------------------------------------------------------------------------
# Renkli output
# ----------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; N=''
fi

info()  { printf "${B}[INFO]${N}  %s\n" "$*"; }
ok()    { printf "${G}[ OK ]${N}  %s\n" "$*"; }
warn()  { printf "${Y}[WARN]${N}  %s\n" "$*" >&2; }
fail()  { printf "${R}[FAIL]${N}  %s\n" "$*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Fonksiyon: suderra-installer binary indir
# ----------------------------------------------------------------------------
download_installer() {
    URL_BASE="https://github.com/${REPO}/releases"

    if [ "$VERSION" = "latest" ]; then
        URL_BASE="$URL_BASE/latest/download"
        BIN_NAME="suderra-installer-latest-${ARCH}"
    else
        URL_BASE="$URL_BASE/download/${VERSION}"
        BIN_NAME="suderra-installer-${VERSION}-${ARCH}"
    fi

    URL="${URL_BASE}/${BIN_NAME}"
    SHA_URL="${URL}.sha256"

    info "indiriliyor: $URL"

    TMP="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf \"$TMP\"" EXIT

    if ! curl -fsSL "$URL" -o "${TMP}/installer"; then
        rm -rf "$TMP"
        fail "İndirme başarısız: $URL\nLatest release yayınlandı mı?"
    fi

    info "SHA256 doğrulanıyor..."
    if curl -fsSL "$SHA_URL" -o "${TMP}/installer.sha256" 2>/dev/null; then
        EXPECTED="$(awk '{print $1}' "${TMP}/installer.sha256")"
        ACTUAL="$(sha256sum "${TMP}/installer" | awk '{print $1}')"
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            rm -rf "$TMP"
            fail "SHA256 uyuşmazlığı! İndirme bozuk veya manipüle edilmiş.\nBeklenen: $EXPECTED\nGerçek:   $ACTUAL"
        fi
        ok "SHA256 doğrulandı"
    else
        warn "SHA256 dosyası bulunamadı, doğrulama atlanıyor"
    fi

    # cosign varsa signature doğrula
    if command -v cosign >/dev/null 2>&1; then
        info "cosign signature doğrulanıyor..."
        if curl -fsSL "${URL}.sig" -o "${TMP}/installer.sig" 2>/dev/null; then
            # Pin the OIDC subject to release.yml on a SemVer tag so any other
            # workflow in this repo cannot produce signatures that pass.
            cosign_identity_re="^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.\\-]+)?$"
            if cosign verify-blob \
                --certificate-identity-regexp "${cosign_identity_re}" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                --signature "${TMP}/installer.sig" \
                "${TMP}/installer" >/dev/null 2>&1; then
                ok "cosign signature doğrulandı"
            else
                rm -rf "$TMP"
                fail "cosign signature doğrulanamadı!"
            fi
        else
            warn "Signature dosyası yok, atlanıyor"
        fi
    else
        warn "cosign kurulu değil — signature doğrulaması atlandı"
        warn "  Production'da kur: https://docs.sigstore.dev/cosign/installation/"
    fi

    install -m 0755 "${TMP}/installer" "$INSTALLER_PATH"
    ok "suderra-installer kuruldu: $INSTALLER_PATH"
}

# ----------------------------------------------------------------------------
# 1. Root kontrolü
# ----------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    fail "Root yetkisi gerekli. sudo ile çalıştır:\n  curl -fsSL https://get.suderra.com | sudo sh"
fi

# ----------------------------------------------------------------------------
# 2. Bağımlılık kontrolü
# ----------------------------------------------------------------------------
for cmd in curl sha256sum uname install awk mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || fail "'$cmd' kurulu değil"
done

# ----------------------------------------------------------------------------
# 3. Mimari tespit
# ----------------------------------------------------------------------------
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="aarch64" ;;
    *)              fail "Desteklenmeyen mimari: $RAW_ARCH (yalnızca x86_64, aarch64)" ;;
esac
info "Mimari: $ARCH"

# ----------------------------------------------------------------------------
# 4. OS tespit (uyarı amaçlı)
# ----------------------------------------------------------------------------
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    info "OS: $OS_ID $OS_VERSION"
    if [ "$OS_ID" != "suderra-os" ]; then
        warn "Bu sistem Suderra OS değil ($OS_ID)."
        warn "Edge Agent yalnızca Suderra OS üzerinde tam desteklidir."
        if [ -t 0 ]; then
            printf "Devam edilsin mi? [y/N] "
            read -r CONFIRM
            case "$CONFIRM" in
                [yY]|[yY][eE][sS])  ok "devam ediliyor" ;;
                *)                  fail "iptal edildi" ;;
            esac
        else
            warn "Non-interactive shell — yine de devam ediliyor"
        fi
    fi
fi

# ----------------------------------------------------------------------------
# 5. suderra-installer kurulu mu?
# ----------------------------------------------------------------------------
if command -v suderra-installer >/dev/null 2>&1; then
    EXISTING="$(command -v suderra-installer)"
    EXISTING_VERSION="$(suderra-installer --version 2>/dev/null || echo unknown)"
    ok "suderra-installer mevcut: $EXISTING ($EXISTING_VERSION)"
else
    info "suderra-installer kurulu değil, indiriliyor..."
    download_installer
fi

# ----------------------------------------------------------------------------
# 6. Edge Agent kur (delege)
# ----------------------------------------------------------------------------
info "Edge Agent kurulumu başlıyor..."
echo

INSTALL_ARGS="install $PACKAGE --mirror $MIRROR --yes"
if [ "$VERSION" != "latest" ]; then
    INSTALL_ARGS="$INSTALL_ARGS --version $VERSION"
fi

# shellcheck disable=SC2086
suderra-installer $INSTALL_ARGS

echo
ok "Kurulum tamamlandı"
echo
echo "Sıradaki adımlar:"
echo "  systemctl status suderra-$PACKAGE-agent"
echo "  journalctl -u suderra-$PACKAGE-agent -f"
echo
