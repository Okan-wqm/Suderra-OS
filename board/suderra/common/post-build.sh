#!/usr/bin/env bash
#
# Suderra OS — Buildroot post-build hook
# Buildroot rootfs tree hazır olduktan SONRA, image üretilmeden ÖNCE çalışır.
#
# Görevler:
#   1. suid binary'leri temizle (gerek olmayanlar)
#   2. /etc/os-release populate
#   3. Gereksiz dosyaları sil
#   4. Permission'ları sıkılaştır
#   5. systemd preset uygula
#
# TARGET_DIR — rootfs tree konumu
# BUILDROOT_DIR — Buildroot kaynak ağacı
# BR2_EXTERNAL_SUDERRA_PATH — bu repo'nun kökü
#
# Buildroot tarafından çağrılır:
#   BR2_ROOTFS_POST_BUILD_SCRIPT="$(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra/common/post-build.sh"

set -euo pipefail
IFS=$'\n\t'

TARGET_DIR="${1:?TARGET_DIR not set}"

echo "==> Suderra OS post-build hook"

# 1. /etc/os-release
echo "==> /etc/os-release güncelleniyor"
cat > "${TARGET_DIR}/etc/os-release" <<EOF
NAME="Suderra OS"
ID=suderra-os
ID_LIKE=buildroot
VERSION="${SUDERRA_VERSION:-v0.1.0-alpha}"
VERSION_ID="${SUDERRA_VERSION:-0.1.0}"
PRETTY_NAME="Suderra OS ${SUDERRA_VERSION:-v0.1.0-alpha}"
ANSI_COLOR="0;32"
HOME_URL="https://suderra.example/"
DOCUMENTATION_URL="https://docs.suderra.example/"
SUPPORT_URL="https://suderra.example/support"
BUG_REPORT_URL="https://github.com/Okan-wqm/suderra-os/issues"
BUILD_ID="${SUDERRA_BUILD_ID:-local-dev}"
BUILD_DATE="${SUDERRA_BUILD_DATE:-unknown}"
VARIANT="${SUDERRA_VARIANT:-dev}"
EOF

# 2. Hostname
echo "suderra-edge" > "${TARGET_DIR}/etc/hostname"

# 3. suid binary temizleme — sadece beyaz liste kalır
echo "==> suid binary'ler temizleniyor"
SUID_ALLOWLIST=(
    "/bin/su"          # eğer gerekiyorsa (DEV variant)
    "/usr/bin/sudo"    # eğer gerekiyorsa (DEV variant)
    # PROD variant'ta hiçbiri olmamalı
)
# TODO Faz 3'te: find $TARGET_DIR -perm /4000 -type f kontrolü ve whitelist dışı olanları temizle

# 4. Gereksiz dosyaları sil
echo "==> Gereksiz dosyalar siliniyor"
rm -rf "${TARGET_DIR}/usr/share/man" \
       "${TARGET_DIR}/usr/share/doc" \
       "${TARGET_DIR}/usr/share/info" \
       "${TARGET_DIR}/usr/share/locale"/*/LC_MESSAGES/!(en*).mo \
       2>/dev/null || true

# 5. Permission sıkılaştırma
echo "==> Permission sıkılaştırma"
# /etc/shadow sadece root
chmod 0600 "${TARGET_DIR}/etc/shadow" 2>/dev/null || true
# /root sadece root
chmod 0700 "${TARGET_DIR}/root" 2>/dev/null || true

# 6. systemd preset — sadece istediğimiz unit'ler enable
# Faz 1'de eklenecek

echo "==> post-build tamamlandı"
