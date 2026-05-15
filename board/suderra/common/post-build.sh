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
DEFCONFIG_NAME="${2:-unknown}"

echo "==> Suderra OS post-build hook"
echo "    Defconfig: ${DEFCONFIG_NAME}"

CONFIG_VARIANT=""
if [ -n "${BR2_CONFIG:-}" ] && [ -f "${BR2_CONFIG}" ]; then
    if grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_DEV=y' "${BR2_CONFIG}"; then
        CONFIG_VARIANT="dev"
    elif grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${BR2_CONFIG}"; then
        CONFIG_VARIANT="prod"
    fi
fi
ENV_VARIANT="${SUDERRA_VARIANT:-}"
case "${ENV_VARIANT}" in
    ""|dev|prod) ;;
    *)
        echo "ERROR: SUDERRA_VARIANT must be dev or prod, got '${ENV_VARIANT}'"
        exit 1
        ;;
esac
if [ -n "${CONFIG_VARIANT}" ] && [ -n "${ENV_VARIANT}" ] && [ "${CONFIG_VARIANT}" != "${ENV_VARIANT}" ]; then
    echo "ERROR: BR2 Suderra variant (${CONFIG_VARIANT}) conflicts with SUDERRA_VARIANT=${ENV_VARIANT}"
    echo "Production/dev variant selection must come from one authoritative build contract."
    exit 1
fi
if [ -n "${CONFIG_VARIANT}" ]; then
    SUDERRA_OS_VARIANT="${CONFIG_VARIANT}"
elif [ -n "${ENV_VARIANT}" ]; then
    SUDERRA_OS_VARIANT="${ENV_VARIANT}"
else
    case "${DEFCONFIG_NAME}" in
        suderra_x86_64*)
            echo "ERROR: production-capable ${DEFCONFIG_NAME} requires BR2_CONFIG or SUDERRA_VARIANT"
            exit 1
            ;;
        *)
            SUDERRA_OS_VARIANT="dev"
            ;;
    esac
fi

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
VARIANT="${SUDERRA_OS_VARIANT}"
IMAGE_ROLE="${DEFCONFIG_NAME}"
EOF

# 2. Hostname
case "${DEFCONFIG_NAME}" in
    *usb_installer*) HOSTNAME="suderra-usb-installer" ;;
    *revpi4*) HOSTNAME="suderra-revpi4" ;;
    *rpi4*) HOSTNAME="suderra-rpi4" ;;
    *) HOSTNAME="suderra-edge" ;;
esac
echo "${HOSTNAME}" > "${TARGET_DIR}/etc/hostname"

# 3. suid binary temizleme — sadece beyaz liste kalır
echo "==> suid binary'ler temizleniyor"
find "${TARGET_DIR}" -xdev -perm /4000 -type f -exec chmod u-s {} + 2>/dev/null || true

# 4. Gereksiz dosyaları sil
echo "==> Gereksiz dosyalar siliniyor"
rm -rf "${TARGET_DIR}/usr/share/man" \
       "${TARGET_DIR}/usr/share/doc" \
       "${TARGET_DIR}/usr/share/info" \
       2>/dev/null || true
if [ -d "${TARGET_DIR}/usr/share/locale" ]; then
    find "${TARGET_DIR}/usr/share/locale" -mindepth 1 -maxdepth 1 \
        ! -name 'en*' -exec rm -rf {} + 2>/dev/null || true
fi

# 5. Permission sıkılaştırma
echo "==> Permission sıkılaştırma"
# /etc/shadow sadece root
chmod 0600 "${TARGET_DIR}/etc/shadow" 2>/dev/null || true
# /root sadece root
chmod 0700 "${TARGET_DIR}/root" 2>/dev/null || true

# 6. Provisioning helpers
chmod 0700 "${TARGET_DIR}/root" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/root/.profile" 2>/dev/null || true
chmod 0755 "${TARGET_DIR}/usr/sbin/suderra-edge-install" \
           "${TARGET_DIR}/usr/sbin/suderra-lockdown" \
           "${TARGET_DIR}/usr/sbin/suderra-lockdown-status" \
           "${TARGET_DIR}/usr/sbin/suderra-firewall" \
           "${TARGET_DIR}/usr/sbin/suderra-provision" \
           "${TARGET_DIR}/usr/sbin/suderra-provision-worker" \
           "${TARGET_DIR}/usr/sbin/suderra-os-install" \
           2>/dev/null || true
chmod 0644 "${TARGET_DIR}/etc/suderra/edge-install.env" 2>/dev/null || true
chmod 0644 "${TARGET_DIR}/etc/default/dropbear" 2>/dev/null || true
mkdir -p "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants" \
         "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants"
ln -sfn ../nftables.service \
    "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants/nftables.service"
ln -sfn ../../../../usr/lib/systemd/system/systemd-networkd.service \
    "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
ln -sfn ../../../../usr/lib/systemd/system/chrony.service \
    "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/chrony.service"

case "${DEFCONFIG_NAME}" in
    *usb_installer*)
        ln -sfn ../../../../usr/lib/systemd/system/suderra-os-install.service \
            "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-os-install.service"
        ;;
    *)
        ln -sfn ../suderra-data.service \
            "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants/suderra-data.service"
        ln -sfn ../suderra-firstboot.service \
            "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants/suderra-firstboot.service"
        ln -sfn ../../../../usr/lib/systemd/system/dropbear.service \
            "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/dropbear.service"
        ln -sfn ../suderra-agent.service \
            "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-agent.service"
        ln -sfn ../suderra-provision-worker.path \
            "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-provision-worker.path"
        ;;
esac

# 7. Appliance lockdown — Suderra OS genel amaçlı Linux dağıtımı değildir.
# Varsayılan target image provisioning modunda gelir: geçici forced-command
# provision kullanıcısı açıktır. Edge artifact kurulduktan sonra
# /usr/sbin/suderra-lockdown bu politikayı runtime'da uygular. CI veya
# embedded-agent imajları için build-time lockdown SUDERRA_APPLIANCE_MODE=1 ile
# zorlanabilir.
if [ "${SUDERRA_APPLIANCE_MODE:-0}" = "1" ]; then
    echo "==> Appliance lockdown uygulanıyor"

    # Root dahil tüm interactive password login yüzeyini kapat.
    if [ -f "${TARGET_DIR}/etc/shadow" ]; then
        sed -i 's#^root:[^:]*:#root:!:#' "${TARGET_DIR}/etc/shadow"
        sed -i 's#^provision:[^:]*:#provision:!:#' "${TARGET_DIR}/etc/shadow"
    fi
    rm -rf "${TARGET_DIR}/root/.ssh" \
           "${TARGET_DIR}/etc/ssh" \
           "${TARGET_DIR}/etc/dropbear" \
           2>/dev/null || true

    mkdir -p "${TARGET_DIR}/etc/systemd/system" \
             "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants" \
             "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants" \
             "${TARGET_DIR}/etc/systemd/system-preset"

    # Login, rescue/debug shell ve remote shell servisleri image içinde maskeli kalır.
    for unit in \
        getty@.service \
        serial-getty@.service \
        console-getty.service \
        container-getty@.service \
        debug-shell.service \
        rescue.service \
        rescue.target \
        emergency.service \
        emergency.target \
        ctrl-alt-del.target \
        ssh.service \
        sshd.service \
        dropbear.service \
        suderra-provision-worker.path \
        suderra-provision-worker.service \
        systemd-logind.service
    do
        ln -sfn /dev/null "${TARGET_DIR}/etc/systemd/system/${unit}"
    done

    rm -rf "${TARGET_DIR}/etc/systemd/system/getty.target.wants" \
           "${TARGET_DIR}/etc/systemd/system/rescue.target.wants" \
           "${TARGET_DIR}/etc/systemd/system/emergency.target.wants" \
           2>/dev/null || true

    # Preset dosyası gelecekte systemctl preset-all koşulursa aynı politikayı korur.
    cat > "${TARGET_DIR}/etc/systemd/system-preset/00-suderra-appliance.preset" <<'EOF'
disable *
enable systemd-networkd.service
enable chrony.service
enable nftables.service
enable suderra-firstboot.service
enable suderra-agent.service
EOF

fi

echo "==> post-build tamamlandı"
