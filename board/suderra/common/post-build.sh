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
# VERSION_ID and SUDERRA_AGENT_ABI are compatibility facts the root installer
# checks releases against (contracts/suderra-edge/v1/statements.json
# compatibility, ADR-048 DEC-23): VERSION_ID is MAJOR.MINOR.PATCH, unquoted;
# SUDERRA_AGENT_ABI is the inclusive agent ABI range this OS supports.
SUDERRA_AGENT_ABI_RANGE="1-1"
SUDERRA_VERSION_TEXT="${SUDERRA_VERSION:-v0.1.0-alpha}"
SUDERRA_VERSION_ID="$(printf '%s\n' "${SUDERRA_VERSION_TEXT}" |
    sed -n 's/^v\{0,1\}\(\(0\|[1-9][0-9]*\)\.\(0\|[1-9][0-9]*\)\.\(0\|[1-9][0-9]*\)\)\([-+].*\)\{0,1\}$/\1/p')"
if [ -z "${SUDERRA_VERSION_ID}" ]; then
    echo "ERROR: SUDERRA_VERSION '${SUDERRA_VERSION_TEXT}' does not start with MAJOR.MINOR.PATCH"
    exit 1
fi
echo "==> /etc/os-release güncelleniyor"
cat > "${TARGET_DIR}/etc/os-release" <<EOF
NAME="Suderra OS"
ID=suderra-os
ID_LIKE=buildroot
VERSION="${SUDERRA_VERSION_TEXT}"
VERSION_ID=${SUDERRA_VERSION_ID}
PRETTY_NAME="Suderra OS ${SUDERRA_VERSION_TEXT}"
ANSI_COLOR="0;32"
HOME_URL="https://suderra.example/"
DOCUMENTATION_URL="https://docs.suderra.example/"
SUPPORT_URL="https://suderra.example/support"
BUG_REPORT_URL="https://github.com/Okan-wqm/suderra-os/issues"
BUILD_ID="${SUDERRA_BUILD_ID:-local-dev}"
BUILD_DATE="${SUDERRA_BUILD_DATE:-unknown}"
VARIANT="${SUDERRA_OS_VARIANT}"
IMAGE_ROLE="${DEFCONFIG_NAME}"
SUDERRA_AGENT_ABI=${SUDERRA_AGENT_ABI_RANGE}
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

# 6. Image facts (ADR-048 DEC-8.2, DEC-23).
# boards.json of the vendored edge contract is the one board vocabulary: it
# maps this defconfig to its board_profile, or classifies it as an image that
# declares no board (a pending board family's qualification base or an
# excluded image), which runs no agent and no provisioning surface.
SUDERRA_EXTERNAL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
BOARDS_JSON="${SUDERRA_EXTERNAL_DIR}/contracts/suderra-edge/v1/boards.json"
[ -f "${BOARDS_JSON}" ] || {
    echo "ERROR: vendored edge contract boards.json missing: ${BOARDS_JSON}"
    exit 1
}
board_facts="$(python3 -I - "${BOARDS_JSON}" "${DEFCONFIG_NAME}_defconfig" <<'PY'
import json, sys
boards = json.load(open(sys.argv[1], encoding="utf-8"))
defconfig = sys.argv[2]
rows = [b for b in boards["boards"] if any(i["defconfig"] == defconfig for i in b["os_images"])]
boardless = [f for f in boards["pending_board_families"] if any(i["defconfig"] == defconfig for i in f["os_images"])]
boardless += [e for e in boards["excluded_os_images"] if e["defconfig"] == defconfig]
if len(rows) + len(boardless) != 1:
    sys.exit(f"{defconfig} is classified {len(rows) + len(boardless)} times in boards.json; it must be exactly once")
if rows:
    b = rows[0]
    print(f"{b['board_profile']}\t{b['arch']}\t{b['rauc_compatible']}\t{b['device_binding_method']}")
else:
    print("-")
PY
)"
if [ "${board_facts}" = "-" ]; then
    SUDERRA_BOARD_PROFILE=""
else
    IFS=$'\t' read -r SUDERRA_BOARD_PROFILE SUDERRA_BOARD_ARCH SUDERRA_RAUC_COMPATIBLE \
        SUDERRA_DEVICE_BINDING_METHOD <<<"${board_facts}"
fi

config_enabled() {
    [ -n "${BR2_CONFIG:-}" ] && grep -q "^$1=y" "${BR2_CONFIG}"
}

mkdir -p "${TARGET_DIR}/etc/suderra"
rm -f "${TARGET_DIR}/etc/suderra/board" "${TARGET_DIR}/etc/suderra/features" \
      "${TARGET_DIR}/etc/suderra/cloud-endpoint"
# Declared features of every image, with or without a board, from what the
# image is built with: the health predicate (`suderra-installer health
# check`, which runs on every image) fails on a declared feature that is
# absent at run time and never probes for undeclared ones (DEC-6.8).
image_arch=""
if config_enabled BR2_x86_64; then
    image_arch=x86_64
elif config_enabled BR2_aarch64; then
    image_arch=aarch64
fi
if [ -n "${SUDERRA_BOARD_PROFILE}" ] && [ "${image_arch}" != "${SUDERRA_BOARD_ARCH}" ]; then
    echo "ERROR: ${DEFCONFIG_NAME} builds ${image_arch:-an unknown arch}, boards.json says ${SUDERRA_BOARD_ARCH}"
    exit 1
fi
features=""
if [ "${SUDERRA_OS_VARIANT}" = "prod" ]; then
    features="verity luks"
    case "${image_arch}" in
        x86_64) features="${features} secure-boot" ;;
    esac
fi
if config_enabled BR2_PACKAGE_RAUC; then
    features="${features} rauc"
fi
if [ -n "${SUDERRA_BOARD_PROFILE}" ] &&
   [ "${SUDERRA_DEVICE_BINDING_METHOD}" = "tpm-ek-sha256" ] &&
   config_enabled BR2_PACKAGE_TPM2_TOOLS; then
    features="${features} tpm"
fi
features="$(printf '%s\n' "${features}" | xargs)"
printf 'FEATURES="%s"\n' "${features}" > "${TARGET_DIR}/etc/suderra/features"
chmod 0644 "${TARGET_DIR}/etc/suderra/features"
echo "==> declared features: ${features:-none}"
if [ -n "${SUDERRA_BOARD_PROFILE}" ]; then
    cat > "${TARGET_DIR}/etc/suderra/board" <<EOF
BOARD_PROFILE=${SUDERRA_BOARD_PROFILE}
ARCH=${SUDERRA_BOARD_ARCH}
RAUC_COMPATIBLE=${SUDERRA_RAUC_COMPATIBLE}
DEVICE_BINDING_METHOD=${SUDERRA_DEVICE_BINDING_METHOD}
EOF
    chmod 0644 "${TARGET_DIR}/etc/suderra/board"
    echo "==> board_profile ${SUDERRA_BOARD_PROFILE}"
    # The provisioning API the root installer fetches deliveries from
    # (DEC-5.5): a build-time fact of every image with a board.
    config_enabled BR2_PACKAGE_SUDERRA_OS_INSTALLER || {
        echo "ERROR: ${DEFCONFIG_NAME} has a board but no root installer (BR2_PACKAGE_SUDERRA_OS_INSTALLER)"
        exit 1
    }
    cloud_endpoint="$(sed -n 's/^BR2_PACKAGE_SUDERRA_OS_INSTALLER_CLOUD_ENDPOINT="\(.*\)"$/\1/p' "${BR2_CONFIG}")"
    # The installer's is_https_url: https, host [A-Za-z0-9.-], optional port,
    # no query, no fragment, no trailing slash.
    if ! printf '%s\n' "${cloud_endpoint}" |
        grep -Eqx 'https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%!$&()*+,;=:@/-]*[^/])?'; then
        echo "ERROR: ${DEFCONFIG_NAME}: BR2_PACKAGE_SUDERRA_OS_INSTALLER_CLOUD_ENDPOINT=\"${cloud_endpoint}\" is not an https base URL"
        exit 1
    fi
    printf '%s\n' "${cloud_endpoint}" > "${TARGET_DIR}/etc/suderra/cloud-endpoint"
    chmod 0644 "${TARGET_DIR}/etc/suderra/cloud-endpoint"
    echo "==> provisioning API ${cloud_endpoint}"
else
    echo "==> ${DEFCONFIG_NAME} declares no board_profile; it runs no edge agent"
fi

# RAUC compatible (ADR-048 DEC-8.3): one per board, so no board's bundle
# installs on another. scripts/ci/rauc-compatible.py takes the compatible of
# the image's OTA target from ci/evidence-contract.yml (the value the bundle
# tool signs into every bundle of that target) and fails unless it equals the
# board's boards.json rauc_compatible (and so RAUC_COMPATIBLE above), or, for
# an image with no board, unless it differs from every board's.
RAUC_SYSTEM_CONF="${TARGET_DIR}/etc/rauc/system.conf"
if [ -f "${RAUC_SYSTEM_CONF}" ]; then
    rauc_compatible="$(python3 -I "${SUDERRA_EXTERNAL_DIR}/scripts/ci/rauc-compatible.py" \
        --root "${SUDERRA_EXTERNAL_DIR}" image "${DEFCONFIG_NAME}_defconfig")"
    # Idempotent: Buildroot reruns post-build on an already filled target.
    sed -i "s/^compatible=@SUDERRA_RAUC_COMPATIBLE@\$/compatible=${rauc_compatible}/" "${RAUC_SYSTEM_CONF}"
    if ! grep -qx "compatible=${rauc_compatible}" "${RAUC_SYSTEM_CONF}" ||
       [ "$(grep -c '^compatible=' "${RAUC_SYSTEM_CONF}")" -ne 1 ]; then
        echo "ERROR: ${RAUC_SYSTEM_CONF} must carry exactly compatible=${rauc_compatible}"
        exit 1
    fi
    echo "==> RAUC compatible ${rauc_compatible}"
fi

# Kernel config list (statements.json compatibility.kernel_config): one
# CONFIG_<NAME>=y|m line per enabled symbol of the kernel this image boots.
if [ -n "${BUILD_DIR:-}" ]; then
    mapfile -t kernel_configs < <(find "${BUILD_DIR}" -mindepth 2 -maxdepth 2 -name .config \
        -path '*/linux-*' ! -path '*/linux-headers-*' ! -path '*/linux-firmware-*' \
        ! -path '*/linux-tools-*' | sort)
    if [ "${#kernel_configs[@]}" -ne 1 ]; then
        echo "ERROR: expected exactly one kernel .config under ${BUILD_DIR}, found ${#kernel_configs[@]}"
        exit 1
    fi
    grep -E '^CONFIG_[A-Z0-9_]+=[ym]$' "${kernel_configs[0]}" > "${TARGET_DIR}/etc/suderra/kernel-config"
    chmod 0644 "${TARGET_DIR}/etc/suderra/kernel-config"
    # Kernel config contract (ADR-048 DEC-8.10): no image is built whose
    # resolved kernel lacks a required symbol, names a symbol the kernel does
    # not define, or silently drops a line of its config files.
    # --root is the tool's global option: it precedes the subcommand.
    python3 -I "${SUDERRA_EXTERNAL_DIR}/scripts/ci/check-kernel-config.py" --root "${SUDERRA_EXTERNAL_DIR}" resolved \
        --defconfig "${DEFCONFIG_NAME}_defconfig" \
        --kernel-tree "$(dirname -- "${kernel_configs[0]}")"
else
    echo "ERROR: BUILD_DIR is not set; post-build runs from Buildroot, which exports it"
    exit 1
fi

# 7. Read-only root mutable state (ADR-048 DEC-4.2, DEC-24;
# contracts/suderra-edge/v1/mutable-state.json). The root is never written at
# run time: every mountpoint exists in the image, suderra-data-unlock binds
# /data trees onto them, and /run trees come from usr/lib/tmpfiles.d.
echo "==> Mountpoint'ler ve read-only root"
for mountpoint in \
    /data \
    /var/lib/suderra-os \
    /var/lib/suderra-installer \
    /var/lib/suderra-site \
    /var/lib/suderra \
    /var/log/suderra \
    /var/lib/chrony \
    /opt/suderra/edge \
    /var/spool/suderra-provision
do
    mkdir -p "${TARGET_DIR}${mountpoint}"
done
rm -rf "${TARGET_DIR}/opt/suderra/edge/releases" "${TARGET_DIR}/var/lib/suderra/config"
# Buildroot links /etc/dropbear to /var/run/dropbear; the provisioning host
# key lives on /data instead (bound from /data/suderra/os/ssh, DEC-5.3).
if [ -L "${TARGET_DIR}/etc/dropbear" ]; then
    rm -f "${TARGET_DIR}/etc/dropbear"
fi
mkdir -p "${TARGET_DIR}/etc/dropbear"
chmod 0700 "${TARGET_DIR}/etc/dropbear"
# /etc/machine-id ships empty: systemd binds a transient id every boot and
# nothing persistent derives from it (DEC-4.9).
: > "${TARGET_DIR}/etc/machine-id"
chmod 0444 "${TARGET_DIR}/etc/machine-id"
# piControl reads its configuration from the compile-time path
# /etc/revpi/config.rsc; the signed site config delivers it (DEC-4.7).
if [ "${SUDERRA_BOARD_PROFILE}" = "revpi-connect4" ]; then
    mkdir -p "${TARGET_DIR}/etc/revpi"
    ln -sfn /var/lib/suderra-site/revpi/config.rsc "${TARGET_DIR}/etc/revpi/config.rsc"
fi
# The provision user's login shell is the forced provisioning command;
# dropbear refuses a shell that /etc/shells does not list (EI-003).
touch "${TARGET_DIR}/etc/shells"
grep -qxF /usr/sbin/suderra-provision "${TARGET_DIR}/etc/shells" ||
    printf '%s\n' /usr/sbin/suderra-provision >> "${TARGET_DIR}/etc/shells"

# 8. Units and helpers.
chmod 0600 "${TARGET_DIR}/root/.profile" 2>/dev/null || true
for helper in \
    suderra-data-unlock \
    suderra-identity \
    suderra-provision-mode \
    suderra-provision \
    suderra-provision-worker \
    suderra-lockdown \
    suderra-lockdown-status \
    suderra-qemu-semantic-collector
do
    chmod 0755 "${TARGET_DIR}/usr/sbin/${helper}"
done
chmod 0755 "${TARGET_DIR}/usr/sbin/suderra-os-install" 2>/dev/null || true
chmod 0644 "${TARGET_DIR}/etc/default/dropbear"

# Only the image's own board drop-in of suderra-agent.service stays
# (contracts unit-directives.json board_dropins).
AGENT_DROPINS="${TARGET_DIR}/etc/systemd/system/suderra-agent.service.d"
for dropin in "${AGENT_DROPINS}"/10-board-*.conf; do
    [ -e "${dropin}" ] || continue
    if [ "$(basename "${dropin}")" != "10-board-${SUDERRA_BOARD_PROFILE}.conf" ]; then
        rm -f "${dropin}"
    fi
done

enable_unit() {
    local unit="$1"
    local target_wants="$2"
    local link=""

    if [ -e "${TARGET_DIR}/etc/systemd/system/${unit}" ]; then
        link="../${unit}"
    elif [ -e "${TARGET_DIR}/usr/lib/systemd/system/${unit}" ]; then
        link="../../../../usr/lib/systemd/system/${unit}"
    else
        echo "ERROR: ${unit} is not in the rootfs; it cannot be enabled"
        exit 1
    fi
    mkdir -p "${TARGET_DIR}/etc/systemd/system/${target_wants}.wants"
    ln -sfn "${link}" "${TARGET_DIR}/etc/systemd/system/${target_wants}.wants/${unit}"
}

# Units Buildroot or an earlier build may have enabled that the lifecycle
# state now owns: dropbear and the provisioning worker run only inside
# suderra-provision-mode.service (DEC-5.1), and firstboot is replaced by it.
rm -f "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/dropbear.service" \
      "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-provision-worker.path" \
      "${TARGET_DIR}/etc/systemd/system/sysinit.target.wants/suderra-firstboot.service"

# Unit presets: Buildroot runs `systemctl preset-all` after this script, and
# the first matching preset line wins, so every unit this image needs is
# enabled before any disable line (a leading `disable *` would disable them
# all).
PRESET="${TARGET_DIR}/etc/systemd/system-preset/00-suderra.preset"
mkdir -p "$(dirname "${PRESET}")"
rm -f "${TARGET_DIR}/etc/systemd/system-preset/00-suderra-appliance.preset"
{
    echo "# Generated by board/suderra/common/post-build.sh (first match wins)."
    echo "enable nftables.service"
    echo "enable systemd-networkd.service"
    echo "enable chrony.service"
} > "${PRESET}"
preset_enable() {
    printf 'enable %s\n' "$1" >> "${PRESET}"
}

enable_unit nftables.service sysinit.target
enable_unit systemd-networkd.service multi-user.target
enable_unit chrony.service multi-user.target

case "${DEFCONFIG_NAME}" in
    *usb_installer*)
        enable_unit suderra-os-install.service multi-user.target
        preset_enable suderra-os-install.service
        ;;
    *)
        # The USB self-installer (suderra-os-install: it writes an OS image
        # onto the internal disk) belongs to the installer image alone. The
        # suderra-os-installer package also installs it, with an [Install]
        # section, into every device image that carries the root installer,
        # and a dev image's presets end without `disable *`, so preset-all
        # enabled it and it ran at every boot (the QEMU edge e2e test found
        # it). Device images do not ship it.
        rm -f "${TARGET_DIR}/usr/sbin/suderra-os-install" \
              "${TARGET_DIR}/usr/lib/systemd/system/suderra-os-install.service" \
              "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-os-install.service"
        enable_unit suderra-data.service sysinit.target
        preset_enable suderra-data.service
        case "${DEFCONFIG_NAME}" in
            suderra_qemu_x86_64*)
                enable_unit suderra-qemu-semantic-collector.service multi-user.target
                preset_enable suderra-qemu-semantic-collector.service
                ;;
        esac
        ;;
esac

if [ -n "${SUDERRA_BOARD_PROFILE}" ]; then
    # Identity, lifecycle, provisioning mode, activation and the agent. Each
    # unit also carries ConditionPathExists=/etc/suderra/board.
    enable_unit suderra-identity.service sysinit.target
    enable_unit suderra-lifecycle.service sysinit.target
    enable_unit suderra-lifecycle.timer timers.target
    enable_unit suderra-lifecycle.path paths.target
    enable_unit suderra-activation.path paths.target
    enable_unit suderra-activation.service multi-user.target
    enable_unit suderra-provision-mode.service multi-user.target
    enable_unit suderra-agent.service multi-user.target
    for unit in suderra-identity.service suderra-lifecycle.service suderra-lifecycle.timer \
        suderra-lifecycle.path suderra-activation.path suderra-activation.service \
        suderra-provision-mode.service suderra-agent.service
    do
        preset_enable "${unit}"
    done
else
    # A boardless image has no agent, no identity and no provisioning
    # surface: remove the units instead of leaving them inert.
    # dropbear keeps its provisioning drop-in: bound to a provisioning mode
    # that does not exist here, it can never start.
    rm -rf "${TARGET_DIR}/etc/systemd/system/suderra-agent.service" \
           "${AGENT_DROPINS}"
    # Without a lifecycle the appliance ruleset is the only ruleset
    # (DEC-11.3): `policy apply` selects it (no lifecycle reads LOCKED) and
    # records its hash for the health check. An image without the root
    # installer loads it directly; it is still checked before it loads,
    # after the base drop ruleset.
    rm -f "${TARGET_DIR}/etc/systemd/system/nftables.service.d/10-appliance-only.conf"
    if ! config_enabled BR2_PACKAGE_SUDERRA_OS_INSTALLER; then
        mkdir -p "${TARGET_DIR}/etc/systemd/system/nftables.service.d"
        cat > "${TARGET_DIR}/etc/systemd/system/nftables.service.d/10-appliance-only.conf" <<'EOF'
# Generated by post-build.sh: this image declares no board_profile and ships
# no root installer, so it has no device lifecycle and loads the appliance
# ruleset directly (ADR-048 DEC-11.3).
[Service]
ExecStart=
ExecStart=/usr/sbin/nft -c -f /etc/nftables.conf
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
ExecReload=
ExecReload=/usr/sbin/nft -c -f /etc/nftables.conf
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
EOF
    fi
    for unit in suderra-identity.service suderra-lifecycle.service suderra-lifecycle.timer \
        suderra-lifecycle.path suderra-lifecycle-request.service suderra-activation.path \
        suderra-activation.service suderra-provision-mode.service \
        suderra-provision-guard.service suderra-provision-worker.path \
        suderra-provision-worker.service
    do
        rm -f "${TARGET_DIR}/etc/systemd/system/${unit}"
    done
fi
if [ -e "${TARGET_DIR}/usr/lib/systemd/system/suderra-rauc-mark-good.service" ]; then
    preset_enable boot.mount
    preset_enable rauc.service
    preset_enable suderra-rauc-mark-good.service
fi

{
    echo "disable dropbear.service"
    echo "disable suderra-provision-worker.path"
    echo "disable suderra-provision-worker.service"
    echo "disable suderra-provision-guard.service"
    echo "disable suderra-firstboot.service"
} >> "${PRESET}"

# 8a. QEMU edge e2e probe (ADR-048 P0 exit test). A root-side observation and
# sandbox-run channel for tests/qemu/edge-*.py over the virtio-serial port
# org.suderra.e2e.0: it exists only on the dev QEMU image and is deleted from
# every other image, including the QEMU prod_ab image and every hardware board
# (tests/image-contracts/edge-e2e-probe-contract-test.sh).
if [ "${DEFCONFIG_NAME}" = suderra_qemu_x86_64 ] && config_enabled BR2_PACKAGE_SUDERRA_VARIANT_DEV; then
    chmod 0755 "${TARGET_DIR}/usr/sbin/suderra-e2e-probe"
else
    rm -f "${TARGET_DIR}/usr/sbin/suderra-e2e-probe" \
          "${TARGET_DIR}/etc/systemd/system/suderra-e2e-probe.service" \
          "${TARGET_DIR}/usr/lib/udev/rules.d/90-suderra-e2e-probe.rules"
fi

# 8b. Production-runtime GUEST senaryo sürücüsü.
# Bu sürücü mutasyon KABUL EDER (payload'dan RAUC bundle / downgrade manifest
# uygular) — saldırı yüzeyi. Yalnız qemu-x86_64-prod-ab runtime-evidence
# imajında enable edilir; DİĞER TÜM imajlardan (saha x86_64 dahil) silinir,
# böylece saha imajı bu affordance'ı hiç içermez.
case "${DEFCONFIG_NAME}" in
    suderra_qemu_x86_64_prod_ab*)
        chmod 0755 "${TARGET_DIR}/usr/sbin/suderra-runtime-scenario"
        enable_unit suderra-runtime-scenario.service multi-user.target
        preset_enable suderra-runtime-scenario.service
        ;;
    *)
        rm -f "${TARGET_DIR}/usr/sbin/suderra-runtime-scenario" \
              "${TARGET_DIR}/etc/systemd/system/suderra-runtime-scenario.service" \
              "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/suderra-runtime-scenario.service"
        ;;
esac

# 9. Appliance lockdown of the production variant.
# Production variant her zaman kilitli imaj üretir: no interactive login (root
# and provision are locked in the image's shadow), no getty, rescue or debug
# shell, and every unit the preset does not enable stays disabled. The provisioning surface is
# not an image variant (DEC-5.1): dropbear and the provisioning units are in
# the image, but they run only inside suderra-provision-mode.service, whose
# condition is the root-owned lifecycle state on /data.
if [ "${SUDERRA_OS_VARIANT}" = "prod" ]; then
    echo "==> Appliance lockdown uygulanıyor"

    if [ -f "${TARGET_DIR}/etc/shadow" ]; then
        sed -i 's#^root:[^:]*:#root:!:#' "${TARGET_DIR}/etc/shadow"
        sed -i 's#^provision:[^:]*:#provision:!:#' "${TARGET_DIR}/etc/shadow"
    fi
    rm -rf "${TARGET_DIR}/root/.ssh" "${TARGET_DIR}/etc/ssh"

    # Login, rescue and debug shells stay masked in the image.
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
        systemd-logind.service
    do
        ln -sfn /dev/null "${TARGET_DIR}/etc/systemd/system/${unit}"
    done
    rm -rf "${TARGET_DIR}/etc/systemd/system/getty.target.wants" \
           "${TARGET_DIR}/etc/systemd/system/rescue.target.wants" \
           "${TARGET_DIR}/etc/systemd/system/emergency.target.wants"
    echo "disable *" >> "${PRESET}"
fi

# 10. Root credential guardrail (C1 regresyon koruması)
# Hiçbir imaj, repo'da paylaşılan/gömülü bir root parolası ile SEVK EDİLMEMELİDİR.
# Root shadow alanı kilitli olmalı (`!`, `*` veya "!..." formu) — yani password
# login imkânsız. Bilinçli dev-debug için SUDERRA_ALLOW_ROOT_PASSWORD=1 escape
# hatch'i gerekir; aksi halde gömülü bir crypt hash (ör. eski "$6$suderra$...")
# build'i fail eder.
if [ -f "${TARGET_DIR}/etc/shadow" ]; then
    root_secret="$(awk -F: '$1=="root"{print $2}' "${TARGET_DIR}/etc/shadow")"
    case "${root_secret}" in
        ""|"*"|"!"|"!!"|"!"*)
            : # kilitli — güvenli
            ;;
        *)
            if [ "${SUDERRA_ALLOW_ROOT_PASSWORD:-0}" = "1" ]; then
                echo "WARNING: root parolası ayarlı (SUDERRA_ALLOW_ROOT_PASSWORD=1 ile izin verildi) — bu imajı DAĞITMAYIN"
            else
                echo "ERROR: root shadow alanı bir parola hash'i taşıyor; sevk edilen imajlarda root login kilitli olmalı."
                echo "       Bir defconfig'te BR2_TARGET_GENERIC_ROOT_PASSWD ayarlı olabilir — kaldırın."
                echo "       Bilinçli dev-debug için SUDERRA_ALLOW_ROOT_PASSWORD=1 verin (dağıtmayın)."
                exit 1
            fi
            ;;
    esac
fi

# 11. Commands of the shipped scripts (EI-078). Every external command a shell
# script of this image runs is declared in runtime-commands.json, and every
# command the image's variant, architecture and packages require resolves in
# this target. Last, after every script was kept, removed or rewritten above,
# so it checks what the image really ships: a script that needs mkfs.ext4 on
# an image without e2fsprogs fails the build instead of the first boot.
[ -n "${BR2_CONFIG:-}" ] || {
    echo "ERROR: BR2_CONFIG is not set; post-build runs from Buildroot, which exports it"
    exit 1
}
python3 -I "${SUDERRA_EXTERNAL_DIR}/scripts/ci/check-target-commands.py" check \
    --target "${TARGET_DIR}" \
    --manifest "${SUDERRA_EXTERNAL_DIR}/board/suderra/common/runtime-commands.json" \
    --variant "${SUDERRA_OS_VARIANT}" \
    --arch "${image_arch}" \
    --config "${BR2_CONFIG}"

echo "==> post-build tamamlandı"
