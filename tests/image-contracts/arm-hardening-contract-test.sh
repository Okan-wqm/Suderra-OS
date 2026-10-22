#!/usr/bin/env bash
#
# ARM (Pi 4 / CM4 / RevPi) kernel hardening sözleşmesi.
#
# Bu test üç şeyi korur:
#   1. arm64 hardening fragmenti her ARM defconfig'ine, kartın kendi taban
#      fragmentinden SONRA bağlı kalır ve x86 ortak fragmentiyle hizalı
#      boot-güvenli seçenekleri içerir.
#   2. Donanım lab kanıtı olmadan uygulanmaması gereken riskli seçenekler
#      (monolitik kernel, zorunlu lockdown) PAYLAŞILAN fragmenta SIZMAZ — bu gate
#      docs/security/kernel-hardening.md ve build-matrix blocker'larına bağlı.
#   3. Zorunlu modül imzası ve zorunlu lockdown yalnızca bir kartın PROD-ONLY
#      fragmentinde yaşar (ADR-0007 M3, EI-048): RevPi Connect 4'te
#      linux-revpi-suderra-prod.config, yalnız prod defconfig'inin listesinde;
#      dev defconfig'i ve paylaşılan fragment onu taşımaz.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FRAGMENT="${ROOT}/board/suderra/aarch64-rpi4/linux-rpi4-hardening.config"
RPI_BASE_REL='board/suderra/aarch64-rpi4/linux-rpi4.config'
REVPI_BASE_REL='board/suderra/aarch64-revpi-connect4/linux-revpi-suderra.config'
REVPI_PROD_REL='board/suderra/aarch64-revpi-connect4/linux-revpi-suderra-prod.config'
HARDENING_FRAGMENT_REL='board/suderra/aarch64-rpi4/linux-rpi4-hardening.config'

[ -f "${FRAGMENT}" ] || {
    echo "ERROR: arm64 hardening fragment missing: ${FRAGMENT}" >&2
    exit 1
}

fragment_list() {
    local defconfig="$1" line
    line="$(grep '^BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=' "${ROOT}/configs/${defconfig}")" || {
        echo "ERROR: ${defconfig} has no kernel fragment list" >&2
        exit 1
    }
    printf '%s' "${line}"
}

for pair in \
    'suderra_aarch64_rpi4_defconfig:'"${RPI_BASE_REL}" \
    'suderra_aarch64_revpi4_defconfig:'"${REVPI_BASE_REL}" \
    'suderra_aarch64_rpi4_usb_installer_defconfig:'"${RPI_BASE_REL}"
do
    defconfig="${pair%%:*}"
    base="${pair#*:}"
    case "$(fragment_list "${defconfig}")" in
        *"${base}"*"${HARDENING_FRAGMENT_REL}"*) ;;
        *)
            echo "ERROR: ${defconfig} must apply ${base} followed by ${HARDENING_FRAGMENT_REL}" >&2
            exit 1
            ;;
    esac
done

# RevPi prod: board fragment, shared hardening, then the prod-only fragment last
# (the last fragment wins); the dev defconfig never lists it.
case "$(fragment_list suderra_aarch64_revpi4_prod_ab_defconfig)" in
    *"${REVPI_BASE_REL}"*"${HARDENING_FRAGMENT_REL}"*"${REVPI_PROD_REL}"*) ;;
    *)
        echo "ERROR: suderra_aarch64_revpi4_prod_ab_defconfig must apply ${REVPI_BASE_REL}, ${HARDENING_FRAGMENT_REL}, then ${REVPI_PROD_REL}" >&2
        exit 1
        ;;
esac
for defconfig in suderra_aarch64_revpi4_defconfig suderra_aarch64_rpi4_defconfig \
    suderra_aarch64_rpi4_prod_ab_defconfig suderra_aarch64_rpi4_usb_installer_defconfig
do
    case "$(fragment_list "${defconfig}")" in
        *revpi-suderra-prod*)
            echo "ERROR: ${defconfig} must not apply the production-only RevPi fragment" >&2
            exit 1
            ;;
    esac
done

# Boot-güvenli sertleştirme çekirdeği: bu token'lar fragmentten düşerse
# ARM imajları sessizce yumuşar.
for token in \
    'CONFIG_SECURITY_LOCKDOWN_LSM=y' \
    'CONFIG_LSM="lockdown,yama,bpf,landlock"' \
    'CONFIG_SECURITY_LANDLOCK=y' \
    'CONFIG_VMAP_STACK=y' \
    'CONFIG_PAGE_POISONING=y' \
    'CONFIG_SLAB_FREELIST_HARDENED=y' \
    'CONFIG_SLAB_FREELIST_RANDOM=y' \
    'CONFIG_ARM64_SW_TTBR0_PAN=y' \
    'CONFIG_RODATA_FULL_DEFAULT_ENABLED=y' \
    'CONFIG_BPF_UNPRIV_DEFAULT_OFF=y' \
    'CONFIG_BPF_JIT_ALWAYS_ON=y' \
    'CONFIG_DM_INIT=y' \
    'CONFIG_DM_VERITY_FEC=y' \
    '# CONFIG_KEXEC is not set' \
    '# CONFIG_KEXEC_FILE is not set' \
    '# CONFIG_HIBERNATION is not set' \
    '# CONFIG_USER_NS is not set'
do
    grep -qF "${token}" "${FRAGMENT}" || {
        echo "ERROR: arm64 hardening fragment missing token: ${token}" >&2
        exit 1
    }
done

# Donanım kanıtı gate'i: bu seçenekler ancak Pi/RevPi lab boot kanıtıyla
# birlikte, ayrı ve bilinçli bir değişiklikte gelebilir.
if grep -qE '^# CONFIG_MODULES is not set' "${FRAGMENT}"; then
    echo "ERROR: disabling CONFIG_MODULES on ARM requires hardware boot evidence (see kernel-hardening.md)" >&2
    exit 1
fi
if grep -qE '^CONFIG_LOCK_DOWN_KERNEL_FORCE_(CONFIDENTIALITY|INTEGRITY)=y' "${FRAGMENT}"; then
    echo "ERROR: forced kernel lockdown on ARM requires signed-FIT boot chain first" >&2
    exit 1
fi

# Prod-only fragment: zorunlu modül imzası + zorunlu lockdown burada, başka yerde değil.
PROD_FRAGMENT="${ROOT}/${REVPI_PROD_REL}"
for token in \
    'CONFIG_MODULES=y' \
    'CONFIG_MODULE_SIG=y' \
    'CONFIG_MODULE_SIG_FORCE=y' \
    'CONFIG_MODULE_SIG_ALL=y' \
    'CONFIG_MODULE_SIG_SHA512=y' \
    'CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y'
do
    grep -qxF "${token}" "${PROD_FRAGMENT}" || {
        echo "ERROR: RevPi prod fragment missing token: ${token}" >&2
        exit 1
    }
done
if grep -qE '^CONFIG_MODULE_SIG_FORCE=y' "${ROOT}/${REVPI_BASE_REL}"; then
    echo "ERROR: forced module signatures belong to the prod-only fragment, not the board fragment dev shares" >&2
    exit 1
fi
if grep -qE '^# CONFIG_MODULES is not set' "${ROOT}/${REVPI_BASE_REL}" "${PROD_FRAGMENT}"; then
    echo "ERROR: package/revpi-picontrol is a module: CONFIG_MODULES stays on" >&2
    exit 1
fi

# USER_NS'i kapatma kararı, hiçbir systemd unit'in PrivateUsers kullanmadığı
# varsayımına dayanır — varsayımı sözleşmeye bağla.
if grep -rn '^PrivateUsers=' \
    "${ROOT}/board/suderra/common/rootfs-overlay" \
    "${ROOT}/package" 2>/dev/null | grep -v 'PrivateUsers=no'; then
    echo "ERROR: a systemd unit uses PrivateUsers=, but ARM kernels ship without CONFIG_USER_NS" >&2
    exit 1
fi
