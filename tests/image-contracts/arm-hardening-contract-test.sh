#!/usr/bin/env bash
#
# ARM (Pi 4 / CM4 / RevPi) kernel hardening sözleşmesi.
#
# Bu test iki şeyi korur:
#   1. arm64 hardening fragmenti üç ARM defconfig'ine de bağlı kalır ve
#      x86 ortak fragmentiyle hizalı boot-güvenli seçenekleri içerir.
#   2. Donanım lab kanıtı olmadan uygulanmaması gereken riskli seçenekler
#      (monolitik kernel, zorunlu lockdown) fragmenta SIZMAZ — bu gate
#      docs/security/kernel-hardening.md ve build-matrix blocker'larına bağlı.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FRAGMENT="${ROOT}/board/suderra/aarch64-rpi4/linux-rpi4-hardening.config"
BASE_FRAGMENT_REL='board/suderra/aarch64-rpi4/linux-rpi4.config'
HARDENING_FRAGMENT_REL='board/suderra/aarch64-rpi4/linux-rpi4-hardening.config'

[ -f "${FRAGMENT}" ] || {
    echo "ERROR: arm64 hardening fragment missing: ${FRAGMENT}" >&2
    exit 1
}

for defconfig in \
    suderra_aarch64_rpi4_defconfig \
    suderra_aarch64_revpi4_defconfig \
    suderra_aarch64_rpi4_usb_installer_defconfig
do
    line="$(grep '^BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=' "${ROOT}/configs/${defconfig}")" || {
        echo "ERROR: ${defconfig} has no kernel fragment list" >&2
        exit 1
    }
    case "${line}" in
        *"${BASE_FRAGMENT_REL} "*"${HARDENING_FRAGMENT_REL}"*) ;;
        *)
            echo "ERROR: ${defconfig} must apply ${BASE_FRAGMENT_REL} followed by ${HARDENING_FRAGMENT_REL}" >&2
            exit 1
            ;;
    esac
done

# Boot-güvenli sertleştirme çekirdeği: bu token'lar fragmentten düşerse
# ARM imajları sessizce yumuşar.
for token in \
    'CONFIG_SECURITY_LOCKDOWN_LSM=y' \
    'CONFIG_LSM="lockdown,yama,bpf,landlock"' \
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

# USER_NS'i kapatma kararı, hiçbir systemd unit'in PrivateUsers kullanmadığı
# varsayımına dayanır — varsayımı sözleşmeye bağla.
if grep -rn '^PrivateUsers=' \
    "${ROOT}/board/suderra/common/rootfs-overlay" \
    "${ROOT}/package" 2>/dev/null | grep -v 'PrivateUsers=no'; then
    echo "ERROR: a systemd unit uses PrivateUsers=, but ARM kernels ship without CONFIG_USER_NS" >&2
    exit 1
fi
