#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
POST_IMAGE="${ROOT}/board/suderra/common/post-image.sh"
X86_DEFCONFIG="${ROOT}/configs/suderra_x86_64_defconfig"
X86_GENIMAGE="${ROOT}/board/suderra/x86_64/genimage.cfg"
X86_GRUB="${ROOT}/board/suderra/x86_64/grub.cfg"
KERNEL_FRAGMENT="${ROOT}/board/suderra/common/kernel-fragment.config"
FIRSTBOOT_UNIT="${ROOT}/package/suderra-firstboot/suderra-firstboot.service"
DATA_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-data.service"
NFTABLES_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/nftables.service"
RAUC_MARK_GOOD_UNIT="${ROOT}/package/suderra-rauc-config/suderra-rauc-mark-good.service"
RAUC_MOUNT_UNIT="${ROOT}/package/suderra-rauc-config/boot.mount"
RAUC_MARK_GOOD="${ROOT}/package/suderra-rauc-config/suderra-rauc-mark-good"
RAUC_BOOT_STATE="${ROOT}/package/suderra-rauc-config/suderra-rauc-boot-state"
INSTALLER="${ROOT}/userspace/suderra-installer/src/cmd/install.rs"
OTA_MAIN="${ROOT}/userspace/suderra-ota/src/main.rs"
OTA_PACKAGE_MK="${ROOT}/package/suderra-ota/suderra-ota.mk"
PROVISION_WORKER_UNIT="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-provision-worker.service"
PROVISION_WORKER="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision-worker"
INSTALLER_EDGE="${ROOT}/userspace/suderra-installer/src/cmd/edge.rs"
INSTALLER_PATHS="${ROOT}/userspace/suderra-installer/src/paths.rs"
INSTALLER_VERIFY="${ROOT}/userspace/suderra-installer/src/contracts/verify.rs"
INSTALLER_FSUTIL="${ROOT}/userspace/suderra-installer/src/fsutil.rs"
MANIFEST="${ROOT}/userspace/suderra-installer/src/manifest.rs"
PRODUCTION_ARTIFACTS="${ROOT}/scripts/production-artifacts.sh"
CREATE_RAUC_BUNDLE="${ROOT}/scripts/create-rauc-bundle.sh"
RAUC_X86_HOOK="${ROOT}/scripts/rauc-x86-slot-hook.sh"
RAUC_CONFIG="${ROOT}/package/suderra-rauc-config/system.conf"
RAUC_PACKAGE_MK="${ROOT}/package/suderra-rauc-config/suderra-rauc-config.mk"
PLAN_DOC="${ROOT}/docs/assessments/2026-05-20-enterprise-grade-gap-closure-plan.md"

grep -q 'ExecStart=/usr/bin/suderra-firstboot' "${FIRSTBOOT_UNIT}" || {
    echo "ERROR: packaged firstboot unit must execute the installed /usr/bin binary" >&2
    exit 1
}
if grep -Eq '^Before=.*sysinit\.target' "${DATA_UNIT}"; then
    echo "ERROR: the data unit must not force itself before sysinit.target" >&2
    exit 1
fi
# ADR-048 DEC-5: suderra-provision-mode.service replaces the overlay firstboot
# unit, which wrote /etc at run time.
if [ -e "${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service" ]; then
    echo "ERROR: the overlay must not ship suderra-firstboot.service (ADR-048 DEC-5)" >&2
    exit 1
fi
grep -q '/usr/sbin/suderra-data-unlock' "${DATA_UNIT}" || {
    echo "ERROR: /data service must delegate production LUKS/TPM unlock to suderra-data-unlock" >&2
    exit 1
}
grep -q 'cryptsetup isLuks' "${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock" &&
    grep -q 'cryptsetup open --token-only' "${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock" || {
    echo "ERROR: production /data path must require LUKS2 and TPM2-backed unlock" >&2
    exit 1
}
grep -q '^After=.*suderra-data.service' "${NFTABLES_UNIT}" || {
    echo "ERROR: nftables must load after suderra-data so lockdown state is visible" >&2
    exit 1
}

grep -q 'SUDERRA_OS_VARIANT.*prod' "${POST_BUILD}" || {
    echo "ERROR: post-build must branch on the production variant" >&2
    exit 1
}
grep -q 'Production variant her zaman kilitli imaj' "${POST_BUILD}" || {
    echo "ERROR: production post-build lockdown must be explicit" >&2
    exit 1
}
grep -q 'disable dropbear.service' "${POST_BUILD}" || {
    echo "ERROR: post-build must keep dropbear disabled outside the provisioning window" >&2
    exit 1
}
if ! grep -q 'enable_unit suderra-agent.service' "${POST_BUILD}" ||
   ! grep -q 'is not in the rootfs; it cannot be enabled' "${POST_BUILD}"; then
    echo "ERROR: post-build must not enable a missing suderra-agent.service" >&2
    exit 1
fi
if grep -q 'ln -sfn ../suderra-agent.service' "${POST_BUILD}"; then
    echo "ERROR: post-build must not create dangling suderra-agent.service wants symlinks" >&2
    exit 1
fi

grep -q 'production Dropbear runs only inside the provisioning window' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must reject Dropbear outside the provisioning window" >&2
    exit 1
}
grep -q 'production defconfig must not enable BR2_TARGET_GENERIC_GETTY' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must reject getty" >&2
    exit 1
}
grep -q 'production defconfig must enable RAUC A/B update support' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must require RAUC before production can pass" >&2
    exit 1
}
grep -q 'production defconfig must install Suderra RAUC slot configuration' "${POST_IMAGE}" || {
    echo "ERROR: production post-image gate must require Suderra RAUC slot config" >&2
    exit 1
}
grep -q 'suderra_qemu_x86_64_prod_ab' "${POST_IMAGE}" || {
    echo "ERROR: qemu-x86_64-prod-ab must receive the same production artifact gate as x86_64" >&2
    exit 1
}
grep -q 'x86 production boot/verity artifact' "${POST_IMAGE}" || {
    echo "ERROR: post-image must generate x86 production boot/verity artifacts before genimage" >&2
    exit 1
}
grep -q 'sbverify --cert' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify Secure Boot signatures on boot artifacts" >&2
    exit 1
}
grep -q 'verify_signed_pe_artifact "suderra-A.efi"' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify the signed slot UKI sidecar and Secure Boot signatures" >&2
    exit 1
}
grep -q 'verify_signed_pe_artifact "suderra-B.efi"' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify the inactive signed slot UKI sidecar and Secure Boot signatures" >&2
    exit 1
}
grep -q 'verify_signed_pe_artifact "grubx64.efi"' "${POST_IMAGE}" || {
    echo "ERROR: post-image must verify the signed GRUB sidecar and Secure Boot signatures" >&2
    exit 1
}
grep -q 'SUDERRA_RELEASE_VERSION is required for production RAUC bundle generation' "${POST_IMAGE}" || {
    echo "ERROR: production post-image must require a versioned RAUC bundle" >&2
    exit 1
}
grep -q 'create-rauc-bundle.sh' "${POST_IMAGE}" || {
    echo "ERROR: production post-image must generate a signed RAUC bundle" >&2
    exit 1
}

# Dropbear is in every production image (ADR-048 DEC-5.1) but runs only
# inside the provisioning window; getty and root login stay out.
if grep -Eq '^BR2_TARGET_GENERIC_GETTY=y|^BR2_TARGET_ENABLE_ROOT_LOGIN=y' "${X86_DEFCONFIG}"; then
    echo "ERROR: x86 production defconfig must not boot with getty/root-login debug surfaces" >&2
    exit 1
fi
for token in \
    'BR2_PACKAGE_RAUC=y' \
    'BR2_PACKAGE_RAUC_DBUS=y' \
    'BR2_PACKAGE_RAUC_GPT=y' \
    'BR2_PACKAGE_RAUC_JSON=y' \
    'BR2_PACKAGE_HOST_RAUC=y' \
    'BR2_PACKAGE_SUDERRA_RAUC_CONFIG=y' \
    'BR2_PACKAGE_SUDERRA_OTA=y' \
    'BR2_PACKAGE_CRYPTSETUP=y' \
    'BR2_PACKAGE_TPM2_TSS=y' \
    'BR2_PACKAGE_TPM2_TOOLS=y' \
    'BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=' \
    'BR2_TARGET_GRUB2_INSTALL_TOOLS=y' \
    'loadenv' \
    'chain'
do
    grep -q "${token}" "${X86_DEFCONFIG}" || {
        echo "ERROR: x86 production defconfig missing token: ${token}" >&2
        exit 1
    }
done

grep -q 'CONFIG_DM_INIT=y' "${KERNEL_FRAGMENT}" || {
    echo "ERROR: kernel hardening fragment must keep dm-init built in for verity boot coverage" >&2
    exit 1
}
grep -q 'partition rootfs-a-verity' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must include a rootfs-a verity partition" >&2
    exit 1
}
grep -q 'partition rootfs-b-verity' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must reserve a rootfs-b verity partition" >&2
    exit 1
}
grep -q 'partition data' "${X86_GENIMAGE}" &&
    ! grep -q 'image = "data.ext4"' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 production genimage must reserve blank /data for LUKS2 provisioning, not ship plain ext4" >&2
    exit 1
}
grep -q 'file EFI' "${X86_GENIMAGE}" || {
    echo "ERROR: x86 genimage must include the generated EFI directory as a tree" >&2
    exit 1
}
if awk '/partition rootfs-b[[:space:]]*{/,/}/ {print}' "${X86_GENIMAGE}" | grep -q 'image = "rootfs.ext4"'; then
    echo "ERROR: x86 rootfs-b must start blank for RAUC ownership" >&2
    exit 1
fi

for token in \
    'load_env --file=${suderra_grubenv} ORDER A_OK A_TRY B_OK B_TRY' \
    'save_env --file=${suderra_grubenv} A_TRY A_OK B_TRY B_OK ORDER' \
    'chainloader (${esp})${selected_loader}' \
    '/EFI/SUDERRA/suderra-A.efi' \
    '/EFI/SUDERRA/suderra-B.efi'
do
    grep -q "${token}" "${X86_GRUB}" || {
        echo "ERROR: x86 GRUB bootchooser missing token: ${token}" >&2
        exit 1
    }
done

for token in \
    'bootloader=grub' \
    'grubenv=/boot/EFI/BOOT/grubenv' \
    'bundle-formats=verity' \
    'statusfile=/data/rauc/status.ini' \
    'device=/run/suderra-os/disk/rootfs-a$' \
    'device=/run/suderra-os/disk/rootfs-a-verity$' \
    'parent=rootfs.0' \
    'device=/run/suderra-os/disk/rootfs-b$' \
    'device=/run/suderra-os/disk/rootfs-b-verity$' \
    'parent=rootfs.1'
do
    grep -q "${token}" "${RAUC_CONFIG}" || {
        echo "ERROR: RAUC system.conf missing token: ${token}" >&2
        exit 1
    }
done

for token in \
    'veritysetup format' \
    'veritysetup verify' \
    'build_x86_verity_initramfs' \
    'suderra.verity.root_partuuid' \
    '.initrd=' \
    'objcopy' \
    'sbsign' \
    'sbverify' \
    'SUDERRA_UKI_STUB' \
    'SUDERRA_GRUB_EFI_INPUT' \
    'suderra-${slot}.efi' \
    'grubx64.efi' \
    'grub-editenv' \
    'SUDERRA_SECUREBOOT_SIGNING_KEY' \
    'reject_prod_file_key'
do
    grep -q "${token}" "${PRODUCTION_ARTIFACTS}" || {
        echo "ERROR: production artifact generator missing token: ${token}" >&2
        exit 1
    }
done
if grep -q 'efi-part/EFI/BOOT/BOOTX64.EFI' "${PRODUCTION_ARTIFACTS}" &&
        ! grep -q 'efi-part/EFI/SUDERRA/suderra-${slot}.efi' "${PRODUCTION_ARTIFACTS}"; then
    echo "ERROR: production artifacts must not replace signed GRUB with a direct-boot UKI" >&2
    exit 1
fi
grep -q 'build_signed_slot_uki "$2" "$3" B' "${PRODUCTION_ARTIFACTS}" || {
    echo "ERROR: production artifacts must generate the inactive slot UKI for RAUC updates" >&2
    exit 1
}

for token in \
    'SUDERRA_RAUC_SIGNING_KEY' \
    'SUDERRA_RAUC_SIGNING_CERT' \
    'SUDERRA_RAUC_PKCS11_URI' \
    'reject_prod_file_key' \
    'manifest.raucm' \
    '[image.rootfs-verity]' \
    'hooks=post-install' \
    'rauc-x86-slot-hook.sh' \
    'rauc_tool'
do
    grep -Fq "${token}" "${CREATE_RAUC_BUNDLE}" || {
        echo "ERROR: RAUC bundle generator missing token: ${token}" >&2
        exit 1
    }
done
for token in \
    'RAUC_BUNDLE_MOUNT_POINT' \
    'RAUC_SLOT_BOOTNAME' \
    '/boot/EFI/SUDERRA/suderra-${bootname}.efi' \
    'slot-post-install'
do
    grep -Fq "${token}" "${RAUC_X86_HOOK}" || {
        echo "ERROR: RAUC x86 slot hook missing token: ${token}" >&2
        exit 1
    }
done

for token in \
    'What=/run/suderra-os/disk/efi$' \
    'Where=/boot' \
    'Before=rauc.service suderra-rauc-mark-good.service'
do
    grep -q "${token}" "${RAUC_MOUNT_UNIT}" || {
        echo "ERROR: RAUC boot mount unit missing token: ${token}" >&2
        exit 1
    }
done
grep -q 'ConditionKernelCommandLine=|rauc.slot=A' "${RAUC_MARK_GOOD_UNIT}" || {
    echo "ERROR: RAUC mark-good unit must be tied to a booted RAUC slot" >&2
    exit 1
}
grep -q 'RequiresMountsFor=/data /boot' "${RAUC_MARK_GOOD_UNIT}" || {
    echo "ERROR: RAUC mark-good unit must require mounted /data and /boot" >&2
    exit 1
}
grep -q 'ReadWritePaths=/data /boot' "${RAUC_MARK_GOOD_UNIT}" || {
    echo "ERROR: RAUC mark-good unit must be allowed to update the shared GRUB environment" >&2
    exit 1
}
if grep -Eq '^(Wants|Requires)=.*suderra-agent\.service' "${RAUC_MARK_GOOD_UNIT}"; then
    echo "ERROR: RAUC mark-good unit must let the health gate decide whether an agent is installed" >&2
    exit 1
fi
grep -q 'suderra-rauc-health-gate' "${RAUC_MARK_GOOD}" || {
    echo "ERROR: RAUC mark-good must be gated by runtime health checks" >&2
    exit 1
}
grep -q 'suderra-rauc-boot-state' "${RAUC_MARK_GOOD}" || {
    echo "ERROR: RAUC mark-good path must emit rollback/boot evidence" >&2
    exit 1
}
# DEC-6.8: a failed gate rolls back only a pending OTA's trial boot; that
# decision belongs to `suderra-ota gate-failed`, never to the script.
grep -q 'suderra-ota gate-failed --reason' "${RAUC_MARK_GOOD}" || {
    echo "ERROR: a failed health gate must go to suderra-ota gate-failed" >&2
    exit 1
}
if grep -Eq 'mark-bad|suderra-ota rollback|/sbin/reboot' "${RAUC_MARK_GOOD}"; then
    echo "ERROR: suderra-rauc-mark-good must not mark a slot bad or reboot by itself" >&2
    exit 1
fi
for dep in BR2_PACKAGE_SUDERRA_OTA BR2_PACKAGE_SUDERRA_OS_INSTALLER; do
    grep -q "^	depends on ${dep}\$" "${ROOT}/package/suderra-rauc-config/Config.in" || {
        echo "ERROR: suderra-rauc-config must depend on ${dep} (the gate's decision and predicate)" >&2
        exit 1
    }
done
grep -q 'suderra-rauc-health-gate' "${RAUC_PACKAGE_MK}" || {
    echo "ERROR: RAUC package must install the health gate" >&2
    exit 1
}
grep -q 'suderra.rauc-boot-state.v1' "${RAUC_BOOT_STATE}" || {
    echo "ERROR: RAUC boot-state collector must emit typed JSON evidence" >&2
    exit 1
}
grep -q 'boot.mount' "${RAUC_PACKAGE_MK}" || {
    echo "ERROR: RAUC package must install and enable the EFI /boot mount" >&2
    exit 1
}

grep -q 'RAUC-backed install engine is not implemented yet' "${INSTALLER}" || {
    echo "ERROR: installer must fail closed instead of reporting a copy as a successful install" >&2
    exit 1
}
grep -q 'SUDERRA_ALLOW_LEGACY_COPY_INSTALL' "${INSTALLER}" || {
    echo "ERROR: any legacy copy install path must be explicit and lab-only" >&2
    exit 1
}
grep -q 'corrupt state ile kurulum fail-closed' "${INSTALLER}" || {
    echo "ERROR: installer must fail closed on corrupt installed state" >&2
    exit 1
}
grep -q 'std::fs::rename' "${MANIFEST}" || {
    echo "ERROR: installed state writes must use atomic rename" >&2
    exit 1
}
# Edge installs run in the Rust root installer (ADR-048 DEC-1.10); its work
# state is root-only, never the agent-writable /var/lib/suderra.
if ! grep -q 'RuntimeDirectory=suderra-installer' "${PROVISION_WORKER_UNIT}" ||
   ! grep -q '/data/suderra/os/installer' "${INSTALLER_PATHS}"; then
    echo "ERROR: edge install work state must be root-owned runtime state, not agent-writable /var/lib/suderra" >&2
    exit 1
fi
grep -q '/usr/bin/suderra-installer" edge provision\|INSTALLER}" edge provision' "${PROVISION_WORKER}" || {
    echo "ERROR: the provisioning worker must delegate the install to suderra-installer edge provision" >&2
    exit 1
}

for token in \
    'suderra.os-update-manifest.v1' \
    'verify_manifest_signature' \
    'min_current_version' \
    'rollback_floor' \
    'run_rauc(&["install"' \
    'run_rauc(&["status", "mark-bad"])' \
    'run_rauc(&["status", "mark-good"])' \
    'persist_rollback_floor'
do
    grep -Fq "${token}" "${OTA_MAIN}" || {
        echo "ERROR: suderra-ota missing production OTA token: ${token}" >&2
        exit 1
    }
done
grep -q 'SUDERRA_RUST_WORKSPACE_BUILD,suderra-ota' "${OTA_PACKAGE_MK}" || {
    echo "ERROR: suderra-ota package must use the shared Rust workspace build contract" >&2
    exit 1
}
grep -q 'https_only(true)' "${INSTALLER_EDGE}" || {
    echo "ERROR: edge install downloads must be HTTPS-only" >&2
    exit 1
}
grep -q 'SiteConfigDigestMismatch' "${INSTALLER_VERIFY}" || {
    echo "ERROR: the signed provisioning manifest must bind its site config" >&2
    exit 1
}
grep -q 'RollbackBelowFloor' "${INSTALLER_VERIFY}" || {
    echo "ERROR: edge install must reject releases below the rollback floor" >&2
    exit 1
}
if ! grep -q 'fn symlink_atomic' "${INSTALLER_FSUTIL}" ||
   ! grep -q 'fn complete_interrupted_switch' "${INSTALLER_EDGE}"; then
    echo "ERROR: edge installs must switch current atomically and recover an interrupted switch" >&2
    exit 1
fi

test -s "${PLAN_DOC}" || {
    echo "ERROR: enterprise gap closure plan documentation must exist" >&2
    exit 1
}
for token in \
    "production_ready=false" \
    "x86_64-first" \
    "factory/provisioning" \
    "signed UKI" \
    "dm-verity" \
    "RAUC" \
    "signed release ingress" \
    "hardware/lab evidence"
do
    grep -q "${token}" "${PLAN_DOC}" || {
        echo "ERROR: enterprise plan doc missing token: ${token}" >&2
        exit 1
    }
done
