################################################################################
#
# suderra-rauc-config
#
################################################################################

SUDERRA_RAUC_CONFIG_VERSION = 0.1.0
SUDERRA_RAUC_CONFIG_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-rauc-config
SUDERRA_RAUC_CONFIG_SITE_METHOD = local
SUDERRA_RAUC_CONFIG_LICENSE = Apache-2.0
SUDERRA_RAUC_CONFIG_DEPENDENCIES = rauc suderra-keys

# Arch-aware bootloader backend: x86 uses GRUB (system.conf + EFI boot.mount);
# ARM uses U-Boot (system.conf.arm + FAT boot.mount.arm + fw_env.config +
# signed-FIT slot hook), per ADR-0007.
ifeq ($(BR2_aarch64),y)
SUDERRA_RAUC_CONFIG_SYSTEM_CONF = system.conf.arm
SUDERRA_RAUC_CONFIG_BOOT_MOUNT = boot.mount.arm
else
SUDERRA_RAUC_CONFIG_SYSTEM_CONF = system.conf
SUDERRA_RAUC_CONFIG_BOOT_MOUNT = boot.mount
endif

define SUDERRA_RAUC_CONFIG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/$(SUDERRA_RAUC_CONFIG_SYSTEM_CONF) \
		$(TARGET_DIR)/etc/rauc/system.conf
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-mark-good \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-mark-good
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-health-gate \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-health-gate
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-boot-state \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-boot-state
	mkdir -p $(TARGET_DIR)/boot
endef

ifeq ($(BR2_aarch64),y)
define SUDERRA_RAUC_CONFIG_INSTALL_ARM_UBOOT
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-arm-slot-hook.sh \
		$(TARGET_DIR)/usr/lib/rauc/suderra-rauc-arm-slot-hook.sh
	$(INSTALL) -D -m 0644 $(@D)/fw_env.config \
		$(TARGET_DIR)/etc/fw_env.config
endef
SUDERRA_RAUC_CONFIG_POST_INSTALL_TARGET_HOOKS += SUDERRA_RAUC_CONFIG_INSTALL_ARM_UBOOT
endif

define SUDERRA_RAUC_CONFIG_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/$(SUDERRA_RAUC_CONFIG_BOOT_MOUNT) \
		$(TARGET_DIR)/usr/lib/systemd/system/boot.mount
	$(INSTALL) -D -m 0644 $(@D)/suderra-rauc-mark-good.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-rauc-mark-good.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/local-fs.target.wants
	ln -fs ../../../../usr/lib/systemd/system/boot.mount \
		$(TARGET_DIR)/etc/systemd/system/local-fs.target.wants/boot.mount
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -fs ../../../../usr/lib/systemd/system/suderra-rauc-mark-good.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/suderra-rauc-mark-good.service
endef

$(eval $(generic-package))
