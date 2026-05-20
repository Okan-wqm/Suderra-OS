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

define SUDERRA_RAUC_CONFIG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(@D)/system.conf \
		$(TARGET_DIR)/etc/rauc/system.conf
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-mark-good \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-mark-good
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-health-gate \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-health-gate
	$(INSTALL) -D -m 0755 $(@D)/suderra-rauc-boot-state \
		$(TARGET_DIR)/usr/sbin/suderra-rauc-boot-state
	mkdir -p $(TARGET_DIR)/boot
endef

define SUDERRA_RAUC_CONFIG_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/boot.mount \
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
