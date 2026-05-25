################################################################################
#
# suderra-ota
#
################################################################################

SUDERRA_OTA_VERSION = 0.1.0
SUDERRA_OTA_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-ota
SUDERRA_OTA_SITE_METHOD = local
SUDERRA_OTA_LICENSE = Apache-2.0
SUDERRA_OTA_DEPENDENCIES = host-rustc rauc suderra-rauc-config

define SUDERRA_OTA_BUILD_CMDS
	$(call SUDERRA_RUST_WORKSPACE_BUILD,suderra-ota)
endef

define SUDERRA_OTA_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 \
		$(@D)/cargo-target/$(RUSTC_TARGET_NAME)/release/suderra-ota \
		$(TARGET_DIR)/usr/bin/suderra-ota
endef

define SUDERRA_OTA_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/suderra-ota-mark-good.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-ota-mark-good.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -fs ../../../../usr/lib/systemd/system/suderra-ota-mark-good.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/suderra-ota-mark-good.service
endef

$(eval $(generic-package))
