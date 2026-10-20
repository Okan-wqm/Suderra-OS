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

# No unit of its own: `suderra-ota mark-good` runs only from
# suderra-rauc-mark-good after the health gate passed, the single mark-good
# path (ADR-048 DEC-6.8).

$(eval $(generic-package))
