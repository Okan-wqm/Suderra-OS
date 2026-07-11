################################################################################
#
# suderra-watchdog
#
################################################################################

SUDERRA_WATCHDOG_VERSION = 0.1.0
SUDERRA_WATCHDOG_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-watchdog
SUDERRA_WATCHDOG_SITE_METHOD = local
SUDERRA_WATCHDOG_LICENSE = Apache-2.0
SUDERRA_WATCHDOG_DEPENDENCIES = host-rustc

define SUDERRA_WATCHDOG_BUILD_CMDS
	$(call SUDERRA_RUST_WORKSPACE_BUILD,suderra-watchdog)
endef

define SUDERRA_WATCHDOG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 \
		$(@D)/cargo-target/$(RUSTC_TARGET_NAME)/release/suderra-watchdog \
		$(TARGET_DIR)/usr/bin/suderra-watchdog
endef

define SUDERRA_WATCHDOG_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/suderra-watchdog.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-watchdog.service
	mkdir -p $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants
	ln -sf ../suderra-watchdog.service \
		$(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/suderra-watchdog.service
endef

$(eval $(generic-package))
