################################################################################
#
# suderra-firstboot
#
# İlk-boot provisioning binary (Rust, musl static).
# Kaynak: userspace/suderra-firstboot/ (Cargo workspace member)
# Faz 2'de tam doldurulur, şu an placeholder binary.
#
################################################################################

SUDERRA_FIRSTBOOT_VERSION = 0.1.0
SUDERRA_FIRSTBOOT_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/userspace
SUDERRA_FIRSTBOOT_SITE_METHOD = local
SUDERRA_FIRSTBOOT_SUBDIR = suderra-firstboot
SUDERRA_FIRSTBOOT_LICENSE = Apache-2.0
SUDERRA_FIRSTBOOT_LICENSE_FILES = ../../LICENSE

# Rust workspace içinde build
SUDERRA_FIRSTBOOT_DEPENDENCIES = host-rustc

define SUDERRA_FIRSTBOOT_BUILD_CMDS
	$(call SUDERRA_RUST_WORKSPACE_BUILD,suderra-firstboot)
endef

define SUDERRA_FIRSTBOOT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 \
		$(@D)/cargo-target/$(RUSTC_TARGET_NAME)/release/suderra-firstboot \
		$(TARGET_DIR)/usr/bin/suderra-firstboot
endef

define SUDERRA_FIRSTBOOT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 \
		$(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-firstboot/suderra-firstboot.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-firstboot.service
endef

$(eval $(generic-package))
