################################################################################
#
# suderra-attestation
#
################################################################################

SUDERRA_ATTESTATION_VERSION = 0.1.0
SUDERRA_ATTESTATION_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-attestation
SUDERRA_ATTESTATION_SITE_METHOD = local
SUDERRA_ATTESTATION_LICENSE = Apache-2.0
SUDERRA_ATTESTATION_DEPENDENCIES = host-rustc tpm2-tools

define SUDERRA_ATTESTATION_BUILD_CMDS
	$(call SUDERRA_RUST_WORKSPACE_BUILD,suderra-attestation)
endef

define SUDERRA_ATTESTATION_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 \
		$(@D)/cargo-target/$(RUSTC_TARGET_NAME)/release/suderra-attestation \
		$(TARGET_DIR)/usr/bin/suderra-attestation
endef

$(eval $(generic-package))
