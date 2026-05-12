################################################################################
#
# suderra-os-installer
#
################################################################################

SUDERRA_OS_INSTALLER_VERSION = 0.1.0
SUDERRA_OS_INSTALLER_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-os-installer
SUDERRA_OS_INSTALLER_SITE_METHOD = local
SUDERRA_OS_INSTALLER_LICENSE = Apache-2.0

# Optional pinned public key for installer payload manifest verification.
# Production builds must provide this through CI/HSM-backed key material.
SUDERRA_INSTALLER_PAYLOAD_PUBKEY ?=

define SUDERRA_OS_INSTALLER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/suderra-os-install \
		$(TARGET_DIR)/usr/sbin/suderra-os-install
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/suderra
	if [ -n "$(SUDERRA_INSTALLER_PAYLOAD_PUBKEY)" ]; then \
		$(INSTALL) -D -m 0644 "$(SUDERRA_INSTALLER_PAYLOAD_PUBKEY)" \
			$(TARGET_DIR)/etc/suderra/os-installer-payload.pub.pem; \
	fi
endef

define SUDERRA_OS_INSTALLER_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/suderra-os-install.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-os-install.service
endef

$(eval $(generic-package))
