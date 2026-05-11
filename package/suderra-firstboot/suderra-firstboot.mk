################################################################################
#
# suderra-firstboot
#
# İlk-boot provisioning script ve systemd unit'i.
# Faz 5'te (operasyonel olgunluk) tamamlanır.
#
################################################################################

SUDERRA_FIRSTBOOT_VERSION = 0.1.0
SUDERRA_FIRSTBOOT_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-firstboot
SUDERRA_FIRSTBOOT_SITE_METHOD = local
SUDERRA_FIRSTBOOT_LICENSE = Apache-2.0
SUDERRA_FIRSTBOOT_LICENSE_FILES = LICENSE

define SUDERRA_FIRSTBOOT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/suderra-firstboot.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-firstboot.service
endef

define SUDERRA_FIRSTBOOT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/suderra-firstboot.sh \
		$(TARGET_DIR)/usr/sbin/suderra-firstboot
endef

$(eval $(generic-package))
