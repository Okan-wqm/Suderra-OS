################################################################################
#
# suderra-keys
#
# Public key / sertifikaları rootfs'e kurar.
# Anahtarların kendisi git'te YOK — SUDERRA_KEYS_DIR'den okur.
#
# DEV: ~/.suderra-keys/dev/
# CI:  HSM-backed kısa-ömürlü session
#
# Faz 3'te (sertleştirme) tamamlanır.
#
################################################################################

SUDERRA_KEYS_VERSION = 0.1.0
SUDERRA_KEYS_SITE = $(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-keys
SUDERRA_KEYS_SITE_METHOD = local
SUDERRA_KEYS_LICENSE = Apache-2.0

# Anahtar dizini — geliştirici override edebilir
SUDERRA_KEYS_DIR ?= $(HOME)/.suderra-keys/dev

define SUDERRA_KEYS_INSTALL_TARGET_CMDS
	@if [ ! -d "$(SUDERRA_KEYS_DIR)" ]; then \
		echo "ERROR: SUDERRA_KEYS_DIR=$(SUDERRA_KEYS_DIR) yok."; \
		echo "Geliştirme anahtarları için: ./scripts/gen-dev-keys.sh"; \
		exit 1; \
	fi
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/rauc
	$(INSTALL) -m 0644 $(SUDERRA_KEYS_DIR)/rauc-signing.crt \
		$(TARGET_DIR)/etc/rauc/keyring.pem
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/dm-verity
	$(INSTALL) -m 0644 $(SUDERRA_KEYS_DIR)/verity-signing.crt \
		$(TARGET_DIR)/etc/dm-verity/pubkey.pem
endef

$(eval $(generic-package))
