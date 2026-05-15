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
SUDERRA_KEYS_PROFILE_FILE ?= suderra-keys.profile

define SUDERRA_KEYS_INSTALL_TARGET_CMDS
	@if [ ! -d "$(SUDERRA_KEYS_DIR)" ]; then \
		echo "ERROR: SUDERRA_KEYS_DIR=$(SUDERRA_KEYS_DIR) yok."; \
		echo "Geliştirme anahtarları için: ./scripts/gen-dev-keys.sh"; \
		exit 1; \
	fi
	@for required in \
		rauc-signing.crt \
		verity-signing.crt \
		installer-payload.ed25519.pub \
		edge-artifact.ed25519.pub; do \
		if [ ! -s "$(SUDERRA_KEYS_DIR)/$$required" ]; then \
			echo "ERROR: required Suderra trust root missing: $(SUDERRA_KEYS_DIR)/$$required"; \
			exit 1; \
		fi; \
	done
	@profile="$$(cat "$(SUDERRA_KEYS_DIR)/$(SUDERRA_KEYS_PROFILE_FILE)" 2>/dev/null || true)"; \
	if [ "$(BR2_PACKAGE_SUDERRA_VARIANT_PROD)" = "y" ]; then \
		if [ "$$profile" != "prod" ]; then \
			echo "ERROR: production builds require $(SUDERRA_KEYS_PROFILE_FILE) containing 'prod'."; \
			echo "Refusing to let development keys masquerade as production trust roots."; \
			exit 1; \
		fi; \
		case "$(SUDERRA_KEYS_DIR)" in \
			*/dev|*/dev/) \
				echo "ERROR: production builds may not use a dev key directory: $(SUDERRA_KEYS_DIR)"; \
				exit 1; \
				;; \
		esac; \
		if command -v openssl >/dev/null 2>&1; then \
			for cert in rauc-signing.crt verity-signing.crt; do \
				subject="$$(openssl x509 -in "$(SUDERRA_KEYS_DIR)/$$cert" -noout -subject 2>/dev/null || true)"; \
				case "$$subject" in \
					*Dev*|*dev*) \
						echo "ERROR: production trust root $$cert has development subject: $$subject"; \
						exit 1; \
						;; \
				esac; \
			done; \
		fi; \
	elif [ "$$profile" = "prod" ]; then \
		echo "ERROR: production trust roots require the production variant."; \
		exit 1; \
	fi
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/rauc
	$(INSTALL) -m 0644 $(SUDERRA_KEYS_DIR)/rauc-signing.crt \
		$(TARGET_DIR)/etc/rauc/keyring.pem
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/dm-verity
	$(INSTALL) -m 0644 $(SUDERRA_KEYS_DIR)/verity-signing.crt \
		$(TARGET_DIR)/etc/dm-verity/pubkey.pem
	$(INSTALL) -D -m 0644 $(SUDERRA_KEYS_DIR)/installer-payload.ed25519.pub \
		$(TARGET_DIR)/etc/suderra/os-installer-payload.ed25519.pub
	$(INSTALL) -D -m 0644 $(SUDERRA_KEYS_DIR)/edge-artifact.ed25519.pub \
		$(TARGET_DIR)/etc/suderra/edge-artifact.ed25519.pub
endef

$(eval $(generic-package))
