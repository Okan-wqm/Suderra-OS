################################################################################
#
# suderra-keys
#
# Public key / sertifikaları rootfs'e kurar.
# Anahtarların kendisi git'te YOK — SUDERRA_TRUST_ROOTS_DIR'den okur.
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

# Anahtar dizini — geliştirici/CI/release override edebilir.
# SUDERRA_KEYS_DIR Buildroot'un suderra-keys package build directory değişkeni
# ile çakışır; trust-root kaynağı için SUDERRA_TRUST_ROOTS_DIR kullanılır.
SUDERRA_TRUST_ROOTS_DIR ?= $(HOME)/.suderra-keys/dev
SUDERRA_KEYS_PROFILE_FILE ?= suderra-keys.profile

define SUDERRA_KEYS_INSTALL_TARGET_CMDS
	@if [ ! -d "$(SUDERRA_TRUST_ROOTS_DIR)" ]; then \
		echo "ERROR: SUDERRA_TRUST_ROOTS_DIR=$(SUDERRA_TRUST_ROOTS_DIR) yok."; \
		echo "Geliştirme anahtarları için: ./scripts/gen-dev-keys.sh"; \
		exit 1; \
	fi
	# The vendored edge contract's TEST-ONLY keys are derivable by anyone, so no
	# image of any variant may pin one (ADR-048 DEC-3.9, DEC-25.1): refuse the
	# whole trust-root directory before installing anything from it.
	@python3 -B $(BR2_EXTERNAL_SUDERRA_PATH)/scripts/ci/check-no-contract-test-keys.py --tree "$(SUDERRA_TRUST_ROOTS_DIR)"
	@for required in \
		rauc-signing.crt \
		verity-signing.crt \
		os-update-manifest.ed25519.pub \
		installer-payload.ed25519.pub \
		recovery-escrow.pub.pem; do \
		if [ ! -s "$(SUDERRA_TRUST_ROOTS_DIR)/$$required" ]; then \
			echo "ERROR: required Suderra trust root missing: $(SUDERRA_TRUST_ROOTS_DIR)/$$required"; \
			exit 1; \
		fi; \
	done
	@profile="$$(cat "$(SUDERRA_TRUST_ROOTS_DIR)/$(SUDERRA_KEYS_PROFILE_FILE)" 2>/dev/null || true)"; \
	if [ "$(BR2_PACKAGE_SUDERRA_VARIANT_PROD)" = "y" ]; then \
		if [ "$$profile" != "prod" ]; then \
			echo "ERROR: production builds require $(SUDERRA_KEYS_PROFILE_FILE) containing 'prod'."; \
			echo "Refusing to let development keys masquerade as production trust roots."; \
			exit 1; \
		fi; \
		case "$(SUDERRA_TRUST_ROOTS_DIR)" in \
			*/dev|*/dev/) \
				echo "ERROR: production builds may not use a dev key directory: $(SUDERRA_TRUST_ROOTS_DIR)"; \
				exit 1; \
				;; \
		esac; \
		if command -v openssl >/dev/null 2>&1; then \
			for cert in rauc-signing.crt verity-signing.crt; do \
				subject="$$(openssl x509 -in "$(SUDERRA_TRUST_ROOTS_DIR)/$$cert" -noout -subject 2>/dev/null || true)"; \
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
	$(INSTALL) -m 0644 $(SUDERRA_TRUST_ROOTS_DIR)/rauc-signing.crt \
		$(TARGET_DIR)/etc/rauc/keyring.pem
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/dm-verity
	$(INSTALL) -m 0644 $(SUDERRA_TRUST_ROOTS_DIR)/verity-signing.crt \
		$(TARGET_DIR)/etc/dm-verity/pubkey.pem
	$(INSTALL) -D -m 0644 $(SUDERRA_TRUST_ROOTS_DIR)/installer-payload.ed25519.pub \
		$(TARGET_DIR)/etc/suderra/os-installer-payload.ed25519.pub
	$(INSTALL) -D -m 0644 $(SUDERRA_TRUST_ROOTS_DIR)/os-update-manifest.ed25519.pub \
		$(TARGET_DIR)/etc/suderra/os-update-manifest.ed25519.pub
	# The offline escrow key of the /data recovery keys (ADR-048 DEC-14.3): a
	# public RSA key, the recipient of every device's recovery-key envelope.
	$(INSTALL) -D -m 0644 $(SUDERRA_TRUST_ROOTS_DIR)/recovery-escrow.pub.pem \
		$(TARGET_DIR)/etc/suderra/recovery-escrow.pub.pem
	rm -f $(TARGET_DIR)/etc/suderra/edge-artifact.ed25519.pub
	# Edge keys pinned per purpose and epoch (ADR-048 DEC-3.4, DEC-3.9):
	# dev/CI keys (and the dev provisioning-API CA) on dev images and on every
	# image of a ci-role board, only ceremony-inventoried keyids on
	# production images of hardware boards (none before P1).
	python3 -B $(@D)/suderra-edge-pins.py \
		--trust-roots "$(SUDERRA_TRUST_ROOTS_DIR)" --target "$(TARGET_DIR)" \
		--variant $(if $(BR2_PACKAGE_SUDERRA_VARIANT_PROD),prod,dev) \
		--defconfig "$(firstword $(call qstrip,$(BR2_ROOTFS_POST_SCRIPT_ARGS)))_defconfig" \
		--boards "$(BR2_EXTERNAL_SUDERRA_PATH)/contracts/suderra-edge/v1/boards.json"
endef

$(eval $(generic-package))
