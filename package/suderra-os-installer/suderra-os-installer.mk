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
SUDERRA_INSTALLER_PAYLOAD_KEY_PROFILE ?=
SUDERRA_TRUST_ROOTS_DIR ?= $(HOME)/.suderra-keys/dev

SUDERRA_OS_INSTALLER_DEPENDENCIES = host-rustc

define SUDERRA_OS_INSTALLER_BUILD_CMDS
	cd $(BR2_EXTERNAL_SUDERRA_PATH)/userspace && \
		cargo build --release \
			--target $(BR2_RUSTC_TARGET_NAME) \
			--package suderra-installer
endef

define SUDERRA_OS_INSTALLER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/suderra-os-install \
		$(TARGET_DIR)/usr/sbin/suderra-os-install
	$(INSTALL) -D -m 0755 \
		$(BR2_EXTERNAL_SUDERRA_PATH)/userspace/target/$(BR2_RUSTC_TARGET_NAME)/release/suderra-installer \
		$(TARGET_DIR)/usr/bin/suderra-installer
	$(INSTALL) -d -m 0755 $(TARGET_DIR)/etc/suderra
	payload_pubkey="$(SUDERRA_INSTALLER_PAYLOAD_PUBKEY)"; \
	payload_profile="$(SUDERRA_INSTALLER_PAYLOAD_KEY_PROFILE)"; \
	if [ -z "$$payload_pubkey" ] && [ -s "$(SUDERRA_TRUST_ROOTS_DIR)/installer-payload.ed25519.pub" ]; then \
		payload_pubkey="$(SUDERRA_TRUST_ROOTS_DIR)/installer-payload.ed25519.pub"; \
		if [ -z "$$payload_profile" ]; then \
			payload_profile="$$(cat "$(SUDERRA_TRUST_ROOTS_DIR)/suderra-keys.profile" 2>/dev/null || true)"; \
		fi; \
	fi; \
	if [ -n "$$payload_pubkey" ]; then \
		if [ "$(BR2_PACKAGE_SUDERRA_VARIANT_PROD)" = "y" ]; then \
			if [ "$$payload_profile" != "prod" ]; then \
				echo "ERROR: production USB installer requires a prod-profiled installer payload public key"; \
				exit 1; \
			fi; \
			case "$$payload_pubkey" in \
				*/dev/*|*/dev) \
					echo "ERROR: production USB installer may not pin a dev payload key: $$payload_pubkey"; \
					exit 1; \
					;; \
			esac; \
		fi; \
		$(INSTALL) -D -m 0644 "$$payload_pubkey" \
			$(TARGET_DIR)/etc/suderra/os-installer-payload.ed25519.pub; \
	elif [ "$(BR2_PACKAGE_SUDERRA_VARIANT_PROD)" = "y" ]; then \
		echo "ERROR: production USB installer requires SUDERRA_INSTALLER_PAYLOAD_PUBKEY"; \
		exit 1; \
	fi
endef

define SUDERRA_OS_INSTALLER_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/suderra-os-install.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-os-install.service
endef

$(eval $(generic-package))
