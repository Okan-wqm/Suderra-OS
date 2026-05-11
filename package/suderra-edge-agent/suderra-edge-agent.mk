################################################################################
#
# suderra-edge-agent
#
# Suderra Edge Agent — endüstriyel edge daemon (Rust + musl)
#
# Bu .mk dosyası Faz 2'de doldurulacak. Şu anda iskelet halinde.
#
# Faz 2 TODO'ları:
#   - Cargo build (musl target: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl)
#   - Statik binary install: /usr/bin/suderra-edge-agent
#   - systemd unit install: /usr/lib/systemd/system/suderra-edge-agent.service
#   - Default config install: /etc/suderra/config.yaml
#   - User/group oluştur: suderra-edge (unprivileged)
#   - /var/lib/suderra dir hazırla
#
################################################################################

SUDERRA_EDGE_AGENT_VERSION = 1.6.0
SUDERRA_EDGE_AGENT_SITE = $(call github,Okan-wqm,aquaculture_platform,v$(SUDERRA_EDGE_AGENT_VERSION))
SUDERRA_EDGE_AGENT_LICENSE = Apache-2.0
SUDERRA_EDGE_AGENT_LICENSE_FILES = sens-api-gateway/LICENSE

SUDERRA_EDGE_AGENT_DEPENDENCIES = host-rustc

# Faz 2 placeholder - Cargo build komutları
define SUDERRA_EDGE_AGENT_BUILD_CMDS
	@echo "TODO Faz 2: cargo build --release --target=$(BR2_RUSTC_TARGET_NAME) --manifest-path=$(@D)/sens-api-gateway/Cargo.toml"
	@true
endef

# Faz 2 placeholder - install
define SUDERRA_EDGE_AGENT_INSTALL_TARGET_CMDS
	@echo "TODO Faz 2: install -m 0755 \$(@D)/sens-api-gateway/target/.../release/suderra-edge-agent \$(TARGET_DIR)/usr/bin/"
	@echo "TODO Faz 2: install -m 0644 systemd unit, config template, etc."
	@true
endef

# Kullanıcı + dizin oluşturma (Buildroot users + permissions framework)
define SUDERRA_EDGE_AGENT_USERS
	suderra-edge -1 suderra-edge -1 * /var/lib/suderra /sbin/nologin - Suderra_Edge_Agent_runtime
endef

define SUDERRA_EDGE_AGENT_PERMISSIONS
	/var/lib/suderra  d 750 suderra-edge suderra-edge - - - - -
	/etc/suderra      d 750 root         suderra-edge - - - - -
endef

$(eval $(generic-package))
