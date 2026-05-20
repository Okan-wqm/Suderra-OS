################################################################################
#
# suderra-edge-agent
# Suderra Edge Agent — industrial edge daemon.
# Update procedure: docs/operations/edge-agent-update.md
#
################################################################################

# Pin immutable commits for OS releases. Moving branches make the generated
# cargo vendor archive and hash non-reproducible.
SUDERRA_EDGE_AGENT_VERSION = eefc2ceb2c999d2dd444259145e10944f0b9116f
SUDERRA_EDGE_AGENT_SITE = $(call github,Okan-wqm,aquaculture_platform,$(SUDERRA_EDGE_AGENT_VERSION))
SUDERRA_EDGE_AGENT_SUBDIR = sens-api-gateway
SUDERRA_EDGE_AGENT_LICENSE = Proprietary
SUDERRA_EDGE_AGENT_LICENSE_FILES = sens-api-gateway/LICENSE

SUDERRA_EDGE_AGENT_CARGO_BUILD_OPTS = --bin suderra-agent
SUDERRA_EDGE_AGENT_CARGO_INSTALL_OPTS = --bin suderra-agent

define SUDERRA_EDGE_AGENT_INSTALL_CONFIG
	$(INSTALL) -D -m 0600 \
		$(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-edge-agent/config.yaml \
		$(TARGET_DIR)/var/lib/suderra/config/config.yaml
endef
SUDERRA_EDGE_AGENT_POST_INSTALL_TARGET_HOOKS += SUDERRA_EDGE_AGENT_INSTALL_CONFIG

define SUDERRA_EDGE_AGENT_INSTALL_RELEASE_LAYOUT
	$(INSTALL) -D -m 0755 $(TARGET_DIR)/usr/bin/suderra-agent \
		$(TARGET_DIR)/opt/suderra/edge/releases/$(SUDERRA_EDGE_AGENT_VERSION)/suderra-agent
	ln -sfn releases/$(SUDERRA_EDGE_AGENT_VERSION) \
		$(TARGET_DIR)/opt/suderra/edge/current
endef
SUDERRA_EDGE_AGENT_POST_INSTALL_TARGET_HOOKS += SUDERRA_EDGE_AGENT_INSTALL_RELEASE_LAYOUT

define SUDERRA_EDGE_AGENT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 \
		$(BR2_EXTERNAL_SUDERRA_PATH)/package/suderra-edge-agent/suderra-agent.service \
		$(TARGET_DIR)/usr/lib/systemd/system/suderra-agent.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -fs ../../../../usr/lib/systemd/system/suderra-agent.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/suderra-agent.service
endef

define SUDERRA_EDGE_AGENT_USERS
	suderra 200 suderra 200 ! /var/lib/suderra /sbin/nologin - Suderra_Edge_Agent_runtime
endef

define SUDERRA_EDGE_AGENT_PERMISSIONS
	/var/lib/suderra        d 750 suderra suderra - - - - -
	/var/lib/suderra/edge   d 750 suderra suderra - - - - -
	/var/lib/suderra/config d 750 root    suderra - - - - -
	/var/log/suderra        d 750 suderra suderra - - - - -
	/etc/suderra            d 755 root    root    - - - - -
	/opt/suderra            d 755 root    root    - - - - -
	/opt/suderra/edge       d 755 root    root    - - - - -
	/var/lib/suderra/config/config.yaml f 640 root    suderra - - - - -
endef

$(eval $(cargo-package))
