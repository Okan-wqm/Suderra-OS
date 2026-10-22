################################################################################
#
# revpi-picontrol
#
################################################################################

# KUNBUS piControl, the Revolution Pi PiBridge master and process-image
# driver (/dev/piControl0). It is a separate out-of-tree module repository, not
# part of the KUNBUS kernel tree, so the kernel-module infrastructure builds it
# against the image's own kernel and modules_install signs it with the kernel's
# module signing key (CONFIG_MODULE_SIG_ALL); the production kernel refuses
# unsigned modules (board/suderra/aarch64-revpi-connect4/
# linux-revpi-suderra-prod.config).
#
# The version is the piControl release KUNBUS ships for the pinned kernel: the
# upstream tag v2.6.2 is byte-identical (apart from debian/) to KUNBUS's
# debian/2.6.2-1+deb12+4, built "for linux-image-6.12.91-revpi0-rpi-v8". Newer
# piControl releases are built for the 6.18 KUNBUS kernel and do not link
# against the 6.12 kernel: piControl 2.8.2 calls pibridge_req_io_tmt,
# pibridge_get_iop_crc16 and pibridge_set_iop_crc16, which
# drivers/tty/serdev/pibridge.c of revpi-6.12 does not export. The kernel pin
# in configs/suderra_aarch64_revpi4*_defconfig and this version move together;
# docs/hardware/revpi-connect4.md is the bump procedure and
# tests/image-contracts/revpi-board-contract-test.sh holds the pairing.
REVPI_PICONTROL_VERSION = 7acf6e9110dd558b434b57f50ee5d4b5d54b5d91
REVPI_PICONTROL_SITE = $(call gitlab,revolutionpi,piControl,$(REVPI_PICONTROL_VERSION))
REVPI_PICONTROL_SOURCE = piControl-$(REVPI_PICONTROL_VERSION).tar.gz
REVPI_PICONTROL_LICENSE = GPL-2.0-only (module), LGPL-2.1-only (json.c, RS485FwuCommand.c), MIT (piControl.h)
REVPI_PICONTROL_LICENSE_FILES = LICENSES/GPL-2.0-only.txt LICENSES/LGPL-2.1-only.txt LICENSES/MIT.txt

# What piControl links against (its includes): the PiBridge serdev master, the
# IIO consumer API (analog modules), netfilter (the gateway telegram hook), the
# LED class and its triggers (the RevPi status LEDs), GPIO consumers, thermal
# and cpufreq. The kernel fragment names the same symbols; the fixups keep a
# defconfig that selects this package from ever dropping one of them.
define REVPI_PICONTROL_LINUX_CONFIG_FIXUPS
	$(call KCONFIG_ENABLE_OPT,CONFIG_SERIAL_DEV_BUS)
	$(call KCONFIG_ENABLE_OPT,CONFIG_SERIAL_DEV_MUX_PIBRIDGE)
	$(call KCONFIG_ENABLE_OPT,CONFIG_IIO)
	$(call KCONFIG_ENABLE_OPT,CONFIG_NETFILTER)
	$(call KCONFIG_ENABLE_OPT,CONFIG_LEDS_CLASS)
	$(call KCONFIG_ENABLE_OPT,CONFIG_LEDS_TRIGGERS)
	$(call KCONFIG_ENABLE_OPT,CONFIG_GPIOLIB)
	$(call KCONFIG_ENABLE_OPT,CONFIG_SPI)
	$(call KCONFIG_ENABLE_OPT,CONFIG_THERMAL)
	$(call KCONFIG_ENABLE_OPT,CONFIG_CPU_FREQ)
endef

# The module is built from the repository root: its Makefile is a kbuild
# Makefile (obj-m := piControl.o with sources under src/).
REVPI_PICONTROL_MODULE_SUBDIRS = .

# piControl has no device alias to autoload on, so systemd-modules-load loads
# it at boot.
define REVPI_PICONTROL_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 $(REVPI_PICONTROL_PKGDIR)/revpi-picontrol.conf \
		$(TARGET_DIR)/usr/lib/modules-load.d/revpi-picontrol.conf
endef

$(eval $(kernel-module))
$(eval $(generic-package))
