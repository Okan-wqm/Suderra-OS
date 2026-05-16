#
# Suderra OS — BR2_EXTERNAL Makefile entegrasyonu
#
# Buildroot bu dosyayı otomatik olarak include eder.
# Burada custom paketler ve post-build/post-image hook'ları tanımlanır.
#

#
# Helper değişkenler — paketler ve hook'lar tarafından kullanılır
#
SUDERRA_BOARD_DIR := $(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra

# Buildroot generic-package reserves <PKG>_DIR variables. Because the package
# is named suderra-keys, SUDERRA_KEYS_DIR is the package build directory inside
# Buildroot and must not be used as the trust-root location. Keep accepting the
# historical environment name only at this boundary, then publish a distinct
# variable for packages.
ifeq ($(origin SUDERRA_TRUST_ROOTS_DIR),undefined)
ifneq ($(origin SUDERRA_KEYS_DIR),undefined)
SUDERRA_TRUST_ROOTS_DIR := $(SUDERRA_KEYS_DIR)
else
SUDERRA_TRUST_ROOTS_DIR := $(HOME)/.suderra-keys/dev
endif
endif
export SUDERRA_TRUST_ROOTS_DIR

# Custom paketler — package/*/.mk dosyalarını dahil et. Helper değişkenler
# önce tanımlanmalı; aksi halde package makefile'ları CI/prod keyring
# override'larını göremez.
include $(sort $(wildcard $(BR2_EXTERNAL_SUDERRA_PATH)/package/*/*.mk))

#
# Post-image hook'u: RAUC bundle, dm-verity hash, SBOM üretimi
# Asıl iş `board/suderra/common/post-image.sh` içinde yapılır.
#
# Bu çağrı `BR2_ROOTFS_POST_IMAGE_SCRIPT` defconfig'de yapılır.
#

# Sürüm bilgisini os-release için ortam değişkenine aktar
export SUDERRA_VERSION   ?= $(call qstrip,$(BR2_PACKAGE_SUDERRA_VERSION))
export SUDERRA_BUILD_ID  ?= $(call qstrip,$(BR2_PACKAGE_SUDERRA_BUILD_ID))
export SUDERRA_BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
