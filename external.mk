#
# Suderra OS — BR2_EXTERNAL Makefile entegrasyonu
#
# Buildroot bu dosyayı otomatik olarak include eder.
# Burada custom paketler ve post-build/post-image hook'ları tanımlanır.
#

# Custom paketler — package/*/.mk dosyalarını dahil et
include $(sort $(wildcard $(BR2_EXTERNAL_SUDERRA_PATH)/package/*/*.mk))

#
# Post-image hook'u: RAUC bundle, dm-verity hash, SBOM üretimi
# Asıl iş `board/suderra/common/post-image.sh` içinde yapılır.
#
# Bu çağrı `BR2_ROOTFS_POST_IMAGE_SCRIPT` defconfig'de yapılır.
#

#
# Helper değişkenler — paketler ve hook'lar tarafından kullanılır
#
SUDERRA_BOARD_DIR := $(BR2_EXTERNAL_SUDERRA_PATH)/board/suderra
SUDERRA_KEYS_DIR  := $(BR2_EXTERNAL_SUDERRA_PATH)/board/keys

# Sürüm bilgisini os-release için ortam değişkenine aktar
export SUDERRA_VERSION   ?= $(call qstrip,$(BR2_PACKAGE_SUDERRA_VERSION))
export SUDERRA_BUILD_ID  ?= $(call qstrip,$(BR2_PACKAGE_SUDERRA_BUILD_ID))
export SUDERRA_BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
