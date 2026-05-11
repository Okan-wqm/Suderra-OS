# Suderra OS — Top-level convenience Makefile
#
# Bu Makefile Buildroot wrapper'ıdır. Asıl build mantığı:
#   buildroot/ submodule (Faz 1'de eklenir) + configs/<defconfig>
#
# Kullanım:
#   make help                 - Bu mesaj
#   make build-qemu           - QEMU x86_64 imajı (geliştirme)
#   make build-x86            - x86_64 endüstriyel imaj
#   make build-arm            - aarch64 imaj (Pi CM4, Revolution Pi)
#   make qemu                 - Son build'i QEMU'da çalıştır
#   make sbom                 - CycloneDX SBOM üret
#   make clean                - Build artifact'lerini temizle (dl/ koru)
#   make distclean            - Her şeyi temizle (download cache dahil)
#   make lint                 - shellcheck + markdownlint + gitleaks
#   make test                 - tests/ altındaki tüm testleri koştur
#   make docker-shell         - Build container içinde shell aç
#   make new-adr TITLE="..."  - Yeni ADR oluştur

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

# Sürüm bilgisi — git tag'den okur, yoksa 'dev'
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BR2_EXTERNAL ?= $(CURDIR)
BUILDROOT_DIR ?= $(CURDIR)/buildroot
OUTPUT_DIR ?= $(CURDIR)/output

DEFCONFIGS := $(notdir $(wildcard configs/suderra_*_defconfig))

.PHONY: help
help:
	@echo "Suderra OS v$(VERSION)"
	@echo ""
	@echo "Build hedefleri:"
	@echo "  build-qemu         QEMU x86_64 imajı (geliştirme/CI)"
	@echo "  build-x86          x86_64 endüstriyel imaj"
	@echo "  build-arm          aarch64 imaj (Pi CM4)"
	@echo ""
	@echo "Çalıştırma:"
	@echo "  qemu               Son QEMU imajını boot et"
	@echo ""
	@echo "Kalite:"
	@echo "  lint               shellcheck + markdownlint + gitleaks"
	@echo "  test               Tüm testler"
	@echo "  sbom               CycloneDX SBOM üret"
	@echo ""
	@echo "Geliştirici:"
	@echo "  docker-shell       Build container içinde shell"
	@echo "  new-adr TITLE=...  Yeni ADR şablonu"
	@echo "  clean              Build artifact'leri sil (dl/ koru)"
	@echo "  distclean          Her şeyi sil"
	@echo ""
	@echo "Mevcut defconfig'ler:"
	@for d in $(DEFCONFIGS); do echo "  $$d"; done

# --- Build hedefleri (Faz 1'de aktive olur) ---

.PHONY: build-qemu
build-qemu:
	@$(MAKE) _build DEFCONFIG=suderra_qemu_x86_64_defconfig

.PHONY: build-x86
build-x86:
	@$(MAKE) _build DEFCONFIG=suderra_x86_64_defconfig

.PHONY: build-arm
build-arm:
	@$(MAKE) _build DEFCONFIG=suderra_aarch64_defconfig

.PHONY: _build
_build:
	@if [ ! -d "$(BUILDROOT_DIR)" ]; then \
		echo "ERROR: $(BUILDROOT_DIR) yok. Faz 1'de submodule olarak eklenecek."; \
		echo "Geçici çözüm: git clone https://gitlab.com/buildroot.org/buildroot.git -b 2024.11 $(BUILDROOT_DIR)"; \
		exit 1; \
	fi
	@if [ -z "$(DEFCONFIG)" ]; then \
		echo "ERROR: DEFCONFIG belirtilmedi."; exit 1; \
	fi
	@echo "==> Building $(DEFCONFIG) (Suderra OS v$(VERSION))"
	$(MAKE) -C $(BUILDROOT_DIR) BR2_EXTERNAL=$(BR2_EXTERNAL) O=$(OUTPUT_DIR)/$(DEFCONFIG) $(DEFCONFIG)
	$(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT_DIR)/$(DEFCONFIG)

# --- Çalıştırma ---

.PHONY: qemu
qemu:
	@./scripts/qemu-run.sh

# --- Kalite ---

.PHONY: lint
lint:
	@./scripts/lint.sh

.PHONY: test
test:
	@./scripts/run-tests.sh

.PHONY: sbom
sbom:
	@./scripts/gen-sbom.sh

# --- Geliştirici ---

.PHONY: docker-shell
docker-shell:
	@./scripts/build-in-docker.sh --shell

.PHONY: new-adr
new-adr:
	@if [ -z "$(TITLE)" ]; then echo "Kullanım: make new-adr TITLE=\"...\""; exit 1; fi
	@./scripts/new-adr.sh "$(TITLE)"

# --- Temizlik ---

.PHONY: clean
clean:
	@echo "==> Build artifact'leri siliniyor (dl/ korunuyor)"
	@rm -rf $(OUTPUT_DIR)

.PHONY: distclean
distclean: clean
	@echo "==> Distclean (download cache dahil)"
	@rm -rf $(BUILDROOT_DIR)/dl

# --- Sürüm bilgisi ---

.PHONY: version
version:
	@echo "Suderra OS $(VERSION)"
	@echo "Build date: $(BUILD_DATE)"
	@echo "BR2_EXTERNAL: $(BR2_EXTERNAL)"
