# Changelog

Bu dosyadaki tüm önemli değişiklikler [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
formatına ve [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kurallarına uyar.

## [Unreleased]

### Added — Faz 0 (Proje İskeleti)
- Initial repository structure (BR2_EXTERNAL pattern)
- Root files: README, LICENSE (Apache-2.0), SECURITY, CONTRIBUTING, CHANGELOG, CODEOWNERS
- Buildroot scaffolding: external.desc, external.mk, Config.in
- Defconfig placeholder'lar: suderra_qemu_x86_64, suderra_x86_64, suderra_aarch64
- 5 başlangıç ADR'ı (Buildroot vs Yocto, systemd minimal, multi-arch, RAUC, dm-verity+secboot)
- Doküman iskeleti: architecture, security, operations, dev, compliance
- CI: lint workflow (shellcheck, markdownlint, gitleaks)
- Issue ve PR şablonları
- Geliştirme container'ı (Ubuntu 24.04 + Buildroot deps)
- Anahtar yönetimi politikası iskeleti

[Unreleased]: https://github.com/Okan-wqm/suderra-os/compare/HEAD
