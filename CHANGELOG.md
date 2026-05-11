# Changelog

Bu dosyadaki tüm önemli değişiklikler [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
formatına ve [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kurallarına uyar.

## [Unreleased]

### Added — Faz 0 (Proje İskeleti)

**Core scaffolding:**
- Initial repository structure (BR2_EXTERNAL pattern)
- Root files: README, LICENSE (Apache-2.0), SECURITY, CONTRIBUTING, CHANGELOG, CODEOWNERS
- Buildroot scaffolding: external.desc, external.mk, Config.in
- Defconfig placeholder'lar: suderra_qemu_x86_64, suderra_x86_64, suderra_aarch64
- 6 ADR (Buildroot vs Yocto, systemd minimal, multi-arch, RAUC, dm-verity+secboot, IEC 62443 SL2 vs SL3)
- Doküman iskeleti: architecture, security, operations, dev, compliance
- CI: lint workflow (shellcheck, markdownlint, gitleaks)
- Issue ve PR şablonları
- Geliştirme container'ı (Ubuntu 24.04 + Buildroot deps)
- Anahtar yönetimi politikası iskeleti

**Endüstri standartları (gap-fix):**
- **Governance:** CODE_OF_CONDUCT (Contributor Covenant 2.1), GOVERNANCE.md, MAINTAINERS.md
- **REUSE 3.3 compliance:** LICENSES/ dizini (Apache-2.0, CC0-1.0, GPL-2.0-or-later), REUSE.toml ile toplu SPDX annotation
- **Supply chain:**
  - `.github/workflows/slsa-provenance.yml` — SLSA L3 provenance
  - `.github/workflows/release.yml` — cosign keyless signing + SBOM imzalama
  - `scripts/gen-sbom.sh` — CycloneDX SBOM üretimi
  - `scripts/sign-bundle.sh` — RAUC + cosign artifact signing
  - `scripts/verify-reproducible.sh` — Reproducible build doğrulama
- **Vulnerability handling:**
  - `vex/` dizini — OpenVEX 0.2.0 dokümanları + örnek
  - `docs/security/vex-policy.md` — VEX triage politikası
  - `docs/security/cvd-policy.md` — Coordinated Vulnerability Disclosure (ISO 29147)
  - `docs/security/incident-response.md` — CRA Article 14 incident runbook
  - `docs/security/pen-test-report-template.md` — Pen-test rapor şablonu
  - `docs/operations/verify-release.md` — End-user release doğrulama rehberi
  - `.well-known/security.txt` (RFC 9116)
- **Compliance:**
  - `docs/compliance/cra-annex-i-checklist.md` — EU CRA Annex I madde-madde mapping
  - `docs/compliance/iec-62443-4-2-component-requirements.md` — IEC 62443-4-2 EDR CR mapping
  - `docs/compliance/support-period.md` — 5+ yıl support commitment (CRA Article 13(8))
  - `docs/compliance/eu-doc-template.md` — CE Declaration of Conformity şablonu
  - `docs/compliance/cis-dil-mapping.md` — CIS DIL benchmark mapping
  - `docs/compliance/openssf-badge-status.md` — OpenSSF Best Practices Badge tracking
- **Automation:**
  - `.github/dependabot.yml` — GitHub Actions + Docker bağımlılık takibi
  - `.github/workflows/scorecard.yml` — OpenSSF Scorecard analizi
  - `.github/workflows/hadolint.yml` — Dockerfile linting
  - `.github/workflows/stale.yml` — Issue/PR housekeeping
  - `.pre-commit-config.yaml` — Lokal hooks (shellcheck, markdownlint, gitleaks, reuse, hadolint, DCO)
  - `.devcontainer/devcontainer.json` — VSCode/Codespaces dev environment
  - `docs/dev/branch-protection.md` — GitHub branch protection rules

[Unreleased]: https://github.com/Okan-wqm/suderra-os/compare/HEAD
