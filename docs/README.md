# Suderra OS — Dokümantasyon

Suderra OS dokümantasyonu beş ana grupta organize edilmiştir. Yeni ekibe katıldıysan **dev/setup.md → architecture/ARCHITECTURE.md → security/threat-model.md** sırasıyla okuman önerilir.

## Yapı

```
docs/
├── architecture/    # Sistem mimarisi + ADR'lar (mimari karar kayıtları)
├── security/        # Tehdit modeli, sertleştirme, anahtar yönetimi
├── operations/      # Build, flash, OTA, debug, runbook
├── dev/             # Geliştirici ortamı, coding standards
└── compliance/      # IEC 62443, CRA, lisans uyumluluğu
```

## Hızlı navigasyon

### Mimari

- [ARCHITECTURE.md](architecture/ARCHITECTURE.md) — yüksek seviye sistem mimarisi
- [boot-chain.md](architecture/boot-chain.md) — UEFI → kernel → rootfs zinciri
- **ADR'lar** (Architecture Decision Records):
  - [ADR-0001: Buildroot vs Yocto](architecture/ADR-0001-buildroot-vs-yocto.md)
  - [ADR-0002: systemd minimal](architecture/ADR-0002-systemd-minimal.md)
  - [ADR-0003: Multi-arch strategy](architecture/ADR-0003-multi-arch-strategy.md)
  - [ADR-0004: RAUC + A/B partition](architecture/ADR-0004-rauc-ab-partition.md)
  - [ADR-0005: dm-verity + Secure Boot](architecture/ADR-0005-dm-verity-secure-boot.md)
  - [ADR-0006: IEC 62443 SL 2 hedef seçimi (SL3 yerine)](architecture/ADR-0006-iec-62443-sl2-vs-sl3.md)
  - [ADR-template.md](architecture/ADR-template.md)

### Güvenlik

- [threat-model.md](security/threat-model.md) — STRIDE tehdit modeli
- [field-appliance-hardening.md](security/field-appliance-hardening.md) — sahada agent-only kilitli appliance güvenlik modeli
- [kernel-hardening.md](security/kernel-hardening.md) — hangi CONFIG'ler açık/kapalı, neden
- [sbom-process.md](security/sbom-process.md) — SBOM (CycloneDX) üretim akışı
- [key-management.md](security/key-management.md) — anahtar lifecycle, HSM roadmap
- [cve-process.md](security/cve-process.md) — CVE takip + patch politikası
- [cvd-policy.md](security/cvd-policy.md) — Coordinated Vulnerability Disclosure (ISO 29147)
- [incident-response.md](security/incident-response.md) — Incident response runbook (CRA Art 14)
- [vex-policy.md](security/vex-policy.md) — Vulnerability Exploitability eXchange politikası
- [pen-test-checklist.md](security/pen-test-checklist.md) — Lynis, OpenSCAP, nmap
- [pen-test-report-template.md](security/pen-test-report-template.md) — Pen-test rapor şablonu

### Operasyon

- [build.md](operations/build.md) — imaj nasıl build edilir (host + Docker)
- [flash.md](operations/flash.md) — USB stick ve gerçek cihaza yazma
- [usb-installer-alpha-validation.md](operations/usb-installer-alpha-validation.md) — Pi/CM4/RevPi USB installer lab kanıt akışı
- [release-lifecycle.md](operations/release-lifecycle.md) — alpha ve production release kapıları
- [ci-log-and-warning-triage.md](operations/ci-log-and-warning-triage.md) — build warning/SARIF governance
- [ota.md](operations/ota.md) — RAUC bundle oluştur, sun, rollback
- [edge-agent-update.md](operations/edge-agent-update.md) — `suderra-agent` pin/hash/config güncelleme akışı
- [verify-release.md](operations/verify-release.md) — cosign + SLSA + SBOM ile release doğrulama
- [debug.md](operations/debug.md) — serial console, journalctl, ssh-yok durum
- [factory-reset.md](operations/factory-reset.md) — fabrika ayarlarına dönüş
- [runbook.md](operations/runbook.md) — saha sorunları için step-by-step

### Geliştirici

- [setup.md](dev/setup.md) — Ubuntu 24.04 host kurulumu
- [docker-build.md](dev/docker-build.md) — reproducible CI build
- [qemu-test.md](dev/qemu-test.md) — QEMU'da test
- [coding-standards.md](dev/coding-standards.md) — kod standartları
- [rust-workspace.md](dev/rust-workspace.md) — Rust userspace workspace rehberi
- [branch-protection.md](dev/branch-protection.md) — GitHub branch protection rules

### Uyumluluk

- [iec-62443-mapping.md](compliance/iec-62443-mapping.md) — IEC 62443-4-1 (process) FR1-FR7
- [iec-62443-4-2-component-requirements.md](compliance/iec-62443-4-2-component-requirements.md) — IEC 62443-4-2 EDR CR mapping
- [cra-readiness.md](compliance/cra-readiness.md) — AB CRA hazırlığı genel bakış
- [cra-annex-i-checklist.md](compliance/cra-annex-i-checklist.md) — CRA Annex I madde-madde
- [support-period.md](compliance/support-period.md) — Vendor support commitment (5+ yıl)
- [eu-doc-template.md](compliance/eu-doc-template.md) — CE Declaration of Conformity şablonu
- [cis-dil-mapping.md](compliance/cis-dil-mapping.md) — CIS DIL benchmark mapping
- [openssf-badge-status.md](compliance/openssf-badge-status.md) — OpenSSF Best Practices Badge tracking
- [licenses.md](compliance/licenses.md) — SPDX raporu, GPL kaynak sunma süreci

## Doküman yazım kuralları

- **Format:** Markdown, GFM (GitHub Flavored)
- **Satır uzunluğu:** Yumuşak (uzun cümleler ok, ama 120 char altı tercih)
- **Code blocks:** Dil etiketi zorunlu (` ```bash`, ` ```yaml`, vb.)
- **Diagram:** Mermaid (kod olarak versiyonlanır) veya ASCII art (basit için)
- **Link:** Relative path (`docs/security/...` değil `security/...` veya `../security/...`)
- **Tablo:** Mümkün olduğunca, listeden okunabilir
- **Tarih:** ISO 8601 (`2026-05-11`)
- **Versiyon:** SemVer (`v0.1.0-alpha`)
- **Lint:** `markdownlint` temiz olmalı (CI kontrol eder)

## Dokümantasyon olgunluk durumu

| Doküman | Durum |
|---|---|
| ARCHITECTURE.md | Skeleton — Faz 1 başında dolacak |
| ADR-0001..0005 | Yazılı |
| threat-model.md | Skeleton — Faz 3 başında dolacak |
| kernel-hardening.md | Skeleton — Faz 3'te dolacak |
| build.md | Skeleton — Faz 1'de dolacak |
| ota.md | Skeleton — Faz 4'te dolacak |
| iec-62443-mapping.md | Skeleton — Faz 6'da dolacak |
| cra-readiness.md | Skeleton — Faz 6'da dolacak |
