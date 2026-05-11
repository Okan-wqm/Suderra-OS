# Suderra OS

Sertleştirilmiş, immutable, OTA-güncellenebilir Linux tabanlı endüstriyel edge işletim sistemi. **Suderra Edge Agent** (Rust) için özel olarak inşa edilmiştir.

> **Status:** Faz 0 — Proje iskeleti. Henüz boot eden bir imaj yok. Yol haritası: [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)

## Neden Suderra OS?

Sıradan Linux dağıtımları (Ubuntu, Debian) endüstriyel sahalarda çalışan bir Rust daemon'unu barındırmak için fazla geniş ve karmaşıktır:

| Boyut | Ubuntu Server | Suderra OS (hedef) |
|---|---|---|
| Disk imajı | ~4 GB | ~50 MB |
| Background daemon | ~40 | 3-5 |
| Açık port (default) | 6+ | 0 |
| Persistence riski | Yüksek (mutable rootfs) | Yok (dm-verity + read-only) |
| Supply chain | Geniş (binlerce paket) | Dar (~30-50 paket, pinli) |

Suderra OS şunları sağlar:

- **Immutable rootfs** + `dm-verity` ile kriptografik bütünlük
- **UEFI Secure Boot** zinciri (shim → kernel → initramfs)
- **A/B partition + RAUC OTA** — bozuk update otomatik geri döner
- **Minimal saldırı yüzeyi** — sadece uygulamanın ihtiyaç duyduğu paketler
- **Sertleştirilmiş kernel** — lockdown, KASLR, modules-off, syscall filtering
- **seccomp + capabilities** — uygulama RCE alsa bile izole
- **SBOM (CycloneDX)** + reproducible build — supply chain güveni
- **IEC 62443 SL2 / CRA hazırlığı**

## Quick Start

> Bu adımlar Faz 1 tamamlanınca çalışır. Şu anda iskelet aşamasında.

```bash
# 1. Geliştirme ortamı kurulumu
./scripts/build-in-docker.sh --help

# 2. QEMU için x86_64 imaj build
make build-qemu

# 3. QEMU'da çalıştır
./scripts/qemu-run.sh

# 4. Gerçek donanım için
make build-x86_64
./scripts/flash-usb.sh /dev/sdX output/images/x86_64/suderra-os.img
```

## Mimari

```
┌─────────────────────────────────────────┐
│   Suderra Edge Agent (Rust, ~5MB)       │
│   - Modbus TCP/RTU, OPC UA, MQTT        │
│   - SQLCipher (encrypted state)         │
│   - sd-notify watchdog                  │
└─────────────────────────────────────────┘
                  ↓ runs on
┌─────────────────────────────────────────┐
│   Minimal systemd (sertleştirilmiş)     │
│   - 3-5 daemon, journald, networkd      │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Linux Kernel 6.12 LTS (hardened)      │
│   - lockdown=confidentiality            │
│   - modules-off (monolithic)            │
│   - KASLR, KPTI, SMEP/SMAP, seccomp     │
└─────────────────────────────────────────┘
                  ↓ verifies
┌─────────────────────────────────────────┐
│   dm-verity (Merkle tree, RO rootfs)    │
└─────────────────────────────────────────┘
                  ↓ booted by
┌─────────────────────────────────────────┐
│   UEFI + Secure Boot (signed chain)     │
└─────────────────────────────────────────┘
```

Detaylar: [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md), [docs/architecture/boot-chain.md](docs/architecture/boot-chain.md)

## Repo Yapısı

| Klasör | İçerik |
|---|---|
| `configs/` | Buildroot defconfig'leri (x86_64, aarch64, qemu) |
| `board/suderra/` | Bootloader, kernel config, rootfs overlay, image layout |
| `package/` | Custom Buildroot paketleri (edge-agent, firstboot, keys) |
| `userspace/` | **Rust workspace** — Suderra-spesifik tools (firstboot, ota, telemetry, watchdog, ...) |
| `docs/` | Mimari, güvenlik, operasyon, uyumluluk dokümantasyonu |
| `scripts/` | Build, sign, flash, qemu, sbom yardımcıları |
| `ci/` | Reproducible build container |
| `tests/` | QEMU, security, OTA testleri |
| `vex/` | Vulnerability Exploitability eXchange dokümanları |
| `.github/` | Workflows, issue/PR şablonları |
| `LICENSES/` | REUSE 3.3 lisans dosyaları |
| `.well-known/` | RFC 9116 security.txt |

## Dokümantasyon

Tam doküman indeksi: [docs/README.md](docs/README.md)

Hızlı linkler:

- **Roadmap:** [ROADMAP.md](ROADMAP.md) — 7 fazlı 5-7 aylık plan
- **Mimari:** [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)
- **Rust workspace:** [docs/dev/rust-workspace.md](docs/dev/rust-workspace.md) + [userspace/README.md](userspace/README.md)
- **Güvenlik:** [docs/security/threat-model.md](docs/security/threat-model.md), [SECURITY.md](SECURITY.md)
- **Build:** [docs/operations/build.md](docs/operations/build.md)
- **Geliştirici kurulumu:** [docs/dev/setup.md](docs/dev/setup.md)
- **OTA:** [docs/operations/ota.md](docs/operations/ota.md)
- **Mimari karar kayıtları (ADR):** [docs/architecture/](docs/architecture/)
- **Uyumluluk:** [docs/compliance/iec-62443-mapping.md](docs/compliance/iec-62443-mapping.md)

## Katkıda Bulunma

- [CONTRIBUTING.md](CONTRIBUTING.md) — conventional commits, DCO sign-off, branch stratejisi, code review
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant v2.1
- [GOVERNANCE.md](GOVERNANCE.md) — karar mekanizması, roller, sürdürülebilirlik
- [MAINTAINERS.md](MAINTAINERS.md) — aktif maintainer listesi

## Güvenlik

- [SECURITY.md](SECURITY.md) — Vulnerability bildirme (public issue açmadan önce oku!)
- [docs/security/cvd-policy.md](docs/security/cvd-policy.md) — Coordinated Vulnerability Disclosure policy
- [docs/security/incident-response.md](docs/security/incident-response.md) — Incident response runbook
- [`.well-known/security.txt`](.well-known/security.txt) — RFC 9116 machine-readable contact

## Uyumluluk (Compliance)

- [docs/compliance/cra-annex-i-checklist.md](docs/compliance/cra-annex-i-checklist.md) — EU CRA Annex I madde-madde checklist
- [docs/compliance/iec-62443-4-2-component-requirements.md](docs/compliance/iec-62443-4-2-component-requirements.md) — IEC 62443-4-2 CR mapping
- [docs/compliance/support-period.md](docs/compliance/support-period.md) — Vendor support commitment (5+ yıl)
- [docs/compliance/eu-doc-template.md](docs/compliance/eu-doc-template.md) — CE Declaration of Conformity şablonu

## Lisans

[Apache-2.0](LICENSE). Buildroot, Linux kernel ve gömülü paketler kendi lisanslarına tabidir;
[REUSE 3.3](https://reuse.software/spec-3.3/) uyumlu (bkz. [REUSE.toml](REUSE.toml)).

SPDX raporu için: [docs/compliance/licenses.md](docs/compliance/licenses.md)
SBOM (CycloneDX, her release ile): `output/sbom.cyclonedx.json`
VEX (Vulnerability Exploitability eXchange): [vex/](vex/)
