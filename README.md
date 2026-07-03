# Suderra OS

Sertleştirilmiş, immutable ve OTA-güncellenebilir olması hedeflenen Linux tabanlı endüstriyel edge işletim sistemi. **Suderra Edge Agent** (Rust) için özel olarak inşa edilir.

> **Status:** Alpha/lab build zinciri GitHub Actions'ta doğrulanıyor. Production release hâlâ bloklu; signed boot, dm-verity, RAUC, anti-rollback, prod key policy ve hardware evidence tamamlanmadan production-ready claim yapılmaz.

## Neden Suderra OS?

Sıradan Linux dağıtımları (Ubuntu, Debian) endüstriyel sahalarda çalışan bir Rust daemon'unu barındırmak için fazla geniş ve karmaşıktır:

| Boyut | Ubuntu Server | Suderra OS (hedef) |
|---|---|---|
| Disk imajı | ~4 GB | ~50 MB |
| Background daemon | ~40 | 3-5 |
| Açık port (default) | 6+ | 0 |
| Persistence riski | Yüksek (mutable rootfs) | Yok (dm-verity + read-only) |
| Supply chain | Geniş (binlerce paket) | Dar (~30-50 paket, pinli) |

Suderra OS hedef mimarisi şunları sağlar. Uygulama durumu için release evidence ve readiness gate'leri esas alınır:

- **Immutable rootfs** + `dm-verity` ile kriptografik bütünlük
- **UEFI Secure Boot** zinciri (shim → kernel → initramfs)
- **A/B partition + RAUC OTA** — bozuk update otomatik geri döner
- **Minimal saldırı yüzeyi** — sadece uygulamanın ihtiyaç duyduğu paketler
- **Sertleştirilmiş kernel** — lockdown, KASLR, modules-off, syscall filtering
- **seccomp + capabilities** — uygulama RCE alsa bile izole
- **SBOM (CycloneDX)** + reproducible build — supply chain güveni
- **IEC 62443 SL2 / CRA hazırlığı**

## Quick Start

> Bu komutlar lab/dev image'leri içindir. Production release için [docs/operations/release-lifecycle.md](docs/operations/release-lifecycle.md) kapıları geçmelidir.

```bash
# 1. Geliştirme ortamı kurulumu
./scripts/build-in-docker.sh --help

# 2. QEMU için x86_64 imaj build
make build-qemu

# 3. QEMU'da çalıştır
./scripts/qemu-run.sh

# 4. Raspberry Pi 4 / CM4 için
./scripts/build-in-docker.sh suderra_aarch64_rpi4_defconfig
sudo ./scripts/flash-sd.sh /dev/sdX \
  output/suderra_aarch64_rpi4_defconfig/images/suderra-rpi4-target.img.xz

# 5. Endüstriyel x86 için (Faz 2-C)
./scripts/build-in-docker.sh suderra_x86_64_defconfig
sudo ./scripts/flash-sd.sh /dev/sdX \
  output/suderra_x86_64_defconfig/images/disk.img.xz
```

**Kurulum rehberi (adım adım, sıfırdan):** [docs/operations/install.md](docs/operations/install.md)

## Desteklenen Hardware

| Platform | Durum | Defconfig | Image |
|---|---|---|---|
| QEMU x86_64 (test) | ✅ Faz 1 | `suderra_qemu_x86_64_defconfig` | `disk.img` |
| Raspberry Pi 4 Model B | ✅ Faz 2-A | `suderra_aarch64_rpi4_defconfig` | `suderra-rpi4-target.img.xz` |
| Pi 4 / CM4 / RevPi USB installer | ✅ Alpha/lab | `suderra_aarch64_rpi4_usb_installer_defconfig` | `suderra-pi-cm4-revpi-usb-installer.img.xz` |
| Compute Module 4 (CM4) | ✅ Faz 2-A | `suderra_aarch64_rpi4_defconfig` | `suderra-rpi4-target.img.xz` |
| Endüstriyel x86 PC (UEFI+TPM) | ⏳ Faz 2-C | `suderra_x86_64_defconfig` | `disk.img.xz` |
| RevPi Connect 4 | ✅ Faz 2-B | `suderra_aarch64_revpi4_defconfig` | `suderra-revpi4-target.img.xz` |

Hardware detayı: [docs/hardware/rpi4-cm4.md](docs/hardware/rpi4-cm4.md)

## Mimari

### Hedef mimari

Aşağıdaki diyagram **hedef** güvenlik mimarisidir; hangi varyantın bugün ne
sağladığı bir sonraki tabloda ve `ci/build-matrix.yml` blocker alanlarında
izlenir.

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

### Bugünkü güvenlik durumu (varyant bazında)

Tek doğruluk kaynağı `ci/build-matrix.yml` (profil + blocker alanları); bu
tablo onun okunabilir özetidir:

| Varyant | Kernel sertleştirme | dm-verity | Signed boot | A/B OTA | Eksikler (blocker) |
|---|---|---|---|---|---|
| `qemu_x86_64` (dev/CI) | yok (dev kernel) | yok | yok | yok | dev/lab imajı — production iddiası yok |
| `x86_64`, `qemu_x86_64_prod_ab` | ortak fragment (lockdown zorunlu, modules-off) | partition layout hazır | UEFI UKI hedefli | RAUC hedefli | HSM, runtime-v2 ve donanım kanıtı |
| `rpi4`, `revpi4` | boot-güvenli arm64 fragmenti (lockdown derli/zorlamasız, **modules açık**) | kernel hazır, imaj **kullanmıyor** | yok (signed-FIT bekliyor) | yok | signed-FIT + dm-verity + RAUC + donanım kanıtı |
| `usb_installer` | boot-güvenli arm64 fragmenti | yok | payload Ed25519 imzalı | — | prod key policy + flash kanıtı |

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
- **USB installer alpha validation:** [docs/operations/usb-installer-alpha-validation.md](docs/operations/usb-installer-alpha-validation.md)
- **Release lifecycle:** [docs/operations/release-lifecycle.md](docs/operations/release-lifecycle.md)
- **CI warning triage:** [docs/operations/ci-log-and-warning-triage.md](docs/operations/ci-log-and-warning-triage.md)
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
