# Changelog

Bu dosyadaki tüm önemli değişiklikler [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
formatına ve [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kurallarına uyar.

## [Unreleased]

### Security — Denetim remediation dalgası (2026-07, PR #85)

**DİKKAT — OTA manifest imza formatı kırılımı:** imza algoritması
`ed25519-suderra-os-update-manifest-v1` → `-v2`. İmza baytları artık paylaşılan
sorted-key kanonik JSON'dur (`suderra-config::canonical`); eski manifest'ler
`scripts/create-os-update-manifest.py` ile yeniden imzalanmalıdır. Sahada cihaz
yok (`production_ready:false`) → dual-accept penceresi bilinçle eklenmedi.

- **AUD-4 / NEW-7:** OTA + installer imza kanonikalizasyonu tek paylaşılan forma
  birleştirildi; diller-arası golden vektörler + Python-imzalı→Rust-doğrulanan
  fixture. prod-varyant tespiti de `suderra-config::variant`'a çıkarıldı.
- **NEW-4:** agent unit'lerinden `/dev/watchdog`+`/dev/tpm0`+`/dev/tpmrm0`
  `DeviceAllow` kaldırıldı; `suderra-watchdog` ilk kez paketlendi (donanım
  watchdog'unun tek sahibi).
- **NEW-5:** `suderra-firewall` imzalı `VARIANT=prod` köküne çapalandı →
  prod'da appliance ruleset koşulsuz (SSH açık provisioning ruleset'ine
  düşülemez); NEW-2 egress allow-list'ini sahada etkin kılar.
- **C-6:** verify→use TOCTOU kapatıldı (installer tek-okuma; ota staged-verify).
- **C-7:** SemVer-dışı `VERSION_ID` build kapısı + install erken teşhisi.
- **RT-2/RT-3/RT-6 (ADR-0009):** TPM 2.0 yazılım tarafı — `suderra-config::tpm`
  subprocess sarmalayıcı, TPM-NV **ordinary-index** anti-rollback çıpası (`ota.conf`
  + `floor sync`; ilk `nt=counter` tasarımı kod incelemesinde gerçek TPM'de kırık
  bulunup ordinary-NV'ye çevrildi), attestation istemcisi (PCR quote), firstboot
  güven tesis durum makinesi + TPM-bağlı cihaz kimliği. Donanım/swtpm kanıtı G5'te.
  RT-2/RT-3 cihaz-üstü wiring (firstboot binary prod'da enable) BEKLİYOR — bkz. register.
- **Kod incelemesi düzeltmeleri:** prod-OTA-brick (floor.service `/run/suderra`
  namespace + firstboot'suz NV tanımı), firewall os-release-okunamaz fail-open,
  attestation AK-pinleme + PCR-format, stage_bundle başarısızlıkta bundle-geri-yükleme,
  anti-rollback floor kapısının install/mark-good'a sınırlanması (status/rollback açık).
- **AUD-5/9/10:** atıl QEMU collector prod imajlardan silindi; senkron
  binary'lerden tokio düşürüldü; `overflow-checks=true`.

### Changed — Faz 1 doğrulama PR'ı için CI tetikleyici

- Tüm 5 katman birikmiş `claude/hardened-linux-edge-os-cDH7d` branch'inde
- main branch yaratıldı (`mcp__github__create_branch` ile) ki PR diff sağlansın
- Bu commit PR diff'i için yapay tetikleyici (CHANGELOG note); ana iş önceki commit'lerde
- PR sonrası GitHub Actions runs subscribe edilecek

### Added — Faz 1 (CI Boot Smoke Test) — Katman 4

- `.github/workflows/build.yml` — `qemu-smoke-test` job eklendi:
  - `build` job tamamlandıktan sonra image artifact'i indirir
  - KVM acceleration tespit (`/dev/kvm`); yoksa QEMU TCG fallback
    (timeout cömertçe 180s)
  - `tests/qemu/boot-test.sh` ile boot doğrulama
  - Boot fail'inde serial log artifact upload (7 gün)
- GitHub Actions runner'larında nested KVM destekli (Ubuntu 24.04, 2023+)

### Added — Faz 1 (Altyapı Tamamlama) — Katman 5

**Boot için kritik eksiklikler dolduruldu:**
- `board/suderra/common/users.txt` — defconfig'lerin referans verdiği dosya
  (yokken Buildroot kırılıyordu); `suderra-edge` UID 200 reproducible
- `board/suderra/x86_64/genimage-qemu.cfg` — QEMU için tek-rootfs layout
  (EFI 32M + rootfs 256M); production'ın A/B+/data karmaşıklığı smoke test'i
  90s timeout'a sığmıyor
- `post-image.sh` — placeholder yorum yerine **çalışan genimage çağrısı**,
  defconfig adına göre QEMU vs production layout otomatik seçer

**Systemd unit'leri:**
- `rootfs-overlay/etc/systemd/system/suderra-firstboot.service` — oneshot,
  ConditionPathExists ile bir kere çalışır:
  - `/etc/machine-id` üretir
  - `/data` partition mkfs (varsa)
  - `/var/lib/suderra` dizini + sahiplik
  - `/etc/suderra/config.yaml` skeleton

**Dependabot:**
- Cargo ecosystem (`/userspace`) **günlük** tarama (önceden yorumda)
- Minor+patch grup PR (rust-minor-patch); major bump'lar (tokio/axum/rustls)
  manuel review
- `gitsubmodule` ecosystem ile Buildroot submodule **aylık** kontrol

**REUSE compliance:**
- Tüm `userspace/**/Cargo.toml` + `userspace/**/*.rs` dosyalarına SPDX header
  (Apache-2.0)

**Dokümantasyon:**
- `docs/operations/build.md`: Disk image layout tablosu + users.txt formatı
- `docs/dev/qemu-test.md`: QEMU disk layout + firstboot davranışı
- `docs/dev/rust-workspace.md`: Dependabot kuralları + SPDX/REUSE bölümleri

### Added — Faz 1 (QEMU Boot Hazırlığı) — Katman 3

**Kernel config (Faz 1 minimal):**
- `board/suderra/x86_64/linux-x86_64.config` — placeholder'dan ~150 satır gerçek config'e:
  - QEMU desteği: virtio-net, virtio-blk, virtio-pci, virtio-rng
  - Gerçek HW desteği: Intel I210/I225/I226 (TSN/PTP), iTCO watchdog, TPM TIS/CRB
  - UEFI + EFI_STUB
  - SLAB hardening, FORTIFY_SOURCE, KASLR, KPTI, RANDOMIZE_KSTACK
  - memfd_secret (Edge Agent zorunlu)
  - Disable: Bluetooth, WLAN, NFC, RDS, DCCP, SCTP, X25 (saldırı yüzeyi)
  - AES-NI hardware crypto acceleration

**Bootloader:**
- `board/suderra/x86_64/grub-qemu.cfg` — QEMU için single-rootfs (vs production A/B)
- Kernel cmdline: slab_nomerge, init_on_alloc, randomize_kstack_offset, oops=panic

**Boot test (CI-ready):**
- `tests/qemu/boot-test.sh` — 90s timeout, 4 doğrulama:
  - "Suderra OS" banner var
  - Kernel panic yok
  - systemd başlatma görüldü
  - Login prompt / target hazır
- CI'da regression detection (her PR'da koşar)

**Dokümantasyon:**
- `docs/dev/qemu-test.md` — gerçek talimatlar:
  - Beklenen boot output örneği
  - Boot aşaması süre tablosu (~30-60s cold boot)
  - Kernel config kritik açıklamaları
  - swtpm + UEFI Secure Boot test setup

### Added — Faz 1 başı (Buildroot Submodule + Defconfig Fill) — Katman 2

**Buildroot integration:**
- `buildroot/` git submodule (gitlab.com/buildroot.org/buildroot, branch 2025.05.x)
- `.gitmodules` — submodule pin (SHA = reproducible build için kritik)
- `.gitignore` — `/buildroot/output/` ve `/buildroot/dl/` ignore (kaynak tracked)

**Defconfig'ler doldurulduk:**
- `configs/suderra_qemu_x86_64_defconfig` — minimal çalışan içerik:
  - musl static + Rust 6.12 LTS kernel + minimal systemd
  - GRUB2 BIOS (QEMU için), ext4 rootfs
  - Reproducible build (BR2_REPRODUCIBLE=y)
  - chrony NTP, networkd, journald
- `configs/suderra_x86_64_defconfig` — endüstriyel x86 PC:
  - Custom kernel config (board-spesifik driver'lar Faz 1'de)
  - GRUB2 EFI (UEFI Secure Boot Faz 3'te), nftables, linuxptp
- `configs/suderra_aarch64_defconfig` — ARM SBC:
  - U-Boot + custom kernel config + DTB
  - Cortex-A72 (Pi CM4 / Revolution Pi default)

**Dokümantasyon:**
- `docs/dev/setup.md` — git clone --recurse-submodules talimatı + submodule güncelleme prosedürü
- `docs/operations/build.md` — Buildroot submodule kullanımı + doğrudan make komutları

### Added — Faz 1.5 (Rust Userspace Workspace) — Katman 1

**Userspace iskelet:**
- `userspace/` Cargo workspace (resolver=2, 7 member crate)
- `userspace/Cargo.toml` — workspace metadata + paylaşılan dependency'ler (tokio, rustls, serde, tracing)
- `userspace/.cargo/config.toml` — musl cross-compile (x86_64 + aarch64), linker config, alias'lar
- `userspace/rust-toolchain.toml` — Rust 1.86.0 pinned (reproducible build için)
- `userspace/deny.toml` — cargo-deny config: lisans whitelist (Apache/MIT/BSD), GPL/OpenSSL ban, CVE check
- `userspace/README.md` — workspace açıklama + cross-compile rehberi

**7 crate iskelet (her birinde Cargo.toml + main.rs/lib.rs + README):**
- `suderra-config` (lib) — ortak config parser + validation (faz 2'de doldurulur)
- `suderra-firstboot` (binary) — ilk boot provisioning (faz 2)
- `suderra-ota` (binary) — RAUC orchestrator (faz 4)
- `suderra-telemetry` (binary) — metrics push (faz 5)
- `suderra-watchdog` (binary) — hw watchdog + health monitor (faz 5)
- `suderra-factory-reset` (binary) — GPIO/cloud reset handler (faz 5)
- `suderra-attestation` (binary) — TPM PCR remote attestation (faz 8+)

**CI/CD:**
- `.github/workflows/rust.yml` — 4 job: check (fmt+clippy+test), build-musl (x86_64+aarch64), security (audit+deny), msrv
- Binary boyut raporu (GitHub Step Summary)

**Buildroot entegrasyonu:**
- `package/suderra-firstboot/suderra-firstboot.mk` — userspace/suderra-firstboot referansına güncellendi
- Cargo workspace içinde build, BR2_RUSTC_TARGET_NAME ile musl cross-compile

**Dokümantasyon:**
- `docs/dev/rust-workspace.md` — detaylı geliştirici rehberi (cross-compile, test stratejisi, Buildroot entegrasyon)
- README repo yapısı güncellendi (userspace/ eklendi)

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
