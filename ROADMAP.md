# Suderra OS — Roadmap

> **Aktif Faz:** Faz 0 tamam → **Faz 1 girişi** (Buildroot + ilk boot)
>
> **Toplam tahmini süre:** Yarı-zamanlı tek geliştirici için 5-7 ay (Faz 1 → Pilot)
>
> Bu doküman canlıdır. Her faz sonunda revize edilir.

## Felsefe: Rust-first userspace, C base layer

Rust **her yerde değil** — pragmatik:

| Katman | Dil | Sürdürüce | Neden |
|---|---|---|---|
| Bootloader (GRUB / U-Boot) | C | Upstream | Stable, production-ready alternatif yok |
| Linux kernel 6.12 LTS | C | Upstream | Kernel Rust deneysel; modüller zaten kapalı |
| musl libc | C | Upstream | Buildroot core |
| systemd minimal | C | Upstream | Edge Agent `Type=notify` + `sd-notify` zorunlu |
| nftables, chrony, RAUC | C | Upstream | Olgun, wrap edilir |
| **Suderra userspace** | **Rust (musl static)** | **Bizim** | **Memory safety = güvenlik tezi** |
| **uutils (opsiyonel BusyBox replace)** | **Rust** | **Upstream** | **Faz 5+ stratejik değerlendirme** |

## Yapı

```
suderra-os/         (bu repo)              userspace/  (Rust workspace, bu repo içinde)
├── configs/                                ├── Cargo.toml
├── board/                                  ├── suderra-firstboot/
├── package/   (Buildroot reçeteleri)       ├── suderra-ota/
├── docs/                                   ├── suderra-telemetry/
└── userspace/ ───────────────────────►     ├── suderra-watchdog/
                                            ├── suderra-factory-reset/
                                            ├── suderra-attestation/
                                            └── suderra-config/

aquaculture_platform/sens-api-gateway       (ayrı repo, submodule veya cargo source)
└── Suderra Edge Agent (mevcut Rust app, IEC 62443 SL2 hazırlıklı)
```

## Faz 1 — İlk Bootable İmaj (2-3 hafta)

**Hedef:** QEMU'da `Suderra OS v0.1.0-alpha` banner ile boot eden imaj + gerçek x86_64 endüstriyel donanımda boot testi.

### İçerik

- [ ] Buildroot 2024.11 LTS `git submodule` olarak ekle
- [ ] `configs/suderra_qemu_x86_64_defconfig` doldur:
  - Arch: x86_64, musl, kernel 6.12 LTS
  - Init: BR2_INIT_SYSTEMD=y (minimal)
  - BusyBox minimal
  - SSH (sadece DEV) + serial console
- [ ] Kernel config: hardware driver'lar
- [ ] `scripts/build-in-docker.sh suderra_qemu_x86_64_defconfig` çalışır
- [ ] `scripts/qemu-run.sh` ile boot
- [ ] `cat /etc/os-release` → `Suderra OS v0.1.0-alpha`
- [ ] CI'da QEMU smoke test (boot-test.sh) yeşil
- [ ] Hedef x86 endüstriyel donanımda boot (Advantech UNO veya seçilen model)
- [ ] `configs/suderra_aarch64_defconfig` placeholder dolu (boot etmese de)

### Doğrulama

- `make build-qemu` ≤ 30 dk
- QEMU boot ≤ 60 sn
- `tests/qemu/boot-test.sh` PASS
- Reproducible build doğrulanmış (`scripts/verify-reproducible.sh`)

### Çıktı

- `output/suderra_qemu_x86_64_defconfig/images/disk.img` (~80-100 MB ilk denemede)
- Buildroot manifest (`legal-info/`)

## Faz 1.5 — Rust Userspace Workspace (1 hafta)

**Hedef:** Suderra-OS-spesifik Rust crate'leri için workspace.

### İçerik

- [x] `userspace/Cargo.toml` (workspace root) [Faz 0 sonu]
- [x] Crate iskeletleri: firstboot, ota, telemetry, watchdog, factory-reset
- [ ] `userspace/.cargo/config.toml` — musl cross-compile (x86_64 + aarch64)
- [ ] CI'da `cargo build --target x86_64-unknown-linux-musl --release`
- [ ] CI'da `cargo test`, `cargo clippy`, `cargo audit`
- [ ] `cargo-deny.toml` — lisans + advisory enforcement
- [ ] İlk crate çalışır: `suderra-firstboot --help`

### Build Stratejisi

Userspace crates Buildroot tarafından paketlenir (`package/suderra-firstboot/suderra-firstboot.mk`).
Buildroot host-rustc kullanır, musl target ile cross-build.

## Faz 2 — Edge Agent + İlk Custom Crate (2-3 hafta)

**Hedef:** Mevcut Edge Agent boot sonrası 5sn'de active + ilk Suderra Rust crate'i (`suderra-firstboot`) çalışıyor.

### İçerik

- [ ] `package/suderra-edge-agent/suderra-edge-agent.mk` doldur (Cargo build)
- [ ] Edge Agent statik binary, `/usr/bin/suderra-edge-agent`
- [ ] systemd unit deploy (mevcut hardened unit)
- [ ] `suderra-firstboot` Rust implementasyonu:
  - Boot sonrası `/data` mkfs + mount
  - `/etc/machine-id` generate (yoksa)
  - Cloud provisioning placeholder
  - `rauc status mark-good` (health check sonrası)
- [ ] Modbus PLC simulator ile end-to-end test
- [ ] 24 saat stres test (memory leak yok)

### Doğrulama

- `systemd-analyze` blame ≤ 8s
- `journalctl -u suderra-edge-agent` → READY=1 < 5s
- PLC'den veri okuma → cloud broker'a publish
- `tests/qemu/app-startup-test.sh` PASS

## Faz 3 — Güvenlik Sertleştirme (3-4 hafta)

**Hedef:** Production-grade güvenlik. Lynis 85+, nmap'te 0 port.

### İçerik (öncelik sırası)

- [ ] Read-only rootfs (erofs veya squashfs)
- [ ] dm-verity aktive (kernel cmdline + hash signing)
- [ ] Secure Boot zinciri (dev keys ile)
- [ ] Kernel sertleştirme (kernel-fragment.config tam aktif)
  - `lockdown=confidentiality`, KASLR, modules-off, KPTI, SMEP/SMAP
- [ ] systemd hardening directives doğrulanmış
  - `systemd-analyze security suderra-edge-agent` < 2.0
- [ ] seccomp BPF profili Edge Agent için
- [ ] nftables tam aktive (default DROP)
- [ ] TPM 2.0 entegrasyon (QEMU swtpm ile test)
- [ ] LUKS2 /data encryption (TPM-sealed)
- [ ] `tests/security/lynis-baseline.sh` ≥ 85
- [ ] `tests/security/nmap-external.sh` → 0 port
- [ ] `tests/security/verity-tamper-test.sh` → kernel reddeder

### Çıktı

- Sertleştirilmiş PROD variant imajı (~50-60 MB)
- Detaylı `docs/security/kernel-hardening.md`
- İlk threat model revisionu

## Faz 4 — OTA Sistemi (2-3 hafta)

**Hedef:** Sahada güvenli + geri dönülebilir update. Bozuk update otomatik rollback.

### İçerik

- [ ] RAUC integration: `BR2_PACKAGE_RAUC=y`
- [ ] A/B partition layout (genimage.cfg)
- [ ] `suderra-ota` Rust crate:
  - Bundle download (HTTPS + mTLS)
  - rauc wrapping (FFI veya CLI çağrısı)
  - Health check coordination
  - Rollback trigger logic
- [ ] Bundle imzalama: `scripts/sign-bundle.sh` aktif
- [ ] Cosign keyless artifact signing (release.yml zaten hazır)
- [ ] SLSA L3 provenance (slsa-provenance.yml aktif)
- [ ] Update sunucu setup (HTTPS, basit file server)
- [ ] `tests/ota/update-rollback-test.sh` → 10× update + 1 bozuk → rollback

### Doğrulama

- 10 başarılı update + 1 bozuk update → otomatik rollback
- İmza tampering → bundle reddedilir
- Downgrade → reddedilir
- Network down → graceful retry

## Faz 5 — Operasyonel Olgunluk (2-3 hafta)

**Hedef:** Sahada cihaz sorun yaşarsa masandan görüyorsun + müdahale ediyorsun.

### İçerik

- [ ] `suderra-telemetry` Rust crate:
  - CPU, RAM, disk, sıcaklık, uptime
  - Edge Agent metrikleri (Modbus read rate, MQTT publish, errors)
  - JSON structured push (cloud endpoint)
- [ ] `suderra-watchdog` Rust crate:
  - Hardware watchdog driver
  - Kernel panic → otomatik reboot
  - Edge Agent crash → systemd restart + telemetry alert
- [ ] Remote syslog: journald → upstream (vector, fluent-bit, veya rsyslog)
- [ ] Crash dump pipeline (`pstore` → upstream)
- [ ] `scripts/gen-sbom.sh` tam implementasyon (syft)
- [ ] SBOM CI artifact'i her release ile
- [ ] CycloneDX VEX template + iş akışı
- [ ] `suderra-factory-reset` Rust crate (GPIO + cloud komut)
- [ ] OpenSSF Best Practices Badge başvurusu (Passing)

### Doğrulama

- Cihaz offline olunca dashboard alert 5dk içinde
- Crash sonrası otomatik raporlama
- SBOM her release artifact'ine eklenmiş
- `cosign verify-blob` PASS (her artifact)

## Faz 6 — Test + Sertifikasyon Hazırlığı (3-4 hafta)

**Hedef:** Müşteriye sunulabilir test raporları + IEC 62443-4-2 / CRA gap analizi tamamlanmış.

### İçerik

- [ ] 30 gün stres testi (lab)
- [ ] Güç kesintisi testi (100× ani güç kesme, fs bozulması yok)
- [ ] Sıcaklık testi (donanım üreticisinin spec'ine göre, varsa lab)
- [ ] EMC ön test (lab erişimi varsa)
- [ ] **İç pen-test** (`docs/security/pen-test-checklist.md` tam koş)
- [ ] **Dış pen-test** (3. parti firma, ~50-100k TL)
- [ ] `docs/compliance/cra-annex-i-checklist.md` her madde için kanıt dosyası
- [ ] `docs/compliance/iec-62443-4-2-component-requirements.md` her CR için kanıt
- [ ] CRA technical documentation paketi hazır
- [ ] CE Declaration of Conformity (`eu-doc-template.md`) doldurulmuş
- [ ] OpenSSF Best Practices Badge → Silver
- [ ] HSM seçimi ve setup (YubiHSM 2 veya AWS KMS)
- [ ] Production signing keys generation (cold ceremony)

### Çıktı

- Test raporları PDF
- Bilinen sorunlar listesi
- Sertifikasyon-ready dokümantasyon paketi
- ADR-0006 review (SL2 hala doğru mu?)

## Faz 7 — Pilot Saha (4-6 hafta)

**Hedef:** 1-3 cihaz gerçek müşteride, 30 gün yakın takip.

### İçerik

- [ ] 1-2 mevcut müşteride pilot kurulum
- [ ] Cihaz başına unique mTLS cert (factory provisioning)
- [ ] 30 gün telemetri günlük inceleme
- [ ] Her sorun → issue tracker
- [ ] Haftalık OTA güncelleme döngüsü
- [ ] Müşteri geri bildirim toplantıları
- [ ] Pilot sonu rapor: üretim onayı veya "şunları çöz" listesi

### Karar Noktası: SL2 vs SL3

Pilot sonrası ADR-0006 yeniden değerlendirilir:

- Müşteri profili → SL3 trigger var mı?
- Tehdit modeli ne kadar gerçekleşti?
- SL3 sertifikasyon investment'ı haklı mı?

## Faz 8+ — İleri (opsiyonel)

Pilot başarılıysa açılır:

| Konu | Süre | Faz |
|---|---|---|
| Multi-arch (aarch64 production) | 4-6 hafta | 8 |
| BusyBox → uutils (Rust coreutils) | 2-3 hafta | 8 |
| `suderra-attestation` (TPM PCR remote attestation) | 3-4 hafta | 8 |
| IEC 62443 SL3 upgrade | 6-12 ay | 9 |
| Notified Body sertifikasyon | 12-18 ay | 9 |
| Delta OTA (bandwidth optimization) | 2-3 hafta | 9 |
| Custom HMI (web UI, Rust + WebAssembly) | 4-6 hafta | 10 |
| Fleet management dashboard | 8-12 hafta | 10 |

## Bağımlılıklar / Açık Sorular

Faz 1 başlamadan önce netleşmesi gerekenler:

| Soru | Karar Tarihi | Sahibi |
|---|---|---|
| Hedef x86_64 endüstriyel PC modeli | Faz 1 başı | @okan-wqm |
| Hedef ARM SBC (Pi CM4 vs Revolution Pi) | Faz 1 sonu | @okan-wqm |
| Edge Agent repo: submodule mi, cargo source mi? | Faz 1.5 | @okan-wqm |
| Update sunucu hosting (VPS provider) | Faz 4 başı | @okan-wqm |
| HSM seçimi (YubiHSM 2 / AWS KMS / Thales) | Faz 4 öncesi | @okan-wqm |
| İlk pilot müşteri(ler) | Faz 6 sonu | @okan-wqm |
| Dış pen-test firması | Faz 6 başı | @okan-wqm |

## Maliyet Tahmini

| Kalem | Tahmini Maliyet (TL) | Faz |
|---|---|---|
| Geliştirme makinesi (varsa atla) | 0-30k | Faz 0 |
| Test cihazları (2-3 adet endüstriyel x86) | 30-60k | Faz 1 |
| ARM SBC (Pi CM4 / Revolution Pi) | 5-15k | Faz 1 sonu |
| TPM modülü (varsa cihazda dahil) | 0-5k | Faz 3 |
| YubiHSM 2 + 2× Yubikey yedek | 25-35k | Faz 4 |
| OTA VPS (yıllık) | 6-24k | Faz 4 |
| Dış pen-test | 50-100k | Faz 6 |
| Lab erişimi (EMC, sıcaklık — varsa) | 10-30k | Faz 6 |
| **IEC 62443-4-2 sertifikasyon** | **200-500k** | Faz 6 sonu / Üretim |
| **Notified Body (SL3 isenirse)** | **800-1500k** | Faz 9 (opsiyonel) |

## Risk Listesi (öncelikli)

| Risk | Olasılık | Etki | Mitigasyon | Faz |
|---|---|---|---|---|
| Hedef donanımda driver sorunu | Orta | Yüksek | Erken gerçek HW testi | Faz 1 |
| Buildroot Rust cross-compile sorunu | Orta | Orta | musl target çalışıyor, riskli paketler izolasyonda | Faz 1.5 |
| Edge Agent musl uyumsuzluğu (SQLCipher) | Düşük | Yüksek | Vendored OpenSSL ile build, Faz 2'de erken test | Faz 2 |
| Secure boot zinciri OEM ile koordinasyon | Yüksek | Orta | Faz 3 başında MOK fallback hazır | Faz 3 |
| OTA bozuk update fleet etkisi | Düşük | Çok yüksek | Faz 4'te kapsamlı rollback testi + canary | Faz 4 |
| HSM seçimi gecikme | Orta | Orta | Faz 4 başlamadan 2 hafta önce karar | Faz 3 |
| Sertifikasyon maliyeti bütçe sınırı | Yüksek | Orta | Faz 6 öncesi finansman planı | Faz 6 |
| Tek geliştirici bottleneck | Yüksek | Yüksek | CI/CD + dokümantasyon disiplini + ADR'lar | Tümü |

## Sonraki Adım

**Şimdi (Faz 1 girişi):**

1. Hedef x86_64 endüstriyel PC modelini kesinleştir
2. Buildroot 2024.11 LTS submodule olarak ekle
3. `configs/suderra_qemu_x86_64_defconfig` doldurmaya başla
4. İlk QEMU boot — `Suderra OS v0.1.0-alpha` banner

**Önerilen ilk task:** `git submodule add https://gitlab.com/buildroot.org/buildroot.git -b 2024.11 buildroot/`

## Revizyon Tarihçesi

| Tarih | Sürüm | Değişiklik |
|---|---|---|
| 2026-05-11 | v0.1 | İlk versiyon, Faz 0 tamamlanması sonrası |
