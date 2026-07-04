# ADR-0007: ARM (Pi 4 / CM4 / RevPi) doğrulanmış boot + dm-verity + A/B zinciri

- **Status:** Proposed
- **Date:** 2026-07-02
- **Deciders:** @okan-wqm
- **Tags:** security, boot, verity, ota, hardware

## Context

x86 production hattı UEFI/UKI + dm-verity + RAUC mimarisine sahipken ARM
hattı (rpi4, revpi4, usb-installer) bugün düz, imzasız, tek-slot imaj sevk
ediyor. `ci/build-matrix.yml` bunu blocker alanlarıyla dürüstçe işaretliyor
(`signed-fit-dm-verity-rauc-and-hardware-evidence-missing`), README varyant
tablosu da aynı boşluğu gösteriyor.

ARM'da x86'daki zincir birebir kopyalanamaz:

- Pi 4/CM4/RevPi Connect 4'te UEFI Secure Boot yok; ilk aşama (GPU firmware
  → `bootcode`/EEPROM) **doğrulanamaz** ve Broadcom'a kapalıdır.
- BCM2711'de vendor imza zorlaması pratikte kullanılamaz; kök güven ancak
  U-Boot'tan itibaren kurulabilir.
- RevPi Connect 4'te SPI TPM 2.0 (SLB9670 serisi) var; Pi 4'te TPM yok.
- Kernel tarafı hazırlığı tamam: `linux-rpi4-hardening.config` DM_INIT,
  DM_VERITY(+FEC), DM_CRYPT ve TPM SPI sürücülerini içeriyor (Phase 2a).

Bu depoda ARM imajı **derlenip boot'lanarak doğrulanamaz**; yanlış partition
düzeni veya kernel/U-Boot kombinasyonu sahadaki cihazı brick edebilir. Bu
yüzden uygulama, aşağıdaki kanıt kapılarına bağlanır ve her adım GitHub
Actions'ta ya da donanım lab'ında kanıtlanmadan bir sonrakine geçilmez.

## Decision

**U-Boot'u güven kökü yaparak kısaltılmış zincir:**

```
GPU firmware + EEPROM  (DOĞRULANAMAZ — kabul edilen risk, aşağıda)
    ↓ yükler (FAT boot bölümü)
U-Boot (CONFIG_FIT_SIGNATURE=y, embedded RSA pubkey, env yazma kilitli)
    ↓ imza doğrular
Signed FIT = kernel + DTB + initramfs (+ bootargs: verity root hash)
    ↓ initramfs, dm-verity map eder
dm-verity rootfs (RO, squashfs/erofs) — slot A veya B
    ↓
systemd + RAUC (U-Boot boot-count/bootargs backend ile slot seçimi)
    ↓
/data: LUKS2 — RevPi'de TPM2-sealed anahtar, Pi 4'te dosya-tabanlı anahtar
        (daha zayıf; tabloda açıkça işaretlenir)
```

**Partition düzeni (MBR — Pi firmware FAT boot bölümü ister):**

| # | Bölüm | İçerik |
|---|---|---|
| 1 | `boot` (FAT32) | RPi firmware, U-Boot, config.txt; FIT imajları A/B |
| 2 | `rootfs-a` | dm-verity korumalı RO rootfs (slot A) |
| 3 | `rootfs-b` | slot B (ilk flash'ta boş, RAUC sahipliğinde) |
| 4 | `verity-a` / `verity-b` + `data` (extended) | Merkle ağaçları + LUKS2 /data |

**Kabul edilen risk:** İlk aşama (GPU firmware) imzasız kalır. Fiziksel
SD-swap saldırısına karşı tam koruma ancak vendor secure-boot olan
platformlarda mümkün; tehdit modelinde "ARM hattı: fiziksel erişimli
saldırgan boot zincirinin ilk aşamasını değiştirebilir" olarak kayda girer.
U-Boot sonrası her aşama kriptografik doğrulanır.

## Kanıt kapıları (gate'ler)

Her kapı geçilmeden `ci/build-matrix.yml` blocker'ı sökülmez ve bir sonraki
kapının işi başlamaz:

| Gate | Ne kanıtlanır | Nerede |
|---|---|---|
| G0 (bugün) | Kernel verity/TPM hazırlığı + fragment sözleşmesi | Actions: defconfig parse + `arm-hardening-contract-test.sh` |
| G1 | U-Boot FIT_SIGNATURE build + imzalı FIT üretimi; `mkimage -l`/pubkey doğrulaması | Actions: rpi4 build job'ına eklenecek contract adımı |
| G2 | Yeni genimage düzeni + host-side `veritysetup verify` artifact üstünde | Actions: image-contract adımı |
| G3 | QEMU aarch64 (virt + U-Boot) ile FIT imza reddi/kabulü smoke | Actions |
| G4 | Pi 4/CM4/RevPi gerçek boot, RAUC A/B switch + rollback, güç kesme testi | Donanım lab; kanıt mevcut release-evidence hattına yazılır |
| G5 | LUKS2 /data: RevPi TPM2 seal/unseal, Pi 4 keyfile akışı | Donanım lab |

`production_ready` ancak G4+G5 kanıtı release-evidence'ta saklandığında
tartışılır (x86 hattıyla aynı politika).

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Neden seçilmedi |
|---|---|---|---|
| A: TianoCore UEFI (RPi4) + shim + x86 zinciriyle aynı yol | x86 ile tek mimari | RPi UEFI portu endüstriyel olgunlukta değil; DT/donanım desteği eksik | Olgunluk riski |
| B: RPi firmware doğrudan kernel yükler (bugünkü durum + verity) | Basit | Kernel imzası hiç doğrulanmaz; verity hash'i korumasız cmdline'da | Kök güven yok |
| C: U-Boot + signed FIT (seçilen) | Kernel+DTB+initramfs+cmdline imza altında; RAUC'un U-Boot backend'i hazır | İlk aşama yine imzasız; U-Boot bakım yükü | — |

## Consequences

- Yeni genimage cfg'leri ve `post-image.sh` ARM dalı; USB installer payload
  düzeni değişir (installer sözleşme testleri güncellenecek).
- initramfs gerekir (bugün ARM imajlarında yok) — boyut bütçesi ~4-6 MB.
- FIT imza anahtarı `docs/security/key-management.md` ve key-ceremony
  sürecine eklenir; CI'da yalnız lab anahtarı, prod anahtar HSM'de.
- RAUC system.conf ARM slot tanımları ve U-Boot env alanı eklenir
  (ADR-0004'ün ARM somutlaması).
- ADR-0005'in "UEFI Secure Boot" bölümü x86'ya özgü kalır; bu ADR ARM
  karşılığıdır (ADR-0005'i değiştirmez, tamamlar).

## Production build lane (PR-A9)

ARM prod imajı, x86 desenini (ayrı `_prod_ab` defconfig) izleyen ayrı, gated bir
hatta kurulur:

- **`configs/suderra_aarch64_{rpi4,revpi4}_prod_ab_defconfig`** — `VARIANT_PROD`,
  kilitli appliance (dropbear/getty yok). Dev `rpi4`/`revpi4` defconfig'leri
  DOKUNULMAZ; her-PR standart Image Build yeşil kalır. Prod hedefler
  `ci/build-matrix.yml`'de `image_build: false` ile standart build'den hariç
  tutulur (tıpkı `qemu_x86_64_prod_ab`).
- **`.github/workflows/arm-production-build.yml`** — `workflow_dispatch`, korumalı
  `production-runtime` environment. `SUDERRA_SIGNING_MODE=prod` FIT/imaj/RAUC
  imzalamasını **PKCS#11/HSM** anahtarına zorlar (`need_signing_key` dosya
  anahtarını reddeder). Gerçek imzalı build yalnız HSM signing material
  sağlandığında koşar; SoftHSM audited gate (`validate-hsm-signing-evidence.py`
  softhsm negatif kontrolü + allowlist) tarafından reddedilir.
- **`ci/evidence-contract.yml`** — `rpi4-prod-ab`/`revpi4-prod-ab` OTA hedefleri
  `backend: uboot-rauc`, `ota_capable: true`, U-Boot env monotonic rollback.
- `production_ready` tüm prod hedeflerde `false` kalır; gerçek donanım kanıtı
  (G4/G5, A10/A11) release/ingress join'de gelene dek fail-closed.
