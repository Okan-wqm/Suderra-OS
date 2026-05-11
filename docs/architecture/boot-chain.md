# Suderra OS — Boot Zinciri

> **Status:** Skeleton. Detaylı sequence diyagramı ve doğrulama adımları Faz 3 (sertleştirme) içinde dolacak.

## Boot adımları (x86_64 / UEFI)

```
┌─────────────────────┐
│ 1. UEFI Firmware    │  TPM 2.0 PCR0-PCR7 ölçülür
└──────────┬──────────┘  Secure Boot enabled, PK enrolled
           │
           ↓ doğrular (PK/KEK)
┌─────────────────────┐
│ 2. shim.efi         │  Microsoft veya kendi MOK imzalı
│    (UEFI loader)    │  Suderra KEK'i ile chain
└──────────┬──────────┘
           │
           ↓ doğrular (Suderra db key)
┌─────────────────────┐
│ 3. systemd-boot     │  veya GRUB2 (Suderra imzalı)
│    (loader)         │  
└──────────┬──────────┘
           │
           ↓ doğrular (kernel imzası)
┌─────────────────────┐
│ 4. Linux kernel     │  kernel + initramfs (FIT image)
│    + initramfs      │  cmdline: root=/dev/...,
│                     │           dm-verity-hash=<sha256>,
│                     │           lockdown=confidentiality
└──────────┬──────────┘
           │
           ↓ doğrular (Merkle tree)
┌─────────────────────┐
│ 5. dm-verity        │  rootfs.A (erofs, read-only)
│    (rootfs check)   │  Her blok okumada hash kontrol
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 6. systemd PID 1    │  multi-user.target
│    minimal init     │  - journald
│                     │  - udev
│                     │  - chrony
│                     │  - nftables
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 7. firstboot.svc    │  (sadece ilk boot)
│                     │  TPM-sealed config aç
│                     │  /data initialize
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 8. edge-agent.svc   │  Type=notify, READY=1 ≤ 5sn
│                     │  WatchdogSec=60s
│                     │  ProtectSystem=strict
└─────────────────────┘
```

## Boot adımları (aarch64 / U-Boot)

```
┌─────────────────────┐
│ 1. ROM bootloader   │  SoC mask ROM (Pi: bootcode.bin)
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 2. U-Boot SPL       │  imzalı (FIT image trust)
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 3. U-Boot           │  FIT image doğrular
│                     │  Verified boot enabled
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ 4. FIT image        │  kernel + DTB + initramfs
│    (imzalı)         │  Tek monolithic, imzalı
└──────────┬──────────┘
           │
           ↓ dm-verity
           ... (5-8 x86 ile aynı) ...
```

## Anahtar Yönetimi (özet)

| Anahtar | Konum | Saklayan | Lifecycle |
|---|---|---|---|
| **PK** (Platform Key) | UEFI firmware | OEM veya cihaz sahibi | Cihaz ömrü boyunca |
| **KEK** (Key Exchange Key) | UEFI db | Suderra root | 10 yıl |
| **db key** (image signing) | UEFI db | Suderra (HSM) | 2-3 yıl rotation |
| **Kernel signing key** | scripts/sign | Suderra (HSM) | 2-3 yıl rotation |
| **RAUC bundle key** | scripts/sign | Suderra (HSM) | 2-3 yıl rotation |
| **dm-verity root hash** | Kernel cmdline (signed) | Her build'de yeni | Build başına |
| **TPM SRK** | TPM chip | Cihaz başına unique | Cihaz ömrü |

Detay: [../security/key-management.md](../security/key-management.md)

## Anti-Tamper Garantileri

| Saldırı | Koruma |
|---|---|
| Disk değiştir/swap | dm-verity hash kernel'de imzalı → boot reddedilir |
| Bootloader değiştir | shim imza zinciri → UEFI reddeder |
| Kernel değiştir | Kernel imzası shim tarafından doğrulanır |
| initramfs değiştir | FIT image içinde imzalı (ARM) veya unified kernel (x86) |
| Cmdline değiştir | Kernel imzasının bir parçası, değiştirilemez |
| Çalışma anında rootfs yaz | erofs read-only + dm-verity her okumada |
| /etc içinde persistence | rootfs RO, /etc değişmez; /data ayrı ve uygulama-spesifik |
| Reboot ile saldırgan kaybolur | Boot her zaman temiz state'ten başlar |

## Test Senaryoları (Faz 3)

`tests/security/verity-tamper-test.sh` (oluşturulacak):
1. Imaj build, normal boot
2. rootfs.A imajına 1 byte değiştir
3. Reboot
4. **Beklenen:** Kernel "verity: verification failure" hata verir, sistem durur veya rollback eder
5. **Pozitif test:** Düzgün imaj geri yüklenince boot devam eder

## Açık Konular (Faz 3'te netleşecek)

- shim vs sd-stub: hangisi kullanılacak
- MOK enrollment kullanıcı tarafından yapılacak mı (yoksa OEM PK)
- TPM-sealed disk encryption mı, passphrase mi
- Measured boot attestation (uzak doğrulama) hedefte mi
- Rollback protection (versioned signing) ne zaman eklenecek
