# Suderra OS — Sistem Mimarisi

> **Status:** Faz 0 (iskelet). Detaylı diyagramlar Faz 1 başında doldurulacak.

## Mimari Görünüm (yüksek seviye)

```
┌──────────────────────────────────────────────────────────────────┐
│                     KULLANICI / OPERASYON                        │
│   - Telemetry dashboard (uptime, CPU, RAM, app health)           │
│   - OTA dağıtım sunucusu (HTTPS, bundle storage)                 │
│   - Vulnerability/CVE tracking                                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │ HTTPS + mTLS
                           ↓
┌──────────────────────────────────────────────────────────────────┐
│           SUDERRA OS — INDUSTRIAL EDGE DEVICE                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Suderra Edge Agent (Rust, statik binary, ~5MB)            │  │
│  │  - Modbus TCP/RTU master                                   │  │
│  │  - OPC UA server (HMI için)                                │  │
│  │  - MQTT publisher (cloud telemetry, mTLS)                  │  │
│  │  - SQLCipher (encrypted retain/offline state)              │  │
│  │  - sd-notify watchdog (60s heartbeat)                      │  │
│  │  - seccomp ~40 syscalls, no shell, no exec                 │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Systemd (sertleştirilmiş, minimal)                        │  │
│  │  - PID 1 + journald + udev                                 │  │
│  │  - nftables (default DROP)                                 │  │
│  │  - chrony (NTP)                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Linux Kernel 6.12 LTS (hardened, monolithic)              │  │
│  │  - lockdown=confidentiality                                │  │
│  │  - KASLR, KPTI, SMEP/SMAP, KFENCE                          │  │
│  │  - Modules OFF, kexec OFF                                  │  │
│  │  - seccomp BPF, capabilities                               │  │
│  │  - dm-verity, TPM 2.0                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Boot zinciri: UEFI → shim → systemd-boot → kernel         │  │
│  │  → dm-verity → rootfs (erofs, RO, imzalı hash)             │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                           │
                           ↓
┌──────────────────────────────────────────────────────────────────┐
│            ENDÜSTRİYEL SAHA EKİPMANLARI                          │
│   PLC (Siemens, Schneider) | Sensor (Modbus, 4-20mA) | Pump      │
└──────────────────────────────────────────────────────────────────┘
```

## Partition / Disk Layout

```
GPT
├── EFI System Partition           (~256MB, FAT32)        # Bootloader, shared
├── rootfs.A                       (~512MB, erofs+verity) # Aktif slot
├── rootfs.B                       (~512MB, erofs+verity) # Yedek slot (OTA target)
├── /data                          (kalan, ext4 enc)      # Kullanıcı/uygulama state
└── (opsiyonel) rescue/factory     (~256MB)               # Faz 5+
```

## Boot Süreci

1. **UEFI firmware** TPM 2.0 PCR'larını ölçer
2. **shim.efi** Microsoft veya MOK imzalı, Suderra KEK'i kontrol eder
3. **systemd-boot** (Suderra db key ile imzalı) kernel'i yükler
4. **Kernel** kendi imzasını doğrular, cmdline'da `dm-verity` root hash var
5. **dm-verity** rootfs'in Merkle tree'sini lazy doğrular
6. **systemd PID 1** boot.target → multi-user.target
7. **suderra-firstboot.service** (sadece ilk boot) TPM-sealed config açar
8. **suderra-edge-agent.service** başlar (Type=notify, 5sn içinde READY=1)

Detay: [boot-chain.md](boot-chain.md)

## Network Yüzeyi

| Yön | Protokol | Port | Açıklama |
|---|---|---|---|
| Outbound | MQTT TLS | 8883 | Cloud broker (mTLS) |
| Outbound | Modbus TCP | 502 | PLC'lere |
| Outbound | OPC UA | 4840 | Sahadaki HMI server'lar |
| Outbound | HTTPS | 443 | OTA + provisioning |
| Inbound | OPC UA | 4840 | Eğer cihaz server modunda (opsiyonel) |
| Inbound | HTTP | 8080 | Health endpoint (sadece lokal/mTLS, opsiyonel) |
| Inbound | **HİÇBİR ŞEY** | - | SSH/Telnet/FTP/RPC/mDNS YOK |

Firewall: nftables, default DROP. Detay: [board/suderra/common/rootfs-overlay/etc/nftables.conf](../../board/suderra/common/rootfs-overlay/etc/nftables.conf) (Faz 1'de oluşturulacak)

## Sertleştirme Katmanları (defense-in-depth)

```
Katman 1: Boot integrity      → UEFI SB + shim + signed kernel + dm-verity
Katman 2: Kernel hardening    → lockdown, KASLR, modules-off, seccomp
Katman 3: Userspace isolation → systemd ProtectSystem, capabilities, seccomp BPF
Katman 4: Network             → nftables default DROP, no listening services
Katman 5: Process izolasyon   → namespace (pid, mount, net, user), cgroup v2
Katman 6: Disk encryption     → /data LUKS2, TPM-sealed key
Katman 7: Audit               → journald → upstream syslog (lokal dolmasın)
```

## Bileşen Versiyonları (pinli)

> Faz 1'de doldurulacak. Tüm versiyonlar reproducible build için pinli.

| Bileşen | Versiyon | LTS bitiş |
|---|---|---|
| Buildroot | 2024.11.x | TBD |
| Linux kernel | 6.12.x | TBD |
| systemd | TBD | - |
| RAUC | TBD | - |
| musl libc | TBD | - |
| BusyBox | TBD | - |
| nftables | TBD | - |
| chrony | TBD | - |
| Rust toolchain | 1.86.x current pin | MSRV proof tracked separately |

## Açık Konular (Faz 1'de doldurulacak)

- Net donanım modelleri (Advantech UNO-2271G mi, Siemens IPC227G mi?)
- ARM hedef cihazı (Pi CM4 vs Revolution Pi)
- TPM 2.0 zorunluluğu mu, opsiyonel mu?
- /data encryption anahtarı: TPM-sealed mi, passphrase mi?
- Telemetry backend mimarisi (Faz 5)

## Referanslar

- ADR'lar: [ADR-0001](ADR-0001-buildroot-vs-yocto.md) .. [ADR-0005](ADR-0005-dm-verity-secure-boot.md)
- Tehdit modeli: [../security/threat-model.md](../security/threat-model.md)
- Kernel hardening: [../security/kernel-hardening.md](../security/kernel-hardening.md)
