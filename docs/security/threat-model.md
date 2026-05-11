# Suderra OS — Tehdit Modeli (STRIDE)

> **Status:** Skeleton — Faz 3 (sertleştirme) başında detaylanacak. Bu dosya yapı ve ilk pas içerir.

## Amaç

Suderra OS'in karşılaştığı tehditleri sistematik şekilde tanımlamak, her tehdit için koruma katmanını eşleştirmek, ve uyumluluk (IEC 62443-4-2, CRA) için kanıt sağlamak.

## Kapsam

| Dahil | Hariç |
|---|---|
| Suderra OS imajı + boot zinciri | Saha PLC'leri (3. parti) |
| RAUC OTA mekanizması | Cloud sunucu (ayrı threat model) |
| Suderra Edge Agent (Rust) | Operasyonel insan riski (eğitim, social eng.) |
| /data partition + state | Fiziksel donanım üreticisi tedarik zinciri (OEM sorumluluğu) |

## Aktörler

| Aktör | Motivasyon | Yetenek | Erişim |
|---|---|---|---|
| **Casual insider** | Kasıtsız hata, merak | Düşük | Ağ + fiziksel |
| **Insider threat** | Sabotaj, hırsızlık | Orta | Cihaza erişim |
| **External attacker (remote)** | Fidye, casusluk, sabotaj | Yüksek | Sadece ağ |
| **External attacker (physical)** | Hedefli saldırı (state actor) | Çok yüksek | Cihazı çalar veya fiziksel erişir |
| **Supply chain attacker** | Geniş etki | Yüksek | Buildroot/kernel paketleri |

## STRIDE Analizi

### S — Spoofing (Kimlik sahteciliği)

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| Sahte OTA bundle gönderme | Kritik | Düşük | RAUC X.509 imza doğrulama + pinned keyring |
| MITM cloud broker'a | Yüksek | Orta | mTLS (sertifika pinning), TLS 1.3 |
| Sahte güncelleme sunucusu DNS | Yüksek | Düşük | HTTPS + pinned CA + sertifika doğrulama |
| Cihaz kimliği taklit (telemetry) | Orta | Düşük | mTLS client cert, TPM-attestation (Faz 5+) |

### T — Tampering (Bütünlük ihlali)

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| Diskteki kernel/rootfs değiştirme | Kritik | Düşük | Secure Boot + dm-verity |
| Çalışma anında binary değiştirme | Kritik | Orta (RCE sonrası) | rootfs RO, /etc RO |
| Cmdline değiştirme | Kritik | Düşük | Kernel imzasının parçası |
| Bootloader değiştirme | Kritik | Düşük | UEFI Secure Boot |
| /data içinde state corruption | Orta | Orta | SQLCipher (Edge Agent kendi içinde) |
| RAUC bundle MITM | Kritik | Düşük | İmza + TLS |
| Buildroot upstream paket compromise | Kritik | Düşük (xz benzeri) | Hash file (.hash), pinned versiyon, SBOM diff |

### R — Repudiation (İnkâr)

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| Saldırgan log'ları silme | Yüksek | Orta (RCE sonrası) | Remote syslog (Faz 5), audit log integrity (Faz 5+) |
| Komut kim verdi belirsizlik | Orta | Düşük | Edge Agent: RBAC + Ed25519 imzalı command log |

### I — Information disclosure (Bilgi sızıntısı)

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| Cihaz çalınıp disk imajlanırsa | Yüksek | Orta | /data LUKS2 + TPM-sealed (Faz 3) |
| Çalışan process'lerden anahtar sızıntı | Yüksek | Düşük | Edge Agent: `mlock`, `memfd_secret`, `PR_SET_DUMPABLE=0` |
| Network sniff (TLS olmadan) | Kritik | Yüksek (TLS yoksa) | TLS 1.3 mTLS her yerde |
| dmesg / kallsyms ile leak | Düşük | Orta | `dmesg_restrict=1`, `kptr_restrict=2` |
| Core dump leak | Orta | Düşük | `kernel.core_pattern` kapalı |

### D — Denial of Service

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| App donar/crash → uretim durur | Yüksek | Orta | systemd Restart=always + watchdog (60s) |
| Kernel panic → cihaz duracak | Kritik | Düşük | Hardware watchdog (Faz 5) → otomatik reboot |
| Disk dolma (log) | Orta | Yüksek | journald rate limit + remote syslog (Faz 5) |
| Ağ flood | Düşük (TCP) | Orta | nftables rate limit (Faz 3) |
| OTA içine DoS payload | Yüksek | Düşük | İmza + manifest validation |

### E — Elevation of privilege

| Tehdit | Etki | Olasılık | Koruma |
|---|---|---|---|
| Edge Agent RCE → root | Kritik | Orta | seccomp (no execve), capabilities drop, NoNewPrivileges |
| Kernel exploit → root | Kritik | Düşük | KASLR, KPTI, SMEP/SMAP, lockdown, modules off |
| systemd unit hijack | Yüksek | Düşük | unit file RO (rootfs RO), CAP_BOUNDING |
| Suid binary abuse | Orta | Düşük | suid binary'leri post-build.sh ile temizle |
| Kernel module yükleme | Kritik | Düşük | CONFIG_MODULES=n (monolithic) |

## Risk Matrix

```
Olasılık ↑
  Yüksek │              │   journal full     │            │
  Orta   │ runtime tamp │   syslog rate      │ TLS sniff  │
  Düşük  │ supply chain │   kernel exploit   │ phys+key   │
         └──────────────┴─────────────────────┴────────────┘
            Düşük Etki     Orta Etki          Yüksek Etki
```

## Açık Konular (Faz 3'te detaylanacak)

- [ ] Her tehdide STRIDE-per-element mapping (her Suderra bileşeni için)
- [ ] DFD (Data Flow Diagram) çiz
- [ ] Trust boundary'leri belirle (cihaz-ağ, ağ-cloud)
- [ ] Her korunma için test senaryosu yaz (`tests/security/`)
- [ ] Residual risk listesi (kabul edilen riskler)
- [ ] Saldırı ekonomisi analizi (saldırının maliyeti vs değeri)

## Referanslar

- [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [ENISA Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats)
- IEC 62443-4-2 (Component-level security)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- ADR-0005: dm-verity + Secure Boot (Tampering/Spoofing korumaları)
