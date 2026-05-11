# IEC 62443-4-2 Component Requirements (CR) Mapping

> **Status:** Skeleton — Faz 6 (sertifikasyon hazırlığı) içinde detaylanacak.
>
> Bu doküman IEC 62443-4-2:2019 (Technical security requirements for IACS components) gereksinimlerinin Suderra OS karşılığını izler. **Component-level** ürün sertifikasyonu için temel.

## Sınıflandırma

Suderra OS bileşen tipi: **Embedded Device Requirement (EDR)**

- Edge device (sensör veri toplama + kontrol)
- Sınırlı I/O, dedicated function
- Yerel network'ten ulaşılabilir

Hedef Security Level: **SL 2** (Suderra Edge Agent ile uyumlu)

| SL | Saldırgan | Skill | Kaynak | Motivasyon |
|---|---|---|---|---|
| SL 1 | Kasıtsız | Genel | Düşük | Hata |
| **SL 2** | **Bilinçli** | **Düşük** | **Düşük** | **Genel saldırı** |
| SL 3 | Bilinçli | Yüksek | Orta | Hedefli, IACS-spesifik |
| SL 4 | Bilinçli | Yüksek | Yüksek | State actor / APT |

## Foundational Requirements (FR1-FR7)

### FR 1 — Identification and Authentication Control (IAC)

| CR | Gereksinim | SL2 | Suderra OS Karşılama | Kanıt |
|---|---|---|---|---|
| CR 1.1 | Human user identification | ✓ | mTLS client cert per ops user (cloud üzerinden) | Edge Agent RBAC |
| CR 1.2 | Software process identification | ✓ | systemd unit identity, suderra-edge agent user | systemd unit |
| CR 1.3 | Account management | ✓ | Edge Agent RBAC; OS-level no users (PROD) | Edge Agent |
| CR 1.4 | Identifier management | ✓ | Cihaz seri no + cloud provisioning | firstboot.service |
| CR 1.5 | Authenticator management | ✓ | mTLS cert rotation, TPM-bound | key-management.md |
| CR 1.7 | Strength of password-based auth | ✓ | N/A (key-based only) | - |
| CR 1.8 | Public key infrastructure certificates | ✓ | X.509 + RSA-3072+ | key-management.md |
| CR 1.9 | Strength of public key auth | ✓ | RSA-3072 / Ed25519 | ADR-0005 |
| CR 1.10 | Authenticator feedback | ✓ | Edge Agent zaten implemented | - |
| CR 1.11 | Unsuccessful login attempts | SL3+ | N/A (key-based) | - |
| CR 1.13 | Access via untrusted networks | ✓ | mTLS only, nftables outbound whitelist | ADR-0005 |

### FR 2 — Use Control (UC)

| CR | Gereksinim | SL2 | Karşılama |
|---|---|---|---|
| CR 2.1 | Authorization enforcement | ✓ | Edge Agent RBAC + OS capabilities |
| CR 2.2 | Wireless use control | N/A | Cihazda wireless yok (wired only) |
| CR 2.3 | Use control for portable devices | N/A | - |
| CR 2.4 | Mobile code | ✓ | Yok (no scripting, no plugin) |
| CR 2.5 | Session lock | N/A | No interactive login (PROD) |
| CR 2.6 | Remote session termination | ✓ | mTLS session timeout |
| CR 2.7 | Concurrent session control | ✓ | Edge Agent built-in |
| CR 2.8 | Auditable events | ✓ | journald + remote syslog |
| CR 2.9 | Audit storage capacity | ✓ | Remote syslog (lokal dolmasın) |
| CR 2.10 | Response to audit processing failures | ✓ | Faz 5'te |
| CR 2.11 | Timestamps | ✓ | chrony NTP |
| CR 2.12 | Non-repudiation | ✓ | Ed25519 imzalı command log (Edge Agent) |

### FR 3 — System Integrity (SI)

| CR | Gereksinim | SL2 | Karşılama | Kanıt |
|---|---|---|---|---|
| CR 3.1 | Communication integrity | ✓ | TLS 1.3 (rustls) | Edge Agent |
| CR 3.2 | Protection from malicious code | ✓ | dm-verity + lockdown, no exec from /data | ADR-0005 |
| CR 3.3 | Security functionality verification | ✓ | systemd-analyze security, lynis, CI tests | pen-test-checklist.md |
| CR 3.4 | **Software + information integrity** | ✓ | **dm-verity + Secure Boot** | ADR-0005 |
| CR 3.5 | Input validation | ✓ | Edge Agent: Modbus/OPC-UA parser + fuzz | Edge Agent |
| CR 3.6 | Deterministic output | ✓ | Edge Agent IEC 61131-3 PLC engine | - |
| CR 3.7 | Error handling | ✓ | systemd Restart=on-failure, watchdog | systemd unit |
| CR 3.8 | Session integrity | ✓ | mTLS session | - |
| CR 3.9 | Protection of audit info | ✓ | journald → remote (immutable) | Faz 5 |
| CR 3.10 | Backup integrity | SL3+ | Faz 5+ |
| CR 3.11 | Physical tamper resistance | SL3+ | OEM sorumluluğu (TPM 2.0) |
| CR 3.12 | Provisioning asset owner roots of trust | ✓ | Customer enrolls MOK / cloud cert | firstboot |
| CR 3.13 | Provisioning protection | ✓ | mTLS + TPM-sealed | firstboot |
| CR 3.14 | Integrity of boot process | ✓ | UEFI SB + signed kernel + verity | boot-chain.md |

### FR 4 — Data Confidentiality (DC)

| CR | Gereksinim | SL2 | Karşılama |
|---|---|---|---|
| CR 4.1 | Information confidentiality | ✓ | TLS 1.3 transport, LUKS2 at-rest |
| CR 4.2 | Information persistence | ✓ | /data encrypted, mlock for secrets |
| CR 4.3 | Use of cryptography | ✓ | NIST SP 800-131A compliant (rustls + AES-256-GCM, SHA-256, RSA-3072+) |

### FR 5 — Restricted Data Flow (RDF)

| CR | Gereksinim | SL2 | Karşılama |
|---|---|---|---|
| CR 5.1 | Network segmentation | ✓ | nftables default DROP |
| CR 5.2 | Zone boundary protection | ✓ | mTLS at boundaries |
| CR 5.3 | General purpose communication restrictions | ✓ | No SSH, no IRC, no Telnet |
| CR 5.4 | Application partitioning | ✓ | systemd namespace, cgroup v2 |

### FR 6 — Timely Response to Events (TRE)

| CR | Gereksinim | SL2 | Karşılama |
|---|---|---|---|
| CR 6.1 | Audit log accessibility | ✓ | journald + remote syslog |
| CR 6.2 | Continuous monitoring | ✓ | Telemetry (Faz 5) |

### FR 7 — Resource Availability (RA)

| CR | Gereksinim | SL2 | Karşılama |
|---|---|---|---|
| CR 7.1 | DoS protection | ✓ | nftables rate limit, kernel sysctl |
| CR 7.2 | Resource management | ✓ | systemd MemoryMax=256M, CPUQuota=75% |
| CR 7.3 | Control system backup | ✓ | Edge Agent retain.db, /data |
| CR 7.4 | Control system recovery | ✓ | RAUC rollback, factory reset |
| CR 7.6 | Network/security config integrity | ✓ | Config dosyaları rootfs RO içinde |
| CR 7.7 | Least functionality | ✓ | Tek uygulama, gereksizler kaldırılmış |
| CR 7.8 | Control system component inventory | ✓ | SBOM |

## Embedded Device Specific (EDR) Requirements

Embedded Device kategorisindeki Suderra OS için ek gereksinimler:

| EDR Req | Karşılama |
|---|---|
| EDR 2.13 | Use of physical diagnostic and test interfaces (UART debug) — sadece DEV, PROD'da disable |
| EDR 3.2 | Protection from malicious code — dm-verity + Secure Boot |
| EDR 3.10 | Support for updates — RAUC OTA |
| EDR 3.11 | Physical tamper resistance — OEM sorumluluğu |
| EDR 3.12 | Provisioning asset owner roots of trust |
| EDR 3.14 | Integrity of the boot process |

## Sertifikasyon Yol Haritası

1. **Faz 6**: Self-assessment + gap analysis
2. **Faz 6 sonu**: Iç pen-test (Lynis 85+, OpenSCAP CIS)
3. **Faz 7 başı**: Dış pen-test
4. **Faz 7+**: Notified Body (ISA, TÜV, vb.) — opsiyonel
5. **Üretim öncesi**: IEC 62443-4-2 sertifikasyon (~200-500k TL maliyet)

## Yapılacaklar

- [ ] Her CR için detaylı kanıt dosyası (Faz 6)
- [ ] Notified Body iletişimi (ISA Secure, TÜV SÜD)
- [ ] Müşteri yöneliminde 62443 sunum dokümanı

## Referanslar

- IEC 62443-4-2:2019
- [IEC 62443-4-2 Quick Start](https://62443-4-2.org/)
- [ISA Global Cybersecurity Alliance](https://gca.isa.org/)
- [iec-62443-mapping.md](iec-62443-mapping.md) (4-1 — process)
