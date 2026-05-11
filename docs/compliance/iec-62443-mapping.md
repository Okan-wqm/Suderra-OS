# IEC 62443 Foundational Requirements Mapping

> **Status:** Skeleton — Faz 6 (sertifikasyon hazırlığı) içinde dolacak.

## Standart

IEC 62443-4-2: Technical security requirements for IACS components
Target Security Level: **SL 2** (Suderra Edge Agent zaten SL 2 hazırlıklı)

## Foundational Requirements (FR1-FR7)

### FR1 — Identification and Authentication Control (IAC)

| SR | Gereksinim | Suderra OS Karşılama |
|---|---|---|
| SR 1.1 | Human user identification | N/A (no human users on device, only service accounts) |
| SR 1.2 | Software process and device identification | mTLS client cert per device, TPM attestation (Faz 5) |
| SR 1.3 | Account management | Edge Agent RBAC; OS-level: edge-agent unprivileged user only |
| SR 1.4 | Identifier management | Cihaz seri no + cloud provisioning |
| SR 1.5 | Authenticator management | mTLS cert rotation, TPM-bound keys |
| SR 1.6 | Wireless access management | N/A (wired only, varsa) |
| SR 1.7 | Strength of public key authentication | RSA-3072+ veya Ed25519 |
| SR 1.8 | Public key infrastructure certificates | X.509, kendi CA |
| SR 1.9 | Strength of password-based authentication | N/A (no passwords, key-based) |
| SR 1.10 | Authenticator feedback | Edge Agent zaten implemented |
| SR 1.11 | Unsuccessful login attempts | N/A |
| SR 1.12 | System use notification | N/A |
| SR 1.13 | Access via untrusted networks | mTLS only |

### FR2 — Use Control (UC)

| SR | Karşılama |
|---|---|
| SR 2.1-2.12 | Edge Agent içinde RBAC + cihaz seviyesinde rootless |

### FR3 — System Integrity (SI)

| SR | Karşılama |
|---|---|
| SR 3.1 | Communication integrity | TLS 1.3 (rustls) |
| SR 3.2 | Malicious code protection | dm-verity + lockdown, no exec from /data |
| SR 3.3 | Security functionality verification | systemd-analyze security, lynis, CI tests |
| SR 3.4 | **Software and information integrity** | **dm-verity + Secure Boot zinciri** ← Ana karşılama |
| SR 3.5 | Input validation | Edge Agent: Modbus/OPC-UA parser fuzzing |
| SR 3.6 | Deterministic output | Reproducible build |
| SR 3.7 | Error handling | systemd Restart=on-failure, watchdog |
| SR 3.8 | Session integrity | mTLS session |
| SR 3.9 | Protection of audit information | journald → remote syslog (immutable) |

### FR4 — Data Confidentiality (DC)

| SR | Karşılama |
|---|---|
| SR 4.1 | Information confidentiality | TLS 1.3 transport, LUKS2 at-rest |
| SR 4.2 | Information persistence | /data encrypted, cache mlock |
| SR 4.3 | Use of cryptography | NIST SP 800-131A compliant |

### FR5 — Restricted Data Flow (RDF)

| SR | Karşılama |
|---|---|
| SR 5.1 | Network segmentation | nftables default DROP |
| SR 5.2 | Zone boundary protection | mTLS at boundaries |
| SR 5.3 | General purpose person-to-person communication restrictions | N/A |
| SR 5.4 | Application partitioning | systemd namespace, cgroup |

### FR6 — Timely Response to Events (TRE)

| SR | Karşılama |
|---|---|
| SR 6.1 | Audit log accessibility | journald + remote syslog |
| SR 6.2 | Continuous monitoring | Telemetry (Faz 5) |

### FR7 — Resource Availability (RA)

| SR | Karşılama |
|---|---|
| SR 7.1 | Denial of service protection | nftables rate limit, kernel sysctl |
| SR 7.2 | Resource management | systemd MemoryMax/CPUQuota |
| SR 7.3 | Control system backup | Edge Agent retain.db, /data backup (TODO) |
| SR 7.4 | Control system recovery and reconstitution | RAUC rollback, factory reset |
| SR 7.5 | Emergency power | N/A (hardware) |
| SR 7.6 | Network and security configurations | Konfig RO, signed |
| SR 7.7 | Least functionality | Tek uygulama, gereksizler kaldırılmış |
| SR 7.8 | Control system component inventory | SBOM |

## Gap Analizi (Faz 6'da yapılır)

- [ ] Her SR için kanıt dosyası referansı
- [ ] Eksik SR'lar için planlama
- [ ] Dış denetçi review
- [ ] Sertifikasyon yol haritası (ücretli, 200-500k TL)

## Referanslar

- IEC 62443-4-1 (Secure product development lifecycle)
- IEC 62443-4-2 (Component security requirements)
- [ISA Global Cybersecurity Alliance](https://gca.isa.org/)
