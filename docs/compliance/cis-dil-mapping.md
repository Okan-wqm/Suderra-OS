# CIS Distribution Independent Linux (DIL) Benchmark Mapping

> **Status:** Skeleton — Faz 3 (sertleştirme) içinde detaylanır.
>
> CIS DIL v2.0+ ile Suderra OS sertleştirme durumu eşleştirmesi.

## Genel Bakış

CIS DIL Benchmark Linux sistemleri için en geniş kabul gören sertleştirme rehberidir. Suderra OS hedefi:
- **Level 1:** ≥95% pass (zorunlu, üretim için)
- **Level 2:** ≥85% pass (yüksek güvenlik)

## Section 1 — Initial Setup

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 1.1.x | Filesystem mounts (nodev, nosuid, noexec) | post-build.sh + systemd | Faz 3 |
| 1.1.2 | /tmp tmpfs | systemd-default | OK |
| 1.1.6 | /home noexec | N/A (no /home) | N/A |
| 1.2.x | Configure software updates | RAUC OTA | Faz 4 |
| 1.3.x | Filesystem integrity checking | dm-verity | OK (ADR-0005) |
| 1.4.x | Secure boot settings | UEFI SB | OK (ADR-0005) |
| 1.5.x | Process hardening (core dump, ASLR) | sysctl + kernel CONFIG | OK |
| 1.6.x | MAC (SELinux/AppArmor) | TBD | Faz 3+ |
| 1.7.x | Command line warning banners | /etc/issue (PROD: no login) | OK |
| 1.8.x | GNOME display manager | N/A (headless) | N/A |

## Section 2 — Services

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 2.1.x | Inetd / xinetd | Yok | OK |
| 2.2.x | Special purpose services (avahi, cups, dhcp...) | Hiçbiri yok | OK |
| 2.3.x | Service clients (NIS, telnet, talk...) | Yok | OK |
| 2.4 | Cron daemon | timers (systemd) | OK |

## Section 3 — Network Configuration

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 3.1.x | Disable unused network protocols | nftables + kernel CONFIG | OK |
| 3.2.x | Network parameters (host) | sysctl 90-suderra-hardening.conf | OK |
| 3.3.x | Network parameters (router) | N/A (cihaz router değil) | N/A |
| 3.4.x | Uncommon network protocols (DCCP, SCTP, RDS, TIPC) | Kapalı | OK |
| 3.5.x | Firewall configuration | nftables default DROP | OK |
| 3.5.3 | iptables (alternative) | nftables yerine | N/A |
| 3.6.x | Disable wireless | N/A (wired only) | OK |
| 3.7 | Disable IPv6 (if not needed) | sysctl=1 (disable) | OK |

## Section 4 — Logging and Auditing

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 4.1.x | systemd-journald | journald + remote syslog | OK |
| 4.2.x | auditd | Faz 5 | Faz 5 |
| 4.3.x | Logrotate | journald built-in | OK |

## Section 5 — Access, Authentication, Authorization

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 5.1.x | SSH server | Yok (PROD) / dev-only | OK (PROD) |
| 5.2.x | sudo | Yok (no interactive users) | OK |
| 5.3.x | PAM | Sadece auth gerekli kısımlar | TBD |
| 5.4.x | User accounts (password) | Yok (key-based) | OK |
| 5.5.x | User environment | N/A | N/A |
| 5.6.x | Su / runas | Yok | OK |

## Section 6 — System Maintenance

| Item | Description | Suderra OS | Status |
|---|---|---|---|
| 6.1.x | System file permissions | post-build.sh | OK |
| 6.2.x | User and group settings | suderra-edge user only | OK |

## Otomatize Doğrulama

```bash
# OpenSCAP ile CIS DIL benchmark
oscap xccdf eval \
    --profile xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Server \
    --results cis-dil-results.xml \
    --report cis-dil-report.html \
    /usr/share/scap-security-guide/distribution-independent-linux-ds.xml
```

CI'da otomatik (Faz 3'te aktive olur):
```yaml
- name: CIS DIL benchmark
  run: |
    docker run --rm -v $(pwd):/work \
        opensuse/oscap \
        oscap xccdf eval --profile ... 
```

## Skor Takibi

| Tarih | Sürüm | Level 1 | Level 2 |
|---|---|---|---|
| 2026-05-11 | v0.1.0-alpha | TBD | TBD |
| (Faz 3 sonu) | v0.5.0 | ≥80% | ≥60% |
| (Faz 6) | v1.0 LTS | ≥95% | ≥85% |

## Yapılacaklar

- [ ] OpenSCAP integration (`tests/security/oscap-cis.sh`)
- [ ] CI'da otomatik skor takibi
- [ ] Sapmaları justify eden doküman (waiver list)

## Referanslar

- [CIS DIL Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [CIS DIL Ansible role (referans)](https://github.com/dev-sec/cis-dil-benchmark)
- [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
- [docs/security/kernel-hardening.md](../security/kernel-hardening.md)
