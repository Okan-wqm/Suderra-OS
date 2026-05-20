# Penetration Test Checklist

> **Status:** Skeleton — Faz 6 hazırlığı.

## Hedef Skorlar

| Tool | Hedef |
|---|---|
| Lynis | ≥ 85 |
| OpenSCAP (CIS Distribution-Independent) | ≥ 80% pass |
| Nmap (external) | 0 port open |
| systemd-analyze security <unit> | < 2.0 (en güvenli) |

## Kategoriler

### 1. Ağ Yüzeyi

- [ ] `nmap -sS -sU -sV -A <ip>` — hiçbir port görünmemeli (production)
- [ ] `nmap -p- <ip>` (all 65535) — aynı
- [ ] IPv6 disabled doğrulama: `cat /proc/sys/net/ipv6/conf/all/disable_ipv6` → `1`
- [ ] mDNS/LLMNR yanıt: `python -c "..."` — yanıt yok
- [ ] ICMP echo: nmap reports filtered veya no response

### 2. Boot Bütünlük

- [ ] Secure Boot durum: `mokutil --sb-state` → enabled
- [ ] dm-verity aktif: `dmsetup table` → verity satırı var
- [ ] Kernel cmdline değişmemiş: `cat /proc/cmdline | grep dm-verity`
- [ ] Tamper testi: 1 byte değiştir → kernel reddetmeli (`tests/security/verity-tamper-test.sh`)

### 3. Kernel Sertleştirme

- [ ] `cat /sys/kernel/security/lockdown` → `[confidentiality]`
- [ ] KASLR aktif: `/proc/kallsyms` adresleri her boot'ta değişiyor
- [ ] Modules kapalı: `lsmod` → boş, `cat /proc/sys/kernel/modules_disabled` → `1`
- [ ] kexec yok: `kexec` komutu permission denied
- [ ] dmesg restrict: `cat /proc/sys/kernel/dmesg_restrict` → `1`
- [ ] kptr restrict: `cat /proc/sys/kernel/kptr_restrict` → `2`

### 4. Userspace İzolasyon

- [ ] `systemd-analyze security suderra-edge-agent` → skor < 2.0
- [ ] `ps -eo user,comm` → suderra-edge-agent root DEĞİL
- [ ] `cat /proc/<pid>/status | grep CapEff` → minimal capabilities
- [ ] `cat /proc/<pid>/status | grep Seccomp` → mode 2
- [ ] SSH erişim yok: `ssh user@<ip>` → connection refused

### 5. Filesystem

- [ ] `mount | grep ro` → / read-only
- [ ] `/etc` write testi: `touch /etc/test` → permission denied
- [ ] suid binary'ler: `find / -perm -4000 -type f` → minimal liste
- [ ] World-writable: `find / -perm -002 -type f` → sadece /tmp gibi yerlerde
- [ ] LUKS aktif: `cryptsetup status data` → encrypted

### 6. Audit

- [ ] journald aktif: `journalctl --since "1 min ago"` log akıyor
- [ ] Remote syslog (Faz 5): cloud'a log geliyor
- [ ] Auditd kuralları: `auditctl -l` (eğer kullanılıyorsa)

### 7. OTA Güvenlik

- [ ] Sahte bundle reddedilir: `tests/ota/sign-tamper-test.sh`
- [ ] Bozuk bundle rollback: `tests/ota/update-rollback-test.sh`
- [ ] Downgrade reddedilir: eski versiyon bundle reddedilmeli

### 8. Tedarik Zinciri

- [ ] Reproducible build: `scripts/verify-reproducible.sh` (2 build aynı SHA256)
- [ ] SBOM mevcut + güncel: `output/sbom.cyclonedx.json`
- [ ] Hash dosyaları doğru: izole Buildroot source tree ile
  `make -C "${buildroot_source_dir}" check-package-hashes`

## Otomasyon

- `tests/security/lynis-baseline.sh` — Lynis çağırır, skor kontrol eder
- `tests/security/nmap-external.sh` — Dışarıdan tarar, 0 port bekler
- `tests/security/verity-tamper-test.sh` — Bütünlük tampering testi
- CI'da nightly çalıştır

## Dış Pen Test

Faz 6 sonu için planlanmalı. Bütçe: ~50-100k TL.
Kapsam: tüm yukarıdaki + black-box exploit denemesi.

## Referanslar

- [Lynis](https://cisofy.com/lynis/)
- [OpenSCAP](https://www.open-scap.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [OWASP Embedded Application Security](https://owasp.org/www-project-embedded-application-security/)
