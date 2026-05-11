# ADR-0002: Init sistemi olarak sertleştirilmiş minimal systemd

- **Status:** Accepted
- **Date:** 2026-05-11
- **Deciders:** @okan-wqm
- **Tags:** systemd, init, hardening

## Context

Init sistemi seçimi, OS'in temel yapı taşıdır. Suderra Edge Agent (Rust uygulaması, v1.6.0) zaten **systemd entegrasyonu varsayımı ile yazılmış**:

- `Type=notify` — readiness için `sd_notify(READY=1)` çağrısı
- `WatchdogSec=60` — `sd_notify(WATCHDOG=1)` ile heartbeat
- `ProtectSystem=strict`, `NoNewPrivileges=true`, `CapabilityBoundingSet` (systemd hardening directives)
- `MemoryMax=256M`, `CPUQuota=75%` (systemd resource control)
- `TimeoutStopSec=90s`, graceful shutdown
- `JournalNamespace` ile log isolation

Önceki master planda "systemd yerine finit veya s6" yazıyordu. Ancak bu, uygulamanın **temelden refactor edilmesini** gerektirir (sd-notify, hardening directives, journald log akışı, vb. — hepsi yeniden yazılır).

Diğer seçenekler:

- s6 / s6-rc — küçük, modüler, ama sd-notify yok
- finit — küçük, embedded'a yönelik, ama Type=notify ekosistemi yok
- BusyBox init + custom shell — primitive, watchdog/hardening manuel
- OpenRC — Alpine'da yaygın, ama notify protokolü yok

## Decision

**systemd kullanılacak** ama sertleştirilmiş ve minimal konfigürasyonla:

1. **Sadece core systemd** + journald + udev
2. **DIŞLANAN** systemd bileşenleri (Buildroot Kconfig'de disable):
   - `systemd-networkd` — yerine custom nftables + minimal config
   - `systemd-resolved` — yerine doğrudan resolv.conf
   - `systemd-timesyncd` — yerine chrony (daha sertleştirilmiş)
   - `systemd-logind` — gerek yok (interaktif login yok)
   - `systemd-homed` — gerek yok
   - `systemd-portabled` — gerek yok
   - `systemd-machined` — container yok
   - `systemd-importd` — gerek yok
   - `systemd-userdbd` — gerek yok
3. **Tek user unit:** `suderra-edge-agent.service`
4. **Tek target:** `multi-user.target` (graphical/network değil)

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Karar |
|---|---|---|---|
| **systemd minimal (seçilen)** | App ile uyumlu, watchdog/notify protokol mevcut, hardening directives, journald | Saldırı yüzeyi diğer init'lerden büyük, RAM ~10MB | **SEÇİLDİ** |
| s6 / s6-rc | Çok küçük (~200KB), modüler, hızlı boot | App'i refactor şart, sd-notify yok, watchdog protokolü farklı, ekosistem dar | Reddedildi |
| finit | Embedded-friendly, küçük | App'i refactor şart, dokümantasyon zayıf | Reddedildi |
| BusyBox init | En minimal | Watchdog manuel, hardening manuel, herşey kendin yazılır | Reddedildi |
| OpenRC | Alpine ekosistemi | App refactor + sd-notify shim gerekir, kompleks | Reddedildi |

## Consequences

### Positive

- Mevcut uygulama **değiştirmeden** çalışır — Faz 2 süresi 2-3 ay kısalır
- systemd hardening directives güçlü (ProtectSystem, NoNewPrivileges, vb.)
- `systemd-analyze security` ile her unit'in skoru ölçülebilir
- journald ile structured logging (`docs/operations/debug.md`)
- Watchdog + cgroup v2 resource control hazır
- Endüstriyel ekosistemde yaygın (debug bilgisi bol)

### Negative

- systemd "küçük" değil — minimal kurulumda bile 8-15MB
- systemd CVE'leri (CVE-2022-3821 vb.) — patch disiplini şart
- Geçmişte 38xx CVE → kernel'le birlikte takip
- Boot süresi s6'ya göre 2-3x yavaş (1-2 sn fark)

### Neutral / Trade-offs

- "systemd-free" pazarlama hikayesinden vazgeçildi → "hardened minimal systemd" hikayesine geçildi
- Eğer ileride app refactor edilirse s6'ya geçiş düşünülebilir, ama bu büyük bir karar (yeni ADR ile)

## Implementation Notes

- Buildroot defconfig: `BR2_INIT_SYSTEMD=y`
- Disable edilen systemd özellikleri için `BR2_PACKAGE_SYSTEMD_*` flag'leri (yukarıdaki liste)
- `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-edge-agent.service` — sertleştirilmiş unit
- `systemd-analyze security suderra-edge-agent.service` skoru hedef: < 2.0 (max güvenlik)
- Boot süresi hedef: 5sn içinde edge-agent active (Faz 2 doğrulama)
- Boot süresi ölçümü: `systemd-analyze blame`, `systemd-analyze critical-chain`

## References

- [systemd hardening guide](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Arch Wiki — systemd hardening](https://wiki.archlinux.org/title/Security#Restricting_root)
- ADR-0001: Buildroot seçimi
- Suderra Edge Agent v1.6.0 systemd unit (mevcut `aquaculture_platform/sens-api-gateway`)
