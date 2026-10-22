# ADR-0008: Edge agent entegrasyon sözleşmesi — Suderra OS yükümlülükleri

- **Status:** Accepted — kayıt kararı aquaculture_platform ADR-048'dir; karar, operatörün 2026-10-19
  yetki devriyle Claude tarafından alındı; operatör incelemesi ve CODEOWNERS (@Okan-wqm) onayı
  bekleniyor.
- **Date:** 2026-10-19
- **Deciders:** @okan-wqm (yetki devri, 2026-10-19), Claude (öneri ve sentez)
- **Tags:** security, boot, ota, hardware, provisioning

## Context

Suderra OS, Suderra edge agent (`sens-api-gateway`, crate `suderra-agent`) ve bulut platformu
arasındaki entegrasyon sözleşmesinin kayıt kararı (decision of record) şudur:

**[aquaculture_platform ADR-048: Suderra OS – edge agent – bulut entegrasyon sözleşmesi](https://github.com/Okan-wqm/aquaculture_platform/blob/main/docs/adr/048-suderra-os-edge-agent-integration-contract.md)**

Bağlam, kanıtlar (bugünkü kırıklar K1–K14), gerekçe, riskler, kart matrisi, fazlar, saha devreye alma
kapıları ve açık sorular yalnız ADR-048'dedir. Bu ADR yalnız bu repoya düşen yükümlülükleri karar
kimliğiyle listeler ve hangi mevcut OS ADR'larını değiştirdiğini kaydeder. ADR-048 ile bu dosya
çelişirse ADR-048 geçerlidir.

## Decision

Suderra OS, ADR-048'deki kararları uygular. Bu repodaki yükümlülükler aşağıdadır; ayrıntı, yol ve
gerekçe parantez içindeki ADR-048 maddesindedir.

| Karar | Suderra-OS yükümlülüğü |
|---|---|
| DEC-1 | P0: `package/suderra-edge-agent/` silinir; imajda tek overlay agent unit'i, kart drop-in'leri ve udev kuralları (1.1, 1.8). Agent unit'inden `/dev/watchdog`, `/dev/tpm0` ve `/dev/tpmrm0` kaldırılır; P0–P1'de agent TPM cihazı almaz (1.8, DEC-21). `/data/suderra/edge` bind'i ve `/data` mount seçenekleri (1.3, 1.7). Atomik `current` geçişi (1.4). `suderra-installer edge install\|verify-current\|rollback\|request` ve her start'ta `verify-current` (1.5). Installer girdi savunması: katı version regex'i, tam `binary_name`, güvenli tar açma, Rust'ta `openat`/`O_NOFOLLOW` (1.10). Unit contract testi overlay unit'e yeniden hedeflenir (1.9). P2: verity release imajı ve kernel'in zorladığı root hash imzası (`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` veya IPE, `edge-image` X.509 anahtarı; 1.6, EDGE-MEDIUM-116). |
| DEC-2 | P0: paket kurulum komutları prod build'den çıkar; tek mark-good; `security_version` ve root floor (2.2, 2.5, 2.8). P1: istek kanalı ve root worker (`edge-update`, `os-update`, `site-config` cihaza bağlı ve `update_seq`'li; `trust-anchors` cihaza bağlı değil, fleet-root zinciri, `bundle_seq` ratchet'i ve `tenant_scope` ile), tek kilit, bakım penceresi, `userspace/suderra-ota/src/main.rs`'e teslim (2.3, 2.4, 2.9). P2: `edge-update.v2` + `approvals[]` (2.4). P3: platform firmware hook'ları, hava boşluklu USB update ingress (2.10, 2.11). |
| DEC-3 | P0: DSSE doğrulayıcı (3.2); `suderra-keys` amaç/epoch başına pinler ve prod keyid allowlist'i (3.3, 3.4, 3.9); root epoch ratchet'i (3.5); `suderra-identity` ve device binding (3.6); trust-anchor bundle'ının fleet-root pinine karşı doğrulanması, `scripts/gen-dev-keys.sh` ile dev fleet-root'u (3.7); anahtar envanteri (3.11). dev/CI anahtarlarını yalnız dev imajları ve QEMU hedefleri pinler. P1: üretim anahtar seremonisi (operatör; fleet-root ve edge-release offline); donanım kartlarının prod defconfig'leri (`suderra_aarch64_revpi4_prod_ab_defconfig`, `suderra_aarch64_rpi4_prod_ab_defconfig`, `suderra_x86_64_defconfig`) yalnız envanterdeki seremoni/HSM kökenli keyid'leri kurar ve üretim imajları P1'den itibaren build edilir (3.9). P2: imajda pinli online amaçlar (edge-provisioning, device-lifecycle) ve edge-release için KMS kökenli yeni epoch'lar `suderra-keys`'e girer, eskileri `key-epoch-advance` ile emekliye ayrılır (3.9, DEC-15). |
| DEC-4 | P0: `/data` alt ağaçları ve tek sahiplik yazıcısı; agent alt dizinleri yalnız `data-layout.tmpfiles.conf` ile (4.2, 4.3). Provisioning spool'unda root worker'ın sonuç dosyası root:provision 0640'tır; `provision` kullanıcısı okur (4.2, EI-002). Kilit/provisioning durumu `/data/suderra/os/`'te (4.4); çalışma anında `/etc` yazması yok (4.1). Agent unit'i yol env'i set etmez; `ReadOnlyPaths`, dar `ReadWritePaths`, `ExecStartPre=+`/`ExecReload` site digest kontrolü (4.5, 4.10, 4.11). `/etc/revpi/config.rsc` symlink'i (4.7). Volatile journal, `ClientIdentifier=mac`, boş `/etc/machine-id` (4.9). `suderra-installer site apply` (4.12). P1: `kind=site-config` (4.12). |
| DEC-5 | P0: prod defconfig'lerde dropbear; birimler yalnız PROVISIONING veya yeniden provisioning amaçlı MAINTENANCE'ta (5.1). `suderra-provision-mode` ve `suderra-provision-mode.service` (yeni) ile `/run` OTP'si, `/data`'da host key (5.2, 5.3). Provisioning SSH yalnız varsayılan rota arayüzünde ve kaynak adresi başına nft meter'la (`board/suderra/common/rootfs-overlay/etc/nftables.provisioning.conf`; 5.4). Stdin token, `curl -H @dosya`, ara ad + rename inbox, `/etc/shells` (5.5). `suderra-activation.path` ve `suderra-activation.service` (yeni), asenkron lockdown (5.8, 5.9). `suderra-lifecycle.{path,service}` (yeni) ile yeniden provisioning (5.14). P1: USB provisioning bundle ingress, RevPi durum LED'leri. P3: claim-code ve aktivasyon PoP'u (5.11, DEC-10.7; EDGE-MEDIUM-126). |
| DEC-6 | P0: `suderra-installer health check` yüklemi ve `suderra-rauc-health-gate` v2 (6.8); env tabanlı üretim modu kaldırılır (6.9). P1: PID1 watchdog yapılandırması, `CONFIG_WATCHDOG_NOWAYOUT=y`, kart başına WDT sürücüleri; `userspace/suderra-watchdog` paketlenmez (6.6). |
| DEC-7 | P1: OS'e ait `chrony.conf`, `suderra-chrony-wait.service`, `suderra-timefloor.{service,timer}`, time-state yazıcısı, NTP egress kısıtı, provision worker zaman sıralaması, installer `--clock-floor-file`, RevPi RTC sürücüsü (7.1–7.8). |
| DEC-8 | P0: `/etc/suderra/board` (8.2); x86 kernel sembolleri, dev QEMU kernel fragment'ı ve defconfig'i, kernel config contract testi (8.10). P1: `board/suderra/aarch64-revpi-connect4/`, KUNBUS kernel'i, `package/revpi-picontrol/{Config.in,revpi-picontrol.mk,revpi-picontrol.hash}` (yeni; kök `Config.in`'e eklenir), FIT DTB kapısı (8.6, 8.7); kart başına RAUC compatible (8.3); x86 USB installer imajı ve dönüşüm runbook'u (8.9); tek 6.12 hattı (8.12). |
| DEC-9 | P0: root installer RBAC manifestini trust-anchor bundle'ındaki `rbac-manifest` çapasına karşı doğrular ve `/data/suderra/site/`'a yazar (9.9). P1: aynısı `kind=site-config` ile. |
| DEC-10 | P0: `package/suderra-keys/Config.in`'deki karşılıksız MQTT CA vaadi kaldırılır; MQTT CA kümesi bundle'la gelir (10.4, 10.6). |
| DEC-11 | P0: temel drop ruleset'i, `nft -c`, networkd'nin firewall'a bağlanması, ağ failsafe target'ı, appliance varsayılanı, provisioning ruleset'i yalnız PROVISIONING'de, varsayılan rota arayüzünde ve kaynak başına meter'la, DHCP ve NTS-KE kuralları (11.2, 11.3, 11.8, 11.9). P1: UID başına egress, kart profili arayüz rolleri (11.4, 11.6). P2: imzalı site netpolicy için tipli renderer ve LKG (11.7). |
| DEC-12 | P0: root-owned yaşam döngüsü deposu, LOCKED varsayılanı, prod ve dev giriş kuralları (`genimage-qemu.cfg`'de `SUDERRA-DATA` bölümü), yeniden provisioning amaçlı MAINTENANCE. P3: break-glass amaçlı MAINTENANCE, DECOMMISSIONED/RMA, TPM NV aynası. |
| DEC-13 | P1: update worker ve `suderra-ota` bakım penceresi, onay ve kesinti bütçesini uygular; devreye alma kontrol listesi (13.1, 13.4). |
| DEC-14 | P1: x86 PCR 7 + imzalı PCR 11 politikası, SBAT/dbx, recovery key yolu (14.1, 14.3); bu commit'ler EI-037'yi `Refs:` ile anar. P3: RevPi OTP secure boot (operatör kararı), U-Boot measured boot, imzalı PolicyAuthorize, `userspace/suderra-attestation` (14.2, 14.4); EI-037 bu ARM işiyle kapanır. |
| DEC-15 | P2: `key-epoch-advance` doğrulayıcısı, OS anahtarları için ihlal runbook'ları, QEMU tatbikatı. |
| DEC-16, DEC-17 | P0: yeniden provisioning akışı (17 a). P3: break-glass bakım birimi; `userspace/suderra-factory-reset` ve birimi (16, 17 b–c). |
| DEC-18 | P1: PARTUUID bağlama, usbguard ve USB ingress, konsolsuz prod, U-Boot `bootdelay=-2` (`-1` bu U-Boot'ta prompt'ta durur) ve redundant env, `/boot` yalnız kurulumda rw (18.1–18.5). |
| DEC-19 | P0: env tabanlı üretim modu ve güvenlik override'ları kaldırılır; env-okuma invariant testi. |
| DEC-21 | P0: agent unit'i TPM cihazı almaz (`/dev/tpm0` ve `/dev/tpmrm0` kaldırılır). P1: TPM kaynak kaydı ve contract testi. P2: rastgele owner/lockout auth; ardından `/dev/tpmrm0` yalnız TPM keystore etkin `tpm` profilinin kart drop-in'inde (EDGE-MEDIUM-099). `/dev/tpm0` hiçbir fazda verilmez. |
| DEC-22 | P0: imza altındaki `tenant_id` ve bundle'ın tenant kapsamı doğrulanır. |
| DEC-23 | P0: `/etc/os-release`'te `SUDERRA_AGENT_ABI`; `suderra-ota` ön kontrolü. P1: OS güncelleme teslimi. |
| DEC-24 | P0: mutable-state tablosu, prod defconfig'lerde `BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW=n`, volatile journal, sandbox EROFS testi. P1: prod-QEMU EROFS boot testi, `/data` büyütme, eMMC telemetrisi. |
| DEC-25 | P0: `contracts/suderra-edge/` digest ile vendor edilir; `.github/workflows/image-build.yml`'daki `edge-e2e` job'u `suderra_qemu_x86_64_defconfig` üzerinde `tests/qemu/edge-provisioning-e2e.py`'yi her PR'da koşar. P1: aynı job'a güncelleme, rollback ve site-config senaryoları; `.github/workflows/production-runtime-qemu.yml` release kanıtı rolünde kalır ve prod_ab senaryosunu kazanır. |
| DEC-26 | P0: `suderra-display.service` imaja girmez (image-contract testi). |
| DEC-27 | P0: root worker'lar tipli sonuçları `/data/suderra/os/results/` altına yazar ve `/run/suderra/results/`'ta gösterir. |

DEC-20 ve DEC-28 bu repoya iş yüklemez.

### Değiştirilen OS ADR'ları

- **ADR-0004 (RAUC + A/B):** RAUC compatible kart başınadır (ADR-048 DEC-8.3). Health-check adımı
  DEC-6.8'deki gate'tir ve tek mark-good yolu vardır (DEC-2.8). OS bundle'ları root istek kanalıyla
  gelir; reboot zamanlanmış ve onaylıdır (DEC-2.9, DEC-13.4). Agent verisi
  `/data/suderra/agent`'tadır (DEC-4.2).
- **ADR-0005 (dm-verity + Secure Boot):** Agent rootfs zincirinin parçası değildir (DEC-1.5, DEC-1.6);
  P2'den itibaren agent release imajının root hash imzasını kernel, imzalı kernel build'ine gömülü
  `edge-image` sertifikasıyla zorlar (DEC-1.6, DEC-3.3).
  "PROD: SSH YOK" satırı şöyle değişir: PROD'da SSH yalnız PROVISIONING ve yeniden provisioning
  amaçlı MAINTENANCE'ta, süreli ve arayüz kapsamlı olarak vardır (DEC-5). x86 prod güven kökü Suderra
  PK/KEK/db'dir; Microsoft UEFI CA yalnız seçilen modelin option ROM'ları gerektiriyorsa db'de kalır;
  MOK yalnız dev içindir (DEC-8.9). `/etc`'in yazılabilir kısmı `/data/suderra/site`'tır (DEC-4.2).
  Disk anahtarı mühürü DEC-14'tür.
- **ADR-0007 (ARM doğrulanmış boot):** RevPi Connect 4 ayrı bir board'dur (DEC-8.6, DEC-8.7); G4
  RevPi BSP kontrollerini içerir. corr-M3 kart başına compatible ile kapanır (DEC-8.3). H2 (OTP
  secure boot) operatör kararına ve KUNBUS'un yazılı görüşüne bağlanır ve U-Boot measured boot +
  imzalı PolicyAuthorize ile tamamlanır (DEC-14.2). RPi4/CM4'ün üretim kullanımı ADR-048'deki açık
  operatör sorusudur. U-Boot env redundant olur, `bootdelay=-2` (DEC-18; `-1` bu U-Boot'ta prompt'ta durur, ADR-0007). Kernel hattı tek 6.12 LTS
  majörüdür (DEC-8.12).

Bu üç ADR'ın başlıklarına değişiklik notu eklemek ADR-048 P0 kapsamındadır.

## Consequences

Sonuçlar ve riskler ADR-048'in Consequences bölümündedir. Bu repo için: prod imaj koşullu provisioning
birimleri (dropbear dahil) taşır; RevPi yeni bir board dizini ve kernel-module paketi kazanır; installer
kabuk betikleri Rust alt komutlarına taşınır; image-build workflow'u her PR'da bir uçtan uca QEMU
job'u koşar.

## Implementation Notes

- Fazlar, çıkış kriterleri ve saha devreye alma kapıları: ADR-048 §Implementation. P0 "zincir
  çalışır" çıkışı, `image-build.yml`'daki `edge-e2e` job'unda QEMU x86 dev imajı üzerinde otomatik
  uçtan uca provisioning testidir.
- Bulgular: `docs/assessments/2026-10-19-edge-agent-integration-audit.md` (`EI-NNN`). Bu repodaki her
  uygulama commit'i `Refs: docs/assessments/2026-10-19-edge-agent-integration-audit.md#<finding-id>`
  satırı taşır. Kapanış kuralı ADR-048 §Implementation'dadır: parçaları farklı fazlara düşen bir
  bulgu son parçanın fazında kapanır (örneğin EI-037: x86 işi P1, ARM measured boot/OTP işi P3).
- Kalıntı riskler aquaculture_platform bulgu kaydındadır (EDGE-MEDIUM-116…EDGE-LOW-127; tablo
  ADR-048 §Implementation, "Takip edilen kalıntı riskler"). Bu repoya düşenler: EDGE-MEDIUM-116
  (DEC-1.6), EDGE-MEDIUM-118 (DEC-2.11), EDGE-MEDIUM-120 (DEC-8.11), EDGE-MEDIUM-124 (DEC-12),
  EDGE-LOW-125 (DEC-5).

## References

- [aquaculture_platform ADR-048](https://github.com/Okan-wqm/aquaculture_platform/blob/main/docs/adr/048-suderra-os-edge-agent-integration-contract.md)
- ADR-0004, ADR-0005, ADR-0006, ADR-0007
- aquaculture_platform ADR-019 (Suderra OS profili için kısmen değiştirildi), ADR-047
