# Suderra OS — Güvenlik Eksikleri & Riskleri (teyit edilmiş kayıt)

> Bu, mimarinin **teyit edilmiş** eksik/risk kaydıdır — üç bağımsız kod incelemesiyle
> (Rust userspace + ağ, cihaz-donanım güvenliği, build/release zinciri) `dosya:satır`
> temelinde doğrulanmıştır. Spekülasyon yok; her madde koddan kanıtlıdır.
>
> Nasıl çalıştığının anlatımı için: [security-architecture.md](security-architecture.md).
> Tarih: 2026-07-06.

## Nasıl okunmalı — iki risk türü

- **[GATED]** — Zaten biliniyor, dokümante edilmiş ve `production_ready:false` ile kapılı.
  Bu bir "hata" değil; donanım/HSM gelene dek **kasıtlı fail-closed** duruş. Yol haritasında.
- **[AKSİYON]** — Gerçek bir implementasyon boşluğu veya tutarsızlık; kapatılması gerekir.
  Bunlar "mimarisi var, kodu yok" veya "doküman↔kod çelişkisi" kalemleridir.

## Özet tablo (öncelik sırası)

| # | Bulgu | Kategori | Ciddiyet | Tür |
|---|---|---|---|---|
| RT-1 | `/data` at-rest şifreleme provisioning'i YOK | Runtime | **Kritik** | ✅ UYGULANDI (G5 donanım) |
| RT-2 | TPM cihazda hiç kullanılmıyor (attestation + seal iskele) | Runtime | **Yüksek** | KISMİ (seal RT-1'de; attestation AKSİYON) |
| RT-3 | Kriptografik cihaz kimliği / enrollment yok (plaintext serial) | Runtime | **Yüksek** | AKSİYON |
| DOC-1 | `/data` "LUKS2 provision edilir" iddiası — kod yok | Doküman | **Yüksek** | ✅ UYGULANDI (RT-1 ile) |
| RT-4 | 4 güvenlik crate'i placeholder (firstboot/telemetry/attestation/factory-reset) | Runtime | Orta | AKSİYON |
| RT-5 | `systemd-cryptsetup` (tpm2 token) yok sanılıyordu | Runtime | Orta | ✅ ÇÜRÜTÜLDÜ (otomatik açık) |
| RT-6 | "TPM-backed anti-rollback" etikette (TPM NV çağrısı yok) | Runtime | Orta | AKSİYON |
| DOC-2 | ARCHITECTURE.md ağ yüzeyi (Modbus/OPC-UA/MQTT/mTLS) implemente değil | Doküman | Orta | AKSİYON |
| DOC-3 | ROADMAP.md güncel değil (kod yol haritasının önünde) | Doküman | Düşük | AKSİYON |
| SC-1 | HSM kanıtı self-attested (hardware_backed beyan alanı) | Tedarik | Orta | GATED |
| SC-2 | Cross-board RAUC kabulü (paylaşılan compatible) | OTA | Orta | GATED |
| SC-3 | Non-prod'da `SUDERRA_INSECURE` ile TLS doğrulama kapatılabilir | Ağ | Düşük | AKSİYON |
| HW-1 | ARM FIT enforcement donanımda kanıtsız (OF_CONTROL) | Boot | **Yüksek** | GATED (G4) |
| HW-2 | ARM ilk-aşama imzasız (OTP secure boot yok) | Boot | **Yüksek** | GATED (G5) |
| HW-3 | ARM verity-cmdline + module signing | Boot | Orta | GATED (G4) |
| HW-4 | x86 cihaz-tarafı SB enrollment out-of-band | Boot | Orta | GATED |
| MIN-* | Ölü/kullanılmayan güven materyali, lint policy, vb. | Hijyen | Düşük | AKSİYON |

---

## Kategori 1 — Cihaz-içi runtime güvenlik boşlukları (en yüksek öncelik)

### RT-1 — `/data` at-rest şifreleme provisioning'i — **Kritik / ✅ UYGULANDI (G5 donanım bekliyor)**

> **Çözüm (uygulandı):** `suderra-data-unlock` prod yolu artık ilk boot'ta BLANK data
> partition'ını LUKS2 formatlar ve anahtarı **TPM2'ye seal eder** (PCR7-bound,
> `systemd-cryptenroll --tpm2-device=auto`), ephemeral passphrase slot'unu siler → TPM2
> tek unlock yolu. **Fail-closed:** TPM yoksa provision edilmez (kullanıcı kararı: on-disk
> keyfile ile sahte güven YOK). **Güvenlik guard'ı:** yalnız blank partition formatlanır —
> mevcut fs/imza görülürse (blkid) REDDEDİLİR (kaza sonucu veri kaybı yok). `SYSTEMD_CRYPTSETUP`
> 4 prod defconfig'e eklendi (RT-5). LUKS mekaniği (format→open→mkfs→mount→kalıcılık +
> dolu-partition reddi) loopback ile doğrulandı; `data-luks-provision-contract-test.sh` statik
> olarak zorlar; enforce_production_contract paketleri gate'ler. **KALAN:** gerçek TPM2
> seal/unseal donanım/swtpm ister → G5 (`data-luks-swtpm` QEMU senaryosu + hardware lab).

**Kanıt (düzeltme öncesi durum):** Repo-geneli grep `luksFormat|cryptenroll|luksAddKey|tpm2_create` → sadece placeholder
doküman/yorum. `firstboot` (amaçlanan provisioner) no-op ve her defconfig'te kapalı
(`userspace/suderra-firstboot/src/main.rs:39-49`). genimage `data` partition'ı boş/formatsız
(`board/suderra/aarch64-rpi4/genimage-prod.cfg:76-81`).

**Etki:** Bir PROD imajda LUKS2 volume hiç oluşturulmadığından `suderra-data-unlock:52` (`isLuks`
kontrolü) `exit 1` verir → `suderra-data.service` başarısız olur. **Bugün prod cihazda `/data`
şifreli-at-rest değildir.** DEV imajlarda `/data` tasarım gereği düz ext4 (`suderra-data-unlock:27-37`).
Bu, dış incelemecinin haklı olarak sorduğu "cihaz çalınırsa veri/sırlar" senaryosunun tam merkezi.

**Yön:** `firstboot`'u gerçekten uygula — ilk boot'ta `/data`'yı LUKS2 `luksFormat` et, anahtarı
RevPi'de TPM2 PCR'lara `systemd-cryptenroll --tpm2-device`, rpi4'te keyfile ile enroll et; sonra
mapper'ı `mkfs`. `data-luks-swtpm` QEMU senaryosunu gerçek seal doğrulayacak şekilde güçlendir.
Bu, G5 donanım kanıtının da ön koşulu.

### RT-2 — TPM 2.0 cihazda hiç kullanılmıyor — **Yüksek / AKSİYON**

**Kanıt:** `suderra-attestation` saf placeholder (`main.rs:37-44`), `tss-esapi` yok (yalnız yorumda),
paketlenmiyor, **sıfır** defconfig'te. Kernel TPM sürücüleri + `tpm2-tools` prod'da var ama hiçbir
kod TPM ile konuşmuyor. RevPi SLB9670 seal / rpi4 keyfile ayrımı yalnız yorumda.

**Etki:** Boot state attestation (cihazın kurcalanmamış donanım+yazılıma sahip olduğunun kanıtı)
ve TPM-seal (RT-1'in anahtarı) yok. IEC 62443 "hardware root of trust" iddiası şu an TPM sürücüsü
seviyesinde kalıyor.

**Yön:** `suderra-attestation`'a `tss-esapi` ile PCR 0-7 quote üret + bir doğrulayıcıya gönder;
paketle + prod defconfig'lere ekle. (Doğrulayıcı taraf da repoda yok — kapsam kararı gerekir.)

### RT-3 — Kriptografik cihaz kimliği / enrollment yok — **Yüksek / AKSİYON**

**Kanıt:** İlk boot kimliği plaintext YAML (`suderra-firstboot.service:52-68`,
`device_id: 0000...`, `UNACTIVATED`). `suderra-config` struct'ında cert/key/CSR alanı yok
(`lib.rs:25-35`); "mTLS endpoint" yalnız bir yorum. Diskte cert materyali yok; `cloud_enroll` TODO.

**Etki:** Cihaz kimliği kimliksiz bir seri string. Merkez panele mTLS ile kimlik-doğrulamalı
bağlantı (dış incelemecinin sorduğu) yok. Cihaz klonlanabilir/taklit edilebilir.

**Yön:** İlk boot'ta TPM-bağlı bir anahtar çifti üret (attestation identity), CSR ile merkeze
enroll et, dönen client sertifikasını TPM-korumalı sakla; iş yükü (sens-api-gateway) mTLS'te bunu
kullansın. RT-2 ile birlikte gider.

### RT-4 — 4 güvenlik crate'i placeholder — Orta / AKSİYON

`suderra-{firstboot,telemetry,attestation,factory-reset}` yalnız log + exit. Reklamı yapılan
işlevler (LUKS init, TPM seal, cloud enroll, PCR attestation, factory reset) uygulanmamış. Bu
crate'ler workspace'te derleniyor ama (attestation hariç bazıları) imaja bile girmiyor.

### RT-5 — `systemd-cryptsetup`/tpm2 token — Orta / ✅ ÇÜRÜTÜLDÜ (aslında sorun değildi)

Denetim "`BR2_PACKAGE_SYSTEMD_CRYPTSETUP` hiçbir defconfig'te yok" demişti — ancak bu Buildroot
sürümünde **öyle bir sembol yoktur**. systemd cryptsetup+tpm2 desteği `BR2_PACKAGE_CRYPTSETUP` +
`BR2_PACKAGE_TPM2_TSS` ile OTOMATİK açılır (`buildroot/package/systemd/systemd.mk:159-161,635-637`
→ `-Dlibcryptsetup=enabled` + `-Dtpm2=enabled`), ve ikisi de prod defconfig'lerde açıktır. Yani
`systemd-cryptsetup` + `systemd-cryptenroll --tpm2` prod imajlarda zaten üretilir. RT-1 doğrulaması
sırasında (resolved `.config` parse edilerek) yakalandı: defconfig'e ölü sembol eklemek işe yaramaz;
gerçek gate `CRYPTSETUP + TPM2_TSS`'tir (enforce + contract test bunları zorlar). Ders: **yeşil
defconfig metni ≠ resolved config** — sembol var mı diye parse ile doğrula.

### RT-6 — "TPM-backed anti-rollback" etikette kalıyor — Orta / AKSİYON

`suderra-ota` rollback floor'u bir **dosyadan** okur (`main.rs:672-685`);
`SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE=tpm-nv` yalnız bir etiket doğrular — **gerçek TPM NV API çağrısı
yok**. Garanti, dosyayı `/data` dışında dolduran band-dışı bir bileşene bağlı. (Floor kaynağının
yazılabilir dizinde olmasını doğru reddediyor, ama "TPM NV" iddiası enforce edileni aşıyor.)

### RT-7 — `data-luks-open` health gate'inin arkasında implementasyon yok — Orta / AKSİYON

`evidence-contract.yml:646,700,724,748` prod health-check olarak `data-luks-open` ister; ama RT-1
gereği hiçbir kod LUKS provision etmediğinden (QEMU prod lane dahil) bu kontrolün arkası boş.
`data-luks-swtpm` senaryosu yalnız mapper mount'u **gözler**, TPM seal'i kanıtlamaz.

---

## Kategori 2 — Doküman ↔ kod tutarsızlıkları

### DOC-1 — `/data` "LUKS2 provision edilir, düz ext4 SEVK EDİLMEZ" — **Yüksek / AKSİYON**

genimage yorumları (`genimage-prod.cfg`) ve health gate'ler bunu iddia eder; provisioning kodu
yoktur (RT-1). Bu, okuyucuyu "at-rest şifreli" sanmaya yöneltir. Ya kodu yaz (tercih), ya iddiayı
"planlanan (G5)" olarak işaretle.

### DOC-2 — ARCHITECTURE.md ağ yüzeyi implemente değil — Orta / AKSİYON

`ARCHITECTURE.md` "Network Yüzeyi" tablosu Modbus TCP 502 / OPC-UA 4840 / MQTT 8883 (mTLS)
listeler. Bunlar OS'un kendisinde **yok** — harici, kapalı `suderra-edge-agent`
(`aquaculture_platform/sens-api-gateway`) iş yüküne aittir. Tabloyu "OS'un barındırdığı iş yükünün
yüzeyi" diye netleştir; OS ile iş yükünü ayır.

### DOC-3 — ROADMAP.md güncel değil — Düşük / AKSİYON

`ROADMAP.md` "Faz 0 tamam → Faz 1 girişi (ilk boot)" der ve boot-integrity/OTA'yı Faz 3/4 gelecek
gösterir; oysa imzalı-FIT/UKI boot, dm-verity, RAUC OTA, HSM imzalama **zaten uygulanmış**. Yol
haritası gerçekliğin gerisinde — güncellenmeli (aksi halde olgunluk yanlış değerlendirilir).

---

## Kategori 3 — Boot/build zinciri donanım-kapılı boşluklar (dokümante, kabul edilmiş)

Bunlar [GATED] — `production_ready:false` ile tutuluyor, [ADR-0007](../architecture/ADR-0007-arm-verity-ab-boot-chain.md)'de
kesin G4/G5 listesi olarak yazılı. Yeni "hata" değil; donanım gelince kapanacak.

- **HW-1 (G4) — ARM FIT enforcement donanımda kanıtsız.** Build gate anahtarın `u-boot.dtb`'de
  `required="conf"` olduğunu doğrular ama `rpi_arm64`'te bu DTB runtime control FDT olmayabilir;
  fragment `CONFIG_OF_CONTROL` set ediyor, `CONFIG_OF_SEPARATE` değil. Gerçek Pi'de doğrulanmalı.
- **HW-2 (G5) — ARM ilk-aşama imzasız.** GPU firmware → u-boot.bin/boot.scr yol imzasız; yalnız
  CM4/RevPi OTP secure boot ile korunur (fiziksel/depolama swap riski).
- **HW-3 (G4) — ARM verity-cmdline delivery + module signing.** ARM cmdline'da `module.sig_enforce`
  yok (x86'da var); ARM'da `CONFIG_MODULE_SIG_FORCE` yok (paylaşılan kernel config, dev'i kırar).
- **HW-4 — x86 cihaz-tarafı SB enrollment out-of-band.** İmzasız-UKI reddi kriptografik kanıtı
  yalnız QEMU/OVMF yolunda; sevk edilen donanımda db enrollment'ı hiçbir şey zorlamaz.
- **HW-5 — Anti-rollback userspace-only.** Monotonluk yalnız `suderra-ota`'da; ham `rauc install`
  ile geçerli-imzalı eski bundle floor'u atlar. Trusted monotonik çapa (TPM NV / bootloader) G5.

---

## Kategori 4 — Tedarik-zinciri / kripto ince boşluklar

- **SC-1 [GATED] — HSM kanıtı self-attested.** Crypto replay cert'in anahtarının imzaladığını
  kanıtlar; ama `hardware_backed`, `key.extractable=false`, provider adı **beyan edilen** alanlar,
  HSM'in canlı attestation quote'u değil. Kontrol: vetted-provider allowlist + SoftHSM negatif +
  imza replay (güçlü ama seremoni metadata'sına güvenir).
- **SC-2 [GATED] — Cross-board RAUC.** rpi4/revpi4 aynı `compatible=suderra-os-aarch64`
  (`system.conf.arm:2`) → RAUC cross-board bundle kabul eder; multi-board FIT kısmen azaltır.
  Kalıcı çözüm board-aware config (arch-shared refactor).
- **SC-3 [AKSİYON] — Non-prod TLS bypass.** `SUDERRA_INSECURE=1` → `danger_accept_invalid_certs`
  (`download.rs:130-145`); prod'da bloklu, ama dev/staging'de sessiz MITM'e açık (cosign/SHA256
  aşağı-akışta azaltır, o da non-prod'da kapatılabilir).
- **SC-4 [AKSİYON] — cosign harici binary bağımlılığı.** İmza doğrulaması `cosign` subprocess'ine
  bağlı (`verify.rs:31-103`); yoksa fail-closed. Native sigstore-rs "Faz 3" TODO — artefakt
  otantikliği harici araca + TUF köküne bağlı.

---

## Kategori 5 — Hijyen / küçük

- **MIN-1 — Ölü verity-signing anahtarı.** `verity-signing.crt` `/etc/dm-verity/pubkey.pem`'e
  kurulur (`suderra-keys.mk:74-76`) ama boot verity yolu onu tüketmez (root hash imzalı cmdline'dan
  güvenilir). Kullanılmayan güven materyali — ya `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` ile bağla,
  ya kaldır.
- **MIN-2 — Kullanılmayan ağır bağımlılıklar.** `reqwest` (rustls/hyper/quinn çeker)
  `suderra-{ota,telemetry,attestation}`'da tanımlı ama kullanılmıyor — gereksiz saldırı yüzeyi.
- **MIN-3 — Workspace-level lint policy yok.** `[workspace.lints]` yok; `forbid(unsafe_code)`
  yalnız 8 crate'in 2'sinde. İleride bir crate `unsafe`/lint regresyonu sokabilir.
- **MIN-4 — `config.validate()` yanıltıcı.** URL'yi "mTLS endpoint" diye etiketler ama yalnız
  `https://` prefix kontrolü yapar (`lib.rs:85-89`).

---

## Önerilen kapatma sırası (var→eksik yol haritası)

1. **RT-1 + DOC-1 + RT-5 + RT-7** birlikte: `/data` LUKS2 provisioning'i (firstboot) gerçekten
   uygula + `systemd-cryptsetup` ekle + QEMU seal doğrulaması. **En yüksek değer** — hem gerçek
   at-rest şifrelemeyi getirir, hem "iddia var kod yok" tutarsızlığını kapatır, hem G5'in ön koşulu.
2. **RT-2 + RT-3**: TPM attestation + TPM-bağlı cihaz kimliği/enrollment. Bunlar birlikte "cihaz
   güveni" eksenini ayağa kaldırır (dış incelemecinin asıl sorduğu şey).
3. **DOC-2 + DOC-3**: dokümanları kod gerçeğiyle hizala (OS vs iş yükü ayrımı; roadmap güncelle).
4. **RT-6 → HW-5**: anti-rollback için gerçek TPM NV / bootloader monotonik çapa.
5. **SC-3, SC-4, MIN-***: hijyen — non-prod TLS sıkılaştırma, native sigstore, ölü anahtar,
   workspace lints.
6. **HW-1..HW-4 (G4/G5)**: donanım geldiğinde — ADR-0007'deki turnkey liste.
