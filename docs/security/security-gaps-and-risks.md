# Suderra OS — Güvenlik Eksikleri & Riskleri (teyit edilmiş kayıt)

> Bu, mimarinin **teyit edilmiş** eksik/risk kaydıdır — üç bağımsız kod incelemesiyle
> (Rust userspace + ağ, cihaz-donanım güvenliği, build/release zinciri) `dosya:satır`
> temelinde doğrulanmıştır. Spekülasyon yok; her madde koddan kanıtlıdır.
>
> Nasıl çalıştığının anlatımı için: [security-architecture.md](security-architecture.md).
> Tarih: 2026-07-06. **Güncelleme 2026-07-11:** ikinci bağımsız uçtan-uca inceleme
> (güvenlik + kod-doğruluğu + performans) yapıldı; yeni bulgular ve çözüm durumu
> [Kategori 6](#kategori-6--ikinci-bağımsız-inceleme-2026-07-11)'da. Bütünsel çözüm
> mimarisi: [ADR-0008](../architecture/ADR-0008-device-trust-architecture.md).

## Nasıl okunmalı — iki risk türü

- **[GATED]** — Zaten biliniyor, dokümante edilmiş ve `production_ready:false` ile kapılı.
  Bu bir "hata" değil; donanım/HSM gelene dek **kasıtlı fail-closed** duruş. Yol haritasında.
- **[AKSİYON]** — Gerçek bir implementasyon boşluğu veya tutarsızlık; kapatılması gerekir.
  Bunlar "mimarisi var, kodu yok" veya "doküman↔kod çelişkisi" kalemleridir.

## Özet tablo (öncelik sırası)

| # | Bulgu | Kategori | Ciddiyet | Tür |
|---|---|---|---|---|
| RT-1 | `/data` at-rest şifreleme provisioning'i YOK | Runtime | **Kritik** | AKSİYON |
| RT-2 | TPM cihazda hiç kullanılmıyor (attestation + seal iskele) | Runtime | **Yüksek** | AKSİYON |
| RT-3 | Kriptografik cihaz kimliği / enrollment yok (plaintext serial) | Runtime | **Yüksek** | AKSİYON |
| DOC-1 | `/data` "LUKS2 provision edilir" iddiası — kod yok | Doküman | **Yüksek** | AKSİYON |
| RT-4 | 4 güvenlik crate'i placeholder (firstboot/telemetry/attestation/factory-reset) | Runtime | Orta | AKSİYON |
| RT-5 | `systemd-cryptsetup` (tpm2 token) hiçbir defconfig'te yok | Runtime | Orta | AKSİYON |
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

## Güncelleme — Dalga 3 (2026-07-11): TPM yazılım tarafı kapatıldı

**RT-2 / RT-3 / RT-6 yazılım tarafı UYGULANDI** (ADR-0009; donanım kanıtı G5'te
`production_ready:false` ile dürüstçe korunur):

- **RT-6 — Çözüldü (swtpm-kanıtı kaldı):** anti-rollback floor kaynağı env'den
  imzalı `/etc/suderra/ota.conf`'a (dm-verity RO) taşındı; `suderra-ota floor
  sync` gerçek TPM-NV monotonic counter'ı okur, imaj epoch'uyla çapraz doğrular,
  downgrade fail-closed; `firstboot` counter'ı tanımlar/yükseltir, `mark-good`
  ilerletir. Birim + contract testli. "Etikette TPM" durumu kapandı.
- **RT-2 — Kod uygulandı; cihaz-üstü wiring + swtpm/G5 kanıtı BEKLİYOR:**
  `suderra-attestation` placeholder → gerçek CLI (setup/baseline/quote/verify-local;
  PCR 0-7 AK-imzalı quote; verify-local AK-pinlemeli). Doğrulayıcı sunucu bilinçli
  kapsam dışı. **DİKKAT (kod incelemesi):** attestation firstboot tarafından
  çağrılır, ama firstboot binary'si bugün hiçbir imajda çalışmıyor (bkz. RT-3) →
  RT-2 cihazda henüz aktif değil.
- **RT-3 — Kod uygulandı; cihaz-üstü wiring BEKLİYOR:** `firstboot` TPM-resident
  ECC signing key + self-attested `device.json` üretir; X.509 CSR bilinçle
  ertelendi. **DİKKAT (kod incelemesi):** `suderra-firstboot` Rust binary'si board
  overlay'deki placeholder shell unit tarafından isim-gölgelenir ve prod'da hiç
  enable edilmez → identity/attestation adımları cihazda çalışmıyor. Prod'da
  devreye alma Dalga 3'ün kalan wiring adımı (ADR-0009). RT-6 anti-rollback ise
  buna BAĞIMLI DEĞİL: floor sync NV counter'ı kendisi tanımlar (fail-closed brick
  önlendi).
- **Kalan:** QEMU+swtpm senaryoları (`production-runtime-qemu.yml` lane) ve G5
  donanım kanıtı. `suderra_config::tpm` sarmalayıcısı sahte-tpm2 birim testleriyle
  kapsanır. **RT-4** kısmen: firstboot/attestation gerçek; telemetry/factory-reset
  hâlâ placeholder (bu denetimde kritik yolda değil).

---

## Kategori 1 — Cihaz-içi runtime güvenlik boşlukları (en yüksek öncelik)

### RT-1 — `/data` at-rest şifreleme provisioning'i YOK — **Kritik / AKSİYON**

**Kanıt:** Repo-geneli grep `luksFormat|cryptenroll|luksAddKey|tpm2_create` → sadece placeholder
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

### RT-5 — `systemd-cryptsetup` / systemd-tpm2 token handler yok — Orta / AKSİYON

`suderra-data-unlock:63-71` systemd'nin tpm2 cryptsetup token'ına bağlı ama
`BR2_PACKAGE_SYSTEMD_CRYPTSETUP` hiçbir defconfig'te açık değil. LUKS volume olsa bile hem tercih
edilen hem fallback unlock yolu muhtemelen işlevsiz. (RT-1 ile birlikte düzeltilmeli.)

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

---

## Kategori 6 — İkinci bağımsız inceleme (2026-07-11)

Dört bağımsız agent (build/CI performansı, runtime/boot ayak izi, bağımsız güvenlik
doğrulama + yeni-bug avı, Rust kod-doğruluğu) + çapraz-doğrulama. Kategori 1–5
teyit edildi (register sağlam). Aşağıdakiler **register'da OLMAYAN** yeni bulgular ve
her birinin çözüm durumudur. Bütünsel mimari:
[ADR-0008](../architecture/ADR-0008-device-trust-architecture.md).

### Yeni güvenlik bulguları

| # | Bulgu | Ciddiyet | Durum |
|---|---|---|---|
| NEW-1 | OTA `is_production()` yalnız hiçbir yerde set edilmeyen env'le true → anti-rollback trusted-floor + dev-override reddi her cihazda ölü; env ile bypass | **Yüksek** | **Çözüldü** (Dalga 1): prod-tespiti imzalı os-release VARIANT'ından; anti-rollback katmanlı (Tier-1/2); build gate VARIANT=prod assert eder |
| NEW-2 | nftables egress hedefe göre kısıtsız (exfiltration; 502/4840 lateral) | Orta | **Çözüldü — politika** (Dalga 4): appliance ruleset'i fail-closed named-set allow-list'e çevrildi (egress_update/cloud/field/infra), imzalı RO `/etc/suderra/egress.d/*.nft`'ten doldurulur, `nft -c` ile doğrulandı + contract test. **Sahada aktifleşmesi NEW-5'e bağlı** (cihazın appliance-locked ruleset'e geçmesi) |
| NEW-3 | `variant::is_production()` env ile prod'u DOWNGRADE edebiliyordu (+ boş-env fail-open) | Orta | **Çözüldü** (Dalga 1) |
| NEW-4 | `suderra-agent.service` indirilen harici ajana `/dev/tpm0`+`/dev/watchdog` veriyor | Orta | **Çözüldü** (Dalga 4): board+paket agent unit'lerinden `DeviceAllow=/dev/watchdog\|tpm0\|tpmrm0` kaldırıldı (agent sd-notify; TPM Suderra daemon'larının işi — ADR-0009); `suderra-watchdog` ilk kez paketlendi (tek sahip) |
| NEW-5 | Appliance firewall prod'da aktive olmuyor; provisioning ruleset kalıcı default | Düşük | **Çözüldü** (Dalga 4): `suderra-firewall` seçicisi imzalı `VARIANT=prod` güven köküne çapalandı → appliance ruleset KOŞULSUZ; yazılabilir marker prod'u provisioning'e düşüremez; contract test. NEW-2'yi sahada etkin kılar |
| NEW-6 | Dev firstboot provisioning parolasını `/dev/console`'a basıyor (dev-only) | Düşük | **Çözüldü** (#84 Dalga 4) — 0600 `credentials.env` işaretçisi |
| NEW-7 | Ed25519 `verify` (strict değil) + non-canonical imza serileştirme | Düşük | **Çözüldü**: `verify_strict` (Dalga 1) + kanonik imza baytları `suderra-config::canonical`'a birleştirildi, imza `-v2` temiz kırılımı + diller-arası golden vektör (AUD-4) |

### Kod-doğruluğu bug'ları (gerçek crate'ler)

| # | Bulgu | Ciddiyet | Durum |
|---|---|---|---|
| C-1 | `variant::is_production()` set-but-empty env → fail-open | Orta | **Çözüldü** (Dalga 1) |
| C-2 | Watchdog besleme aralığı donanım timeout'una kısıtsız → sağlıklı cihazı reset döngüsü | Orta | **Çözüldü** (Dalga 1) |
| C-3 | Watchdog tick'inde timeout'suz `systemctl` → wedge kick açlığı → reset | Orta | **Çözüldü** (Dalga 1) |
| C-4 | `mark-good --version X` pending yokken floor'u kalıcı yükseltir → update-kilidi DoS | Orta | **Çözüldü** (Dalga 1) |
| C-5 | `restart_after + 1` overflow (hostile env) | Düşük | **Çözüldü** (Dalga 1, `saturating_add`) |
| C-6 | TOCTOU (verify→use) OTA bundle / installer manifest | Düşük–Orta | **Çözüldü**: installer tek-okuma (boyut+sha256+imza aynı tampon); ota root-0700 staging'e atomik rename + fd üzerinden yeniden hash (kalan risk kod yorumunda; RAUC bağımsız imza doğrular) |
| C-7 | Non-SemVer `VERSION_ID` OTA'yı bricker (fail-closed availability) | Düşük | **Çözüldü**: post-build SemVer build kapısı + install girişinde erken teşhis; contract test |

### Register kalemlerinde ilerleme

- **RT-1** (`/data` LUKS2 provisioning yok) → **Çözüldü** (ADR-0008 Dalga 2): `suderra-data-provision`, TPM2-seal default + fail-closed; runtime kanıtı QEMU-swtpm/G5.
- **RT-5** (`systemd-cryptsetup` yok) → **Çözüldü** (Dalga 2): 3 prod defconfig'te `BR2_PACKAGE_SYSTEMD_CRYPTSETUP=y`.
- **DOC-1** (`/data` LUKS iddiası, kod yok) → **Çözüldü** (Dalga 2, provisioning uygulandı).
- **RT-6** (TPM-NV anti-rollback etiket) → NEW-1 ile derinleşti; Tier-2 kaynağı ADR-0008 Dalga 3'te (gerçek TPM-NV).
- **DOC-2 / DOC-3** → **Çözüldü** (Dalga 5): ARCHITECTURE ağ yüzeyi OS/iş-yükü ayrımıyla netleşti; ROADMAP gerçek-durum tablosuyla hizalandı.

### Performans bulguları (özet — ADR-0008 Dalga 6)

- **Build/CI:** cross-toolchain her build'de sıfırdan; dl/ccache cache defconfig-parçalı + `restore-keys` yok → 10 GB bütçe eviction thrash; Docker builder run başına ~5× layer-cache'siz; redundant smoke/parse + `msrv` cache'siz.
- **Footprint (çoğu iyi optimize):** **Çözüldü** → kullanılmayan `reqwest` `ota`/`telemetry`/`attestation`'dan çıkarıldı (MIN-2); `tokio` `full` yerine crate-başı feature (48 satır transitive dep düştü); `i2c-tools` prod'dan çıkarıldı. **Açık:** ikili TLS yığını (OpenSSL+rustls, M-effort); `tpm2-tools` prod'da (post-image gate + Wave 3 attestation'a bağlı); `network-online.target` DHCP boot-stall (~120 s, boot-test gerekir).
- **Hijyen:** **Çözüldü** → workspace-geneli `unsafe_code = "deny"` + hedefli watchdog allow (MIN-3, negatif testle kanıtlı).
