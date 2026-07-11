# ADR-0009: TPM 2.0 implementasyon seçimleri (subprocess, NV yerleşimi, anahtar hiyerarşisi)

- **Status:** Proposed
- **Date:** 2026-07-11
- **Deciders:** @okan-wqm
- **Tags:** security, tpm, attestation, anti-rollback, identity

## Context

ADR-0008 Eksen B (cihaz-içi runtime güven) mimarisini tanımlar; Dalga 3 üç
teyitli açığı kapatır: **RT-2** (TPM attestation cihazda hiç kullanılmıyor),
**RT-3** (kriptografik cihaz kimliği yok), **RT-6** ("TPM-backed anti-rollback"
etikette — gerçek NV çağrısı yok). Bu ADR, Dalga 3'ün *nasıl* implemente
edildiğini kaydeder. ADR-0008 dalga mimarisi sabittir; bu ADR uygulama
kararlarını sabitler (ADR-0007 ↔ ADR-0005 ilişkisiyle aynı).

`tpm2-tools` ve `tpm2-tss` zaten her prod defconfig'te sevk ediliyordu ama
**hiçbir kod TPM ile konuşmuyordu** (denetimde "tüketicisiz ölü ağırlık" olarak
işaretlendi). Bu ADR onları tüketilen mekanizmaya çevirir.

## Karar 1 — subprocess `tpm2-tools`, `tss-esapi` FFI değil

`suderra_config::tpm` modülü `tpm2-tools` alt-araçlarına (`tpm2_nvread`,
`tpm2_quote`, `tpm2_createak`, …) fail-closed exit-code kontrolüyle shell-out
eder.

**Dürüst değerlendirme:**

| | subprocess (`tpm2-tools`) | FFI (`tss-esapi`) |
|---|---|---|
| Repo emsali | rauc (ota), cosign (installer), systemd-cryptenroll (data-provision) — hepsi subprocess | yok (workspace'te libc dışı C-FFI yok) |
| musl cross-compile | ek yük yok | bindgen + tpm2-tss C header'ları + `SUDERRA_RUST_WORKSPACE_BUILD` karmaşıklığı |
| Ölü ağırlık | shipped tpm2-tools'u TÜKETİR | ikinci bir TSS kopyası |
| Tedarik zinciri | `deny.toml` büyümez | yeni crate ağacı + FFI denetimi |
| Hata modeli | exit-code + stderr (mevcut fail-closed desenle aynı) | in-process typed |
| Test seam | `SUDERRA_TPM2_BIN_DIR` ile sahte `tpm2_*` scriptleri (trait yok) | mock için trait makinesi |

**Seçim: subprocess.** Repo emsaliyle birebir uyumlu, shipped araçları tüketir,
cross-compile ve tedarik-zinciri yükü getirmez, mevcut mock desenini (non-prod
env-override binary yolu — `SUDERRA_OTA_RAUC`/`COSIGN_BINARY` gibi) yeniden
kullanır. Yalnız **makine-okur çıktılar** kullanılır (`-o` dosya çıktıları, ham
`nvread` baytları); serbest metin stdout parse edilmez.

Binary çözümü prod'da sabittir (`/usr/bin/tpm2_*`, env ile kaydırılamaz —
güvenlik davranışı prod'da env ile gevşetilemez, #84 `dev_override` sözleşmesi);
non-prod'da `SUDERRA_TPM2_BIN_DIR`/PATH mock için honor edilir.

## Karar 2 — RT-6 NV yerleşimi: 8-byte ORDINARY NV index (epoch ordinal)

> **Düzeltme (kod incelemesi, 2026-07-11):** İlk tasarım `nt=counter` seçmişti.
> Bağımsız uçtan uca inceleme bunun gerçek TPM'de KIRIK olduğunu gösterdi:
> (a) `nt=counter` index'i ilk `NV_Increment`'e kadar `NV_Read`'de UNINITIALIZED
> döner (0 OKUNMAZ) → taze cihazda `floor sync` patlar → prod OTA kilitlenir;
> (b) counter'ın ilk değeri TPM-global bir yüksek-su-işaretine ayarlanır (küçük
> değil) → küçük `rollback_epoch` ordinaliyle karşılaştırma TEMELDEN yanlış.
> Counter kararı geri alındı.

**Reddedilen alternatif (1) — `nt=counter`:** yukarıdaki iki nedenle gerçek
donanımda çalışmaz; birim testleri (sabit-bayt sahte tpm2) bunu yakalayamazdı.

**Seçilen tasarım — ordinary NV index, epoch ordinal'ini DOĞRUDAN tutar:**

- **NV index `0x01500001`** (TCG owner range), **8-byte ordinary** NV
  (`tpm2_nvdefine -s 8 -a "ownerread|ownerwrite|authread|authwrite"`). Tanımdan
  hemen sonra `tpm2_nvwrite` ile **0 yazılır** → sonraki okumalar UNINITIALIZED
  vermez. Değeri BİZ yazdığımızdan mutlak-değer sorunu da yoktur.
- **`/etc/suderra/ota.conf`** (imzalı, dm-verity RO): `rollback_floor_source`,
  `rollback_nv_index`, `rollback_floor_path`, `rollback_floor` (SemVer),
  `rollback_epoch` (ordinal). Kaynak beyanı env'den bu imzalı config'e taşındı
  (prod güven kökü); env yalnız `!is_production()` dev override.
- **epoch karşılaştırması:** NV, `rollback_epoch` ordinal'ini DOĞRUDAN tutar;
  `floor sync` `epoch < nv_ordinal` ise downgrade sayar. Karşılaştırma birimi
  install/mark-good yollarında #84'ün SemVer floor'u OLARAK da KALIR (iki katman).
  **Manifest'e ayrı `rollback_epoch` alanı EKLENMEDİ** — imaj epoch'u `ota.conf`'tan
  gelir; imza format kırılımı Faz 1 (`-v2`) ile sınırlı kalır.
- **Akış:** `suderra-ota floor sync` (boot, mark-good'dan önce) ordinal'i
  idempotent tanımlar (define+0) ve okur; `epoch < ordinal` ise **downgrade →
  fail-closed** (floor yazılmaz → install fail-closed); değilse SemVer floor'u
  `/run/suderra/rollback-epoch`'a yazar. `mark-good` başarısında `nv_raise_ordinal`
  ile ordinal imaj epoch'una tek yazmayla yükseltilir. floor sync ordinal'i kendi
  tanımladığından RT-6, firstboot wiring'inden bağımsızdır.

**Tehdit modeli (dürüst — reddedilen alternatif (2)):** ordinary NV, cihaz root'u
tarafından yeniden yazılabilir. Bu, `/data` silinerek floor sıfırlama saldırısını
engeller (NV, `/data`'dan AYRIdır; factory-reset'e dayanır) — asıl savunulan tehdit
budur. **Online-root'un NV'yi yeniden yazması KAPSAM DIŞIdır** (zaten game-over).
Online-root'a karşı donanım-monotonic anti-rewrite (ör. counter'ı sealing/policy ile
doğru kullanmak, ya da bootloader-measured floor) bir **G5/Wave-7 sertleştirme
kalemi** olarak açık bırakılır. Bu, kırık counter tasarımından net iyileşmedir ve
**swtpm/gerçek-TPM doğrulaması hâlâ zorunludur** — bu yeniden tasarım yerelde yalnız
NV durumunu tutan sadık-mock ile sınanmıştır.

## Karar 3 — anahtar hiyerarşisi ve persistent handle'lar

| Handle | Amaç | Üretim |
|---|---|---|
| `0x81010001` | Attestation Key (AK) | `tpm2_createek` (RSA) → `tpm2_createak` (rsassa/sha256) → evict |
| `0x81010002` | Cihaz kimlik imza anahtarı (RT-3) | `tpm2_createprimary` (ECC) → `tpm2_create` (ecc:ecdsa) → load → evict |
| `0x01500001` | Anti-rollback NV counter (RT-6) | `tpm2_nvdefine nt=counter` |

RT-3 cihaz kimliği **self-attested** bir `device.json`'dur
(`suderra.device-identity.v1`: device_id, TPM pubkey PEM, ek_cert_present,
version_id) — `/data/suderra/identity/` altında. **X.509 CSR YOK**: gerçek
TPM-imzalı CSR `tpm2-openssl` provider'ı (yeni Buildroot paketi + denetim
yüzeyi) gerektirir, üstelik henüz var olmayan bir CA için. Enrollment protokolü
(CSR değişimi, mTLS bootstrap) belgelenmiş bir sözleşme olarak bırakılır; kimlik
dokümanı gelecekteki bir enrollment servisinin ihtiyaç duyacağı her şeyi taşır.

## Doğrulayıcı sunucu — kapsam dışı (dürüst sınır)

Repoda merkezi bir attestation doğrulayıcı / enrollment servisi **yoktur**.
`suderra-attestation` imzalı evidence artifact'i (`suderra.attestation-evidence.v1`:
quote_msg, quote_sig, PCR digest, AK pub, nonce) üretir ve `verify-local` ile
yerel self-check (`tpm2_checkquote` + baseline karşılaştırma) yapar. Uzak bir
doğrulayıcının kontrol etmesi gerekenler:

1. AK pub'ın cihazın EK cert zincirine bağlılığı (TPM üretici cert'i).
2. Quote imzasının AK ile geçerliliği ve nonce tazeliği (replay önleme).
3. PCR 0-7 digest'inin onaylı known-good set'lerden biriyle eşleşmesi.

Sunucu **icat edilmez** — "gereksiz kod yazma" ilkesi.

## Doğrulama ve kalan iş

- **Birim:** `suderra_config::tpm` sahte `tpm2_*` scriptleriyle test edilir (NV
  big-endian parse, fail-closed exit, idempotent define, prod-sabit-yol);
  `floor sync` downgrade reddi + prod-gate `ota.conf` testleri; attestation
  evidence JSON roundtrip; firstboot kimlik doküman serileştirme.
- **Contract:** `ota-rollback-anchor-contract-test.sh` (RT-6 wiring).
- **KALAN (Dalga 3 CI, donanım-gerektirmez ama swtpm gerektirir):** QEMU+swtpm
  senaryoları `tests/qemu/production-runtime.py`'ye eklenecek —
  `tpm-nv-anti-rollback` (downgrade-epoch reddi + pozitif yol counter artışı) ve
  `firstboot-trust-establishment` (temiz disk+swtpm → kimlik/baseline/counter/
  `.provisioned`). `data-luks-swtpm` swtpm state yönetimi ve
  `suderra-runtime-scenario` guest driver'ı GENİŞLETİLİR. Bu lane PR-blocking
  değildir; yerelde swtpm yok, `production-runtime-qemu.yml` dispatch'inde koşar.
- **Donanım (Dalga 7 / G5):** gerçek TPM'de seal/unseal, NV kalıcılığı, PCR
  ölçümleri — `production_ready:false` bu kanıt gelene dek dürüstçe korunur.

### Cihaz-üstü çalıştırma wiring'i (dürüst sınır — kod incelemesinde bulundu)

- **RT-6 (anti-rollback) firstboot'a BAĞIMLI DEĞİLDİR:** `suderra-ota floor sync`
  NV counter'ı **idempotent kendisi tanımlar**; böylece prod OTA yolu, firstboot
  güven-tesis binary'sinin çalışıp çalışmamasından bağımsız fail-closed doğru
  çalışır. `suderra-ota-floor.service` `/run/suderra`'yı `RuntimeDirectory` ile
  oluşturur (aksi halde namespace kurulumu ExecStart'tan önce patlardı).
- **RT-2 / RT-3 (attestation + kimlik) cihaz-üstü çalıştırması BEKLİYOR:** kod +
  birim testi + paketleme hazır, ancak `suderra-firstboot` Rust binary'si bugün
  hiçbir imajda ÇALIŞMIYOR — board overlay'deki placeholder shell unit
  (`/etc/systemd/system/suderra-firstboot.service`, machine-id + dizinler)
  paket unit'ini (`/usr/lib/.../suderra-firstboot.service`, binary'yi çağıran)
  isim-gölgeler ve prod'da firstboot hiç enable edilmez. Bu binary'yi prod'da
  devreye almak (placeholder unit'i binary'yle birleştirmek + prod'da enable) ve
  swtpm/G5 kanıtı **Dalga 3'ün kalan wiring adımıdır**; register bunu açık
  bırakır. Bu yüzden RT-2/RT-3 "kod uygulandı, cihaz-üstü wiring + kanıt bekliyor"
  olarak işaretlenir — "sahada çalışıyor" DEĞİL.

## Sonuçlar

- Olumlu: RT-2/RT-3/RT-6 yazılım tarafı gerçek koda kavuştu; shipped tpm2-tools
  tüketiliyor; anti-rollback artık donanım çıpalı (NV counter), etiket değil.
- Ödünleşim: subprocess parse yüzeyi (makine-okur çıktılarla sınırlandı); NV
  redefine-reset kalıntısı (okuyucu fail-closed ile azaltıldı); gerçek donanım
  kanıtı hâlâ G5'e bağlı.
