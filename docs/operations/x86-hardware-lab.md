# x86_64 Donanım Lab Runbook — `industrial-x86_64`

`suderra_x86_64` üretim hedefinin `production_ready=true` olabilmesi için, QEMU
runtime + HSM imza kanıtına ek olarak **fiziksel `industrial-x86_64` donanım
kanıtı** gerekir (`ci/evidence-contract.yml` `hardware.subject_binding`,
`hardware_required=true`). Bu runbook o kanıtın nasıl üretildiğini tanımlar.

SSOT: gerekli alanlar, kontroller ve negatif testler `ci/evidence-contract.yml`
içinde; bu belge süreçtir, politikayı yeniden tanımlamaz.

## İstasyon kaydı (station registry)

Kanıt üreten istasyon, dış (operatör-kontrollü) bir kayıtta tanımlı olmalıdır
(`station_registry_required=true`). Şema `suderra.lab-station-registry.v1`.
Şablon: [`lab-station-registry.industrial-x86_64.example.json`](lab-station-registry.industrial-x86_64.example.json)
— kopyalayın, her `REPLACE-*` id'sini ve her 64-hex `*_sha256` placeholder'ını
gerçek istasyon değerleriyle doldurun.

Kayıt **repoya commit edilmez** (operatör/lab kanıtıdır, `release-lab-input/`
altında operator-ingress ile taşınır). `adapter_inventory` istasyondaki her
adaptörü (rol, id, sürüm, `binary_sha256`, `command_schema_id`) tam bağlar;
`validate-lab-input.py` bunu `--station-registry` ile alır ve
`adapter_inventory_must_match_registry` gereği kanıttaki adaptörlerle eşleştirir.

Gerekli adaptör rolleri: `flash`, `readback`, `uart`, `power`, `storage`,
`tpm`, `secure-boot`, `rauc`, `tamper`.

## Donanım + fixture

- Board: `industrial-x86_64` (UEFI Secure Boot + fiziksel TPM 2.0 zorunlu).
- Güç döngüsü fixture'ı (power-cycle-transcript için programlanabilir PSU).
- Seri konsol (UART), flash/readback adaptörü, kurcalama (tamper) enjeksiyon
  yolu (dm-verity/secure-boot negatiflerini gerçekten tetiklemek için).
- İki-kişi lab kuralı: acquisition operatörü + witness (ceremony ile aynı
  ilke, [key-ceremony.md](../security/key-ceremony.md)).

## Kontroller (x86)

Ortak donanım kontrollerine ek olarak `x86_required_checks` (SSOT):

- `tpm-presence` — fiziksel TPM 2.0 ölçülür.
- `secure-boot-enforced` — imzalı UKI boot eder, firmware imzasızı reddeder.
- `rauc-rollback` — A/B güncelleme + rollback donanımda tamamlanır.
- `dm-verity-tamper-rejection` — kurcalanmış rootfs kernel tarafından reddedilir.
- `boot-tamper-rejection` — boot zinciri kurcalaması reddedilir.
- `power-cycle-transcript` — güç kesme/döngü altında bütünlük korunur.

## Negatif testler (x86)

`x86_required_negative_tests` (SSOT) — hepsi **kapalı-fail** (write-prevention)
kanıtıyla:

- `dm-verity-rootfs-tamper` — kurcalanmış rootfs boot etmez.
- `secure-boot-unsigned-uki` — imzasız UKI firmware'de reddedilir.
- `rauc-health-rollback` — sağlıksız güncelleme otomatik rollback olur.

## Akış (acquisition → ingest)

1. `industrial-x86_64` imajını üret (release subject); raw/compressed sha256'yı
   kaydet.
2. İstasyonda flash + full readback; `readback_sha256` build subject ile
   eşleşmeli (`readback_must_match_build_subject=true`).
3. `station-acquisition.py` ile tüm kontrolleri + negatif testleri koştur;
   `suderra.station-acquisition.v2` olayı üret.
4. `hardware-subject.json` (`suderra.hardware-subject.v1`) üret ve
   `release-lab-input/<version>/x86_64/` altına operator-ingress ile taşı
   (repoya commit edilmez, gitignored).
5. `validate-lab-input.py validate ... --station-registry <registry> --require-pass`
   ile doğrula; release/ingress join `hardware_required_targets_require_subject`
   gereğini karşılar.

Ancak bu kanıt üretildikten sonra `suderra_x86_64` için `production_ready=true`
tartışılabilir (runtime + HSM + donanım üçlü join).
