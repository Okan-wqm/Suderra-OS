# ADR-0008: Cihaz-içi runtime güven mimarisi (Eksen B) — bütünsel çözüm

- **Status:** Proposed
- **Date:** 2026-07-11
- **Deciders:** @okan-wqm
- **Tags:** security, runtime, tpm, luks, attestation, identity, anti-rollback, network

## Context

[security-architecture.md](../security/security-architecture.md) güveni iki eksene
ayırır: **Eksen A (tedarik zinciri / boot güveni)** — uygulanmış, sağlam,
fail-closed; **Eksen B (cihaz-içi runtime güveni)** — mimarisi kurulmuş ama çoğu
iskele. [security-gaps-and-risks.md](../security/security-gaps-and-risks.md)
(17 bulgu) + sonrasında yapılan bağımsız uçtan-uca inceleme (güvenlik + kod
doğruluğu + performans), Eksen B'nin parçalarının **birbirine bağlı olduğunu**
ama bugüne dek **tekil, koordinesiz** ele alındığını gösterdi. Sonuç: her parça
tek başına "mimarisi var, kodu yok" durumunda kalıyor ve nokta-düzeltmeler (yama)
bütünü çözmüyor.

Bu ADR, Eksen B'yi **tek bir güven mimarisi** olarak tanımlar: her bulgu bu
mimaride bir yere oturur, bağımlılık sırası nettir, ve **kodla çözülebilen her
şey kodla + fail-closed + test edilerek** kapatılır. Yalnızca **fiziksel donanım
gerektiren *doğrulama*** adımları (implementasyon değil) açıkça sınırlanır — bu
"erteleme" değil, dürüst kapsamlamadır: kod tarafı eksiksiz hazır edilir,
geriye yalnız donanımda ölçüm/kanıt kalır.

### Kök neden: iki "conflation"

İnceleme, Eksen B'nin dağınıklığının iki kök nedene indiğini buldu:

1. **Prod-tespiti conflation'ı (NEW-1).** `suderra-ota`'da tek bir env bayrağı
   (`SUDERRA_OTA_PRODUCTION`, hiçbir cihazda set edilmiyordu) hem *dev-override
   reddini* (güvenlik) hem de *TPM-NV zorunluluğunu* (donanım-kapılı) birden
   kapılıyordu. İkisi de ölüydü → anti-rollback güvencesi sevk edilen her cihazda
   kapalıydı ve env ile bypass edilebiliyordu.
2. **Provisioning conflation'ı (RT-1..RT-4).** `/data` at-rest şifreleme, TPM
   seal, cihaz kimliği ve cloud enrollment ayrı ayrı "iskele" olarak duruyordu;
   oysa bunlar **tek bir ilk-boot güven-tesis akışının** halkalarıdır ve ancak
   birlikte anlam kazanır (LUKS anahtarı TPM'e seal edilir; kimlik TPM'e bağlanır;
   attestation aynı PCR'ları kullanır).

## Decision

### 1. Güven kökü tekilleştirme — imzalı `/etc/os-release` VARIANT

Runtime prod-tespiti **tek güven köküne** bağlanır: dm-verity altındaki imzalı,
salt-okunur `/etc/os-release`'in `VARIANT` alanı. Env yalnız sınıflandırmayı
**üretim yönünde sıkılaştırabilir**, asla gevşetemez.

- `suderra-installer::variant::is_production()` — os-release güven kökü; env
  downgrade edemez, boş-env yok sayılır. **(Uygulandı.)**
- `suderra-ota::is_production()` — aynı sözleşme; `dev_override()`'ı kapılar,
  gerçek prod cihazda env güvenlik davranışını gevşetemez. **(Uygulandı.)**
- Build kapısı (`enforce_production_contract`) prod imajın gerçekten
  `VARIANT=prod` taşıdığını assert eder → runtime'daki "VARIANT yoksa dev say"
  fail-open residual'ı build katmanında kapanır. **(Uygulandı.)**
- **Sonraki adım (refactor):** her iki crate'in aynı `variant`/`value_is_prod`
  sözleşmesini kopyalaması yerine paylaşılan bir `suderra-trust` (veya
  `suderra-config`) modülüne çıkarılır. Davranış zaten birleşik; bu DRY hijyeni.

### 2. Anti-rollback katmanlı politika (tiered)

Anti-rollback "hep ya da hiç" değil, **açıkça katmanlı**dır:

- **Tier 2 (donanım-çıpalı, güçlü):** `SUDERRA_OTA_ROLLBACK_FLOOR_SOURCE` =
  `tpm-nv`/`bootloader-monotonic` beyan edilmişse **katı** doğrulanır (kaynak
  yolu zorunlu, yazılabilir state dizini dışında, okunur+geçerli). **(Uygulandı.)**
- **Tier 1 (userspace floor — bugünün dürüst durumu):** kaynak beyan edilmemişse
  `/data` monotonik floor tek katmandır; cihaz **kilitlenmez** ama `degraded`
  seviyesinde açıkça sinyaller. `dev_override` kapalı olduğundan floor env ile
  kurcalanamaz. **(Uygulandı.)**
- **Tier 2'ye geçiş:** monotonik kaynak beyanı env'den **imzalı config'e**
  (dm-verity RO) taşınır ve gerçek TPM-NV/bootloader counter'ı ile doldurulur.
  Bu, aşağıdaki Dalga 3'ün (TPM) parçasıdır; `production_ready` flip'i (G5) buna
  bağlıdır.

### 3. İlk-boot güven-tesis akışı — tek durum makinesi (`suderra-firstboot`)

RT-1..RT-4'ün tamamı, `suderra-firstboot`'un **idempotent, fail-closed** bir
durum makinesi olarak yeniden yazılmasıyla çözülür. Her adım bir sonrakinin ön
koşuludur; herhangi bir adım başarısızsa cihaz "factory/unprovisioned" modunda
kalır (asla yarı-provisioned sevk sırrı bırakmaz):

```
firstboot (Type=oneshot, ConditionPathExists=!/data/.provisioned)
  1. /data LUKS2 provision            (RT-1, DOC-1)
       - luksFormat + mkfs (ilk boot)
       - anahtar: RevPi → TPM2 PCR seal; rpi4/x86 → keyfile (bkz. Dalga 2)
  2. systemd-cryptsetup token enroll   (RT-5)
       - BR2_PACKAGE_SYSTEMD_CRYPTSETUP + systemd-cryptenroll --tpm2-device
  3. cihaz kimliği üret                (RT-3)
       - TPM-bağlı anahtar çifti (attestation identity) → CSR
  4. cloud enroll (mTLS bootstrap)     (RT-3)
       - CSR gönder, client cert al, TPM-korumalı sakla
  5. attestation baseline              (RT-2)
       - PCR 0-7 quote üret, doğrulayıcıya kaydet
  6. mark-provisioned + rauc mark-good
```

Doğrulama: `data-luks-swtpm` QEMU senaryosu **gerçek seal**'i (yalnız mapper
mount'u değil) kanıtlayacak şekilde güçlendirilir; `data-luks-open` health-gate
(RT-7) böylece gerçek bir implementasyona dayanır.

### 4. Ağ yüzeyi mimarisi (egress + capability)

- **Egress default-drop by destination (NEW-2):** `nftables` çıkış zinciri
  adlandırılmış hedef set'leriyle (cloud API, broker, PLC CIDR) yeniden yazılır;
  bilinmeyen host'a giden 443/8883/502/4840 **düşürülür**. Set'ler imzalı config'ten
  gelir (saha-özel CIDR'ler deployment girdisidir).
- **Appliance firewall default'u tersine (NEW-5):** prod imaj build-time
  `.appliance-locked` ile açılır; provisioning ruleset yalnız açık provisioning
  marker'ı varken yüklenir.
- **Capability mediation (NEW-4):** indirilen harici `suderra-agent`'tan
  `/dev/tpm0`/`/dev/tpmrm0`/`/dev/watchdog` erişimi kaldırılır; TPM Suderra-sahipli
  bir broker üzerinden aracılı verilir, watchdog yalnız `suderra-watchdog`'da kalır.

### 5. Runtime crate kalite/robustluk (kod doğruluğu)

Bağımsız kod incelemesinin bulduğu erişilebilir bug'lar (env-downgrade, mark-good
kalıcı-kilit DoS, watchdog'un sağlıklı cihazı reset'lemesi, imza malleability)
mimari-nötr olduklarından **hemen** kapatıldı (bkz. PR — Dalga 1). Bunlar Eksen B
mimarisinin ön-temizliğidir.

### 6. Fiziksel donanım sınırı (dürüst kapsamlama — "kör bırakma" değil)

Şu adımlar **kodda eksiksiz hazır edilir** ama son *doğrulama* fiziksel cihaz
gerektirir; bunlar ADR-0007'nin G4/G5 listesiyle hizalıdır ve `production_ready:
false` ile dürüstçe tutulur:

- **HW-1/HW-2 (G4/G5):** ARM FIT enforcement'ın gerçek Pi'de zorladığının kanıtı;
  OTP secure boot ile ilk-aşama imzası.
- **G5 istasyon-kanıtı:** flash/readback/UART/power/TPM/tamper adapter'larıyla
  ölçülen kanıt bundle'ı (`evidence-contract.yml hardware`).

Bu ADR'nin işi, o kapılara gelene dek **kod tarafında hiçbir boşluk bırakmamak**:
tüm provisioning, seal, attestation, identity yolları implemente + QEMU/swtpm ile
doğrulanmış olur; donanım yalnız "gerçekten böyle davrandı" ölçümünü ekler.

## Bağımlılık-sıralı uygulama dalgaları

| Dalga | Kapsam | Bulgular | Donanım? | Durum |
|---|---|---|---|---|
| **1** | Runtime crate hardening (prod-detection birleştirme, anti-rollback tiering, mark-good, watchdog, verify_strict) | NEW-1, NEW-3, #1/#2/#3/#4/#7 | Hayır | **Uygulandı** |
| **2** | `/data` LUKS2 provisioning + firstboot durum makinesi iskeleti + systemd-cryptsetup | RT-1, RT-4, RT-5, RT-7, DOC-1 | swtpm ile | Sıradaki |
| **3** | TPM seal + attestation + TPM-bağlı kimlik/enrollment + anti-rollback Tier-2 kaynağı imzalı config'e | RT-2, RT-3, RT-6 | swtpm ile | Dalga 2 sonrası |
| **4** | Ağ yüzeyi: egress destination-set, firewall default, agent capability mediation | NEW-2, NEW-4, NEW-5 | Hayır | Paralel |
| **5** | Doküman/roadmap hizalama + register'a NEW-1..7 işleme | DOC-2, DOC-3 | Hayır | Paralel |
| **6** | Performans: CI cache/toolchain + footprint (tokio-full, reqwest, ikili TLS, network-online) | perf | Hayır | Paralel |
| **7** | Donanım kanıtı (G4/G5) — kod hazır, ölçüm cihazda | HW-1..HW-4 | **Evet** | Donanım geldiğinde |

Dalga 4/5/6 birbirinden ve Dalga 2/3'ten dosya-ayrık olduğundan **paralel**
yürütülebilir (bağımsız agent'lar). Dalga 2 → 3 sıralıdır (seal, LUKS anahtarına
bağlı). Dalga 7 yalnız donanım gerektirir.

## Consequences

**Olumlu.** Eksen B artık tekil bir mimariyle ele alınır; her bulgu bir dalgaya
ve bağımlılık sırasına oturur. Prod-tespiti tekilleşti, anti-rollback dürüstçe
katmanlandı, provisioning tek fail-closed akışa indi. Nokta-yama riski ortadan
kalkar; `production_ready` flip'inin ön koşulları netleşir.

**Maliyet / risk.** Dalga 2/3 gerçek kripto/TPM kodu; swtpm ile QEMU'da
doğrulanır ama gerçek SLB9670/OTP davranışı yalnız donanımda kesinleşir (G5).
LUKS provisioning ilk-boot'ta yıkıcı bir işlem (mkfs) olduğundan idempotency +
factory-mode fail-safe kritiktir. Egress destination-set'leri saha-özel CIDR
girdisi gerektirir (deployment-time).

## İlgili

- [security-architecture.md](../security/security-architecture.md) ·
  [security-gaps-and-risks.md](../security/security-gaps-and-risks.md)
- [ADR-0007](ADR-0007-arm-verity-ab-boot-chain.md) (G4/G5 donanım kapıları) ·
  [ADR-0005](ADR-0005-dm-verity-secure-boot.md) ·
  [ADR-0006](ADR-0006-iec-62443-sl2-vs-sl3.md)
