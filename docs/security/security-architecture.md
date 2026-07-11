# Suderra OS — Güvenlik Mimarisi (kod-temelli, uçtan uca)

> Bu doküman Suderra OS güvenliğinin **gerçekte nasıl çalıştığını** anlatır — hedef/plan
> değil, koddaki mekanizmalar. Her iddia `dosya:satır` ile bağlanmıştır. **Uygulanan** ile
> **mimarisi kurulmuş ama henüz iskele** olanı açıkça ayırır. Teyit edilmiş eksikler ve
> riskler ayrı dokümanda: [security-gaps-and-risks.md](security-gaps-and-risks.md).
>
> İlgili: [threat-model.md](threat-model.md) · [ARCHITECTURE.md](../architecture/ARCHITECTURE.md) ·
> [ADR-0007](../architecture/ADR-0007-arm-verity-ab-boot-chain.md) ·
> [iec-62443-mapping.md](../compliance/iec-62443-mapping.md)

## Güven modelinin iki ekseni

Suderra OS'un güvenliğini iki bağımsız eksende düşünmek gerekir. İkisinin olgunluğu
**çok farklıdır** ve bu ayrım tüm dokümanın omurgasıdır:

| Eksen | Soru | Durum |
|---|---|---|
| **A — Tedarik zinciri / boot güveni** | "Cihazda çalışan yazılım gerçekten bizim, kurcalanmamış, imzalı yazılımımız mı?" | **Uygulanmış, sağlam, fail-closed.** Yol haritasının önünde. |
| **B — Cihaz-içi runtime güveni** | "Cihazın kendisi (kimliği, sırları, verisi at-rest) donanımsal olarak korunuyor mu?" | **Mimarisi kurulmuş, çoğu İSKELE.** Dürüstçe `production_ready:false` ile kapılı. |

Kritik dürüstlük notu: hiçbir yerde "yapıldı" diye **yanlış** bir iddia yoktur. Eksen B'nin
eksik parçaları placeholder crate'ler + kapalı defconfig'ler + `production_ready:false`
kapılarıyla açıkça işaretlenmiştir. Yani sistem "eksik ama dürüst".

---

## Bölüm A — Tedarik zinciri & boot güven zinciri (UYGULANMIŞ)

Zincir: **kaynak → imzalı build (HSM) → imzalı boot (UEFI/FIT) → dm-verity (RO rootfs)
→ imzalı OTA (RAUC A/B) → release provenance (SLSA)**. Her halka fail-closed.

### A.1 — İmzalama modeli: prod dosya anahtarını REDDEDER, HSM ZORUNLU

Her imzalama, bir variant/signing-mode sözleşmesinden geçer:

- `board/suderra/common/post-image.sh:46-88` — `SUDERRA_OS_VARIANT`'ı `BR2_CONFIG`'ten türetir;
  prod variant için `SUDERRA_SIGNING_MODE=prod`'u zorla export eder (`:82-88`).
- `scripts/production-artifacts.sh` `reject_prod_file_key()` (`:56-72`): prod modda boş anahtar
  → ölür; `pkcs11:*` URI → geçer; **başka her şey (dosya anahtarı) → ölür**. `need_signing_key()`
  (`:81-94`) PKCS#11 URI'de ek olarak `object=`/`id=` ister. Prod'da `need_file` dalı erişilemez.
- Dev anahtarları `scripts/gen-dev-keys.sh` ile self-signed üretilir (`~/.suderra-keys/dev/`),
  her cert subject'inde "Dev" geçer; script "ÜRETİM için HSM kullan" uyarısı basar (`:121`).
- **Dev anahtarının prod gibi davranmasını engelleme:** `package/suderra-keys/suderra-keys.mk:44-66`
  — trust-root profili `prod` içermeli, dizin `/dev` ile bitmemeli, cert subject'inde `Dev`/`dev`
  geçen kök **reddedilir**.

### A.2 — HSM imzalama + sonradan kriptografik KANIT

- İmzalama HSM'in openssl `pkcs11` engine'i üzerinden yapılır (`sbsign_artifact`/`openssl_sign_artifact`,
  `production-artifacts.sh:130-172`). RAUC bundle `rauc bundle --cert --key <pkcs11-uri>` +
  `rauc info --keyring` ile yeniden doğrulanır (`scripts/create-rauc-bundle.sh:200-217`).
- `scripts/evidence/validate-hsm-signing-evidence.py` imzayı **sonradan replay eder**:
  `hardware_backed==true` ister (`:299`), SoftHSM/software/file marker'larını reddeder
  (`:40-48, 301-346`), **onaylı-sağlayıcı allowlist**'i zorlar (YubiHSM/Thales Luna/Entrust
  nShield/Utimaco/AWS CloudHSM/Nitrokey HSM/Marvell, `evidence-contract.yml:550-566`), ve
  cert'in public key'iyle challenge + her artefakt imzasını **openssl ile yeniden doğrular**
  (`validate_crypto_replay:166-243`) — yani cert'in private key'i gerçekten imzaladı mı kanıtlar.

### A.3 — x86 UEFI Secure Boot

- **UKI (Unified Kernel Image):** `build_signed_slot_uki` (`production-artifacts.sh:445-492`)
  kernel + initramfs + cmdline'ı (dm-verity root hash dahil) **tek bir PE**'ye `objcopy`'ler,
  `sbsign` + `sbverify --cert` ile imzalar/doğrular. Herhangi bir kurcalama SB imzasını bozar.
- **GRUB:** `build_signed_grub` (`:494-529`) `BOOTX64.EFI`'yi sbsign'lar; `grub.cfg` slot UKI'yi
  chainload eder. shim yok — db cert doğrudan güven kökü.
- **OVMF SB enrollment:** `scripts/qemu/enroll-secureboot-vars` `virt-fw-vars` ile PK/KEK/db enroll
  eder, Secure Boot'u AÇAR, fail-closed doğrular (`:76-99`).
- **Zorlama KANITI (QEMU):** `.github/workflows/production-runtime-qemu.yml`, `OVMF_CODE.secboot.fd`
  ile enrolled varstore + SMM/secure boot eder; `validate-production-runtime-suite.py`
  `secure_boot.enabled==true` ister ve `firmware-rejected`/`kernel-rejected` senaryolarıyla
  **imzasız/kurcalanmış UKI'nin boot'ta reddedildiğini gerçekten test eder**.

### A.4 — ARM signed-FIT (build gate uygulanmış; runtime zorlama G4-donanım)

- `build_signed_slot_fit` (`production-artifacts.sh:595-705`) her board DTB için ayrı imzalı
  config'li bir `.its` üretir; imza node'unda `required = "conf"` (`:653-658`) — bu token
  `mkimage -K`'in U-Boot control DTB'sine **required** anahtar yazmasını sağlar, böylece
  `fit_config_verify_required_sigs()` sessizce fail-open olamaz.
- `mkimage -f its -k keydir [-N engine] -K u-boot.dtb -r fit` (`:692-697`); prod HSM engine (`-N`).
- U-Boot: `CONFIG_FIT=y`, `CONFIG_FIT_SIGNATURE=y`, `CONFIG_RSA=y` (`uboot-fragment.config:14-17`).
- **Donanım kapısı (ADR-0007):** `rpi_arm64`'te U-Boot'un runtime control FDT'si firmware'in
  yüklediği `bcm2711-*.dtb`'dir, keyed `u-boot.dtb` DEĞİL. Anahtarın gerçekten zorlaması için
  `CONFIG_OF_SEPARATE` + keyed DTB'nin re-append'i gerekir — **gerçek Pi'de G4 ile doğrulanır**;
  o zamana dek `production_ready:false`. Detay: [ADR-0007](../architecture/ADR-0007-arm-verity-ab-boot-chain.md).

### A.5 — dm-verity (salt-okunur rootfs bütünlüğü)

- `generate_verity` (`production-artifacts.sh:201-237`) `veritysetup format` ile root hash üretir,
  `veritysetup verify` ile doğrular.
- **İmzalı boot artefaktına bağlama:** verity token'ları (`suderra.verity.*`, root_hash dahil)
  cmdline'a yazılır (`emit_verity_bootargs:246-268`); x86'da UKI'nin `.cmdline` section'ına,
  ARM'da FIT config `bootargs`'ına gömülür → **imza kapsamında**. Ayrı bir imzalı-roothash dosyası
  yok; root hash imzalı boot artefaktı doğrulanınca geçişli olarak güvenilir olur.
- **Fail-secure initramfs:** `/init` (`build_verity_initramfs:319-438`) verity table'ı kurar,
  `dmsetup create --readonly`, `ro` mount, `switch_root`. Herhangi bir başarısızlıkta ASLA
  shell'e düşmez — reboot/poweroff (`die():359-369`). Rootfs runtime'da değişmez; yazılabilir
  state yalnız `/data`.

### A.6 — RAUC A/B OTA

- Bundle format `verity`; kurulum imza kapısı `[keyring] /etc/rauc/keyring.pem`
  (`system.conf:8-9`) — bu keyring dm-verity altındaki rootfs'te olduğundan, RAUC her bundle'ın
  CMS imzasını **kurcalanamaz** bir güven köküne karşı doğrular.
- A/B slot modeli PARTLABEL ile; slot-hook imzalı UKI/FIT'i `/boot`'a kopyalar.
- **Anti-rollback:** `userspace/suderra-ota` — monotonik `rollback_floor`, `min_current_version`,
  key-epoch floor, expiry (`main.rs:412-461`); prod'da dev override'lar yok sayılır ve trusted
  floor kaynağı `/data` dışında olmalı (`:701-731`).

### A.7 — `enforce_production_contract` (fail-closed build kapıları)

`board/suderra/common/post-image.sh:378-629`, yalnız prod'da koşar. Bir prod build şu durumlarda
**PATLAR**: verity/roothash/imza/cert eksik veya biçimsiz; image imzası cert'e karşı doğrulanmıyor;
`veritysetup verify` başarısız (araç yoksa fail-closed); root-login/getty/dropbear açık; RAUC yok.
x86'da `sbverify` PE imzası; ARM'da `dumpimage` embedded-rsa2048 imzası **ve** `u-boot.dtb`'de
`key-name-hint="fit-signing"` + `required="conf"` assertion'ı (yoksa "fail-open" hatası).

### A.8 — Release provenance & tedarik-zinciri kanıtı

- **SLSA build provenance:** `actions/attest-build-provenance` (SHA-pinli) her imaj + release
  asset seti için (`image-build.yml`, `release.yml:700-716`).
- **Makine-doğrulaması:** release'te `cosign verify-blob` (identity=workflow ref, issuer=GitHub OIDC)
  ve `gh attestation verify` per asset (`release.yml:717-783`).
- **Evidence contract (SSOT):** `ci/evidence-contract.yml` imzalı artefakt rollerini, digest
  semantiğini, replay gereksinimlerini (SoftHSM prod'da reddedilir, provider allowlist enforced)
  tanımlar. Reproducibility harness: `scripts/verify-reproducible.sh` (iki bağımsız Docker build
  SHA karşılaştırması, `SOURCE_DATE_EPOCH`).

**Eksen A değerlendirmesi:** Bu, projenin en güçlü tarafı — imzalama, boot güveni, OTA doğrulama,
provenance uçtan uca fail-closed ve endüstriyel (IEC 62443 SI / CRA) seviyede. Yol haritasının
"Faz 3/4" içeriği zaten burada.

---

## Bölüm B — Cihaz-içi runtime güvenlik (KISMEN UYGULANMIŞ)

Burada dikkat: **çoğu bileşen mimarisi kurulmuş ama iskele.** Ne olduğunu net görmek şart.

### B.1 — Rust userspace: 4 gerçek, 4 iskele

| Crate | Durum | Ne yapar |
|---|---|---|
| `suderra-ota` | **Gerçek** | Ed25519 manifest doğrula + anti-rollback + SHA256 + `rauc install`. `#![forbid(unsafe_code)]`. **İndirmez** (yol argümanı alır). |
| `suderra-installer` | **Gerçek** | Harici workload bundle'ını HTTPS ile indirir, **cosign keyless (Sigstore)** + SHA256 doğrular. RAUC install motoru henüz yok (LabCopy stub). |
| `suderra-watchdog` | **Gerçek** | Donanım `/dev/watchdog` besler, health-gate, staged reset. Tek `unsafe` (2 ioctl, belgeli). |
| `suderra-config` | **Gerçek (minimal)** | `config.yaml` parse; sadece `https://` prefix kontrolü. |
| `suderra-firstboot` | **İSKELE** | Sadece log + exit. LUKS/TPM seal/cloud enroll = TODO. **Her defconfig'te KAPALI.** |
| `suderra-telemetry` | **İSKELE** | Sadece log + exit. `reqwest` bağımlı ama kullanılmıyor. |
| `suderra-attestation` | **İSKELE** | Sadece log + exit. `tss-esapi` YOK (yalnız yorumda). Hiçbir imaja girmiyor. |
| `suderra-factory-reset` | **İSKELE** | Sadece log + exit. |

Kalite: `rustls` (tek-yön TLS), `cargo-deny` openssl/native-tls yasak, `panic=abort`, MSRV 1.86
pinli, unsafe neredeyse yok. Endüstriyel Rust hijyeni iyi.

### B.2 — `/data` at-rest şifreleme: unlock VAR, provisioning YOK (kritik boşluk)

- **Unlock script'i var:** `board/.../usr/sbin/suderra-data-unlock` — variant'a göre ayrışır:
  - **DEV** → `mount -L SUDERRA-DATA /data` düz ext4, **şifreleme YOK** (tasarım gereği).
  - **PROD** → LUKS2 + TPM2 token zorunlu; `systemd-cryptsetup ... tpm2-device=auto` veya
    `cryptsetup open --token-only`. Plaintext fallback YOK; LUKS değilse `exit 1`.
- **Ama provisioning kodu YOK:** hiçbir yerde `luksFormat`/`cryptenroll`/mapper `mkfs` yok
  (repo-geneli grep negatif). genimage `data` partition'ı **boş/formatsız** sevk edilir. Sonuç:
  bir PROD imajda `/data` LUKS hiç oluşturulmadığından `suderra-data-unlock` `isLuks` kontrolünde
  patlar → **`/data` bugün cihazda şifreli-at-rest DEĞİL** (fail-closed ama işlevsiz).
- Ek olarak `BR2_PACKAGE_SYSTEMD_CRYPTSETUP` (systemd-tpm2 token handler) hiçbir defconfig'te açık
  değil — LUKS volume olsa bile unlock yolu muhtemelen çalışmaz.

### B.3 — TPM 2.0: sürücü + araç VAR, kullanım YOK

- Kernel sürücüleri var (`TCG_TPM`, `TCG_TIS_SPI` ARM; `TCG_TPM`, `HW_RANDOM_TPM` x86).
  `tpm2-tools` ve `tpm2-tss` yalnız **prod** defconfig'lerde.
- Ama **hiçbir kod TPM ile konuşmaz:** attestation iskele, sealing iskele. RevPi SLB9670 seal vs
  rpi4 keyfile ayrımı **yalnız yorumda/dokümanda**, kod yolu yok.

### B.4 — Cihaz kimliği & enrollment: kriptografik kimlik YOK

- İlk boot kimliği (inline `suderra-firstboot.service`) = **plaintext YAML** (`device_id: 0000...`,
  `device_code: UNACTIVATED`). `suderra-config` struct'ında cert/key/CSR alanı yok; "mTLS endpoint"
  yalnız bir yorum string'i. Client sertifikası, CSR, TPM-bağlı kimlik **yok**.
- `suderra-edge-install` baked-in ed25519 pubkey ile **workload artefaktını** doğrular — bu
  tedarik-zinciri doğrulaması, cihaz kimliği değil.

### B.5 — Ağ yüzeyi

- **Uygulanan:** `nftables.conf` (default DROP) mevcut. Tek giden bağlantı `suderra-installer`'ın
  HTTPS release indirmesi — **tek-yön TLS (rustls), mTLS DEĞİL**, client cert yok. Bütünlük
  mTLS'ten değil **cosign + SHA256**'dan gelir. `SUDERRA_INSECURE=1` (prod'da bloklu) doğrulamayı
  kapatabilir.
- **Harici/iskele:** Endüstriyel bağlantı (**Modbus/OPC-UA/MQTT**) bu repoda **yok** —
  `package/suderra-edge-agent` harici proprietary repo `aquaculture_platform/sens-api-gateway`'i
  işaret eder ve build'de **KAPALI** (`Config.in` `CARGO4_HASH_REVALIDATED=default n`). Yani
  endüstriyel protokol katmanı = OS'un çalıştıracağı iş yükü, OS'un parçası değil.
- **Not:** `ARCHITECTURE.md`'nin "Network Yüzeyi" tablosu (Modbus 502 / OPC-UA 4840 / MQTT 8883
  mTLS) bir **hedef**tir; bugünkü OS kodunda karşılığı yoktur.

### B.6 — Kernel/userspace sertleştirme (uygulanan)

- Kernel: lockdown (`LSM="lockdown,yama,bpf,landlock"`), KASLR, hardened usercopy, init-on-alloc,
  stack-protector (`linux-*-hardening.config`). x86 monolitik (`# CONFIG_MODULES`); ARM'da modüller
  hâlâ açık (M3 — bkz. gaps).
- Userspace: prod imajlarda dropbear/getty/root-login KAPALI (enforce_production_contract zorlar).

---

## Bölüm C — `production_ready` kapıları (G0–G5)

Tüm prod hedefleri `ci/build-matrix.yml`'de **`production_ready: false`** (hardcoded, blocker
string'li). Flip için gereken donanım kanıtı `evidence-contract.yml hardware` bloğunda tanımlı:
istasyon-edinim (flash/readback/uart/power/tpm/tamper adapter'ları), `readback_sha==build_subject`,
station-registry, negatif testler (dm-verity/boot tamper reddi).

- **Uygulanan:** kanıt **sözleşmesi + doğrulayıcıları** (`station-acquisition.py` ölçülen değerleri
  zorlar: tpm.present, secure-boot enforced, rauc rollback, tamper reddi, power-cycle).
- **Donanım gerektiren (repoda YOK):** gerçek istasyon adapter implementasyonları + kanıt bundle'ı.
  Bu yüzden her prod hedef fail-closed `false`.

Detaylı G4/G5 listesi: [ADR-0007 "Remaining hardware/kernel gates"](../architecture/ADR-0007-arm-verity-ab-boot-chain.md).

---

## Olgunluk özeti — "yeterince iyi yolda mı?"

**Evet, doğru yolda ve zoru başarılmış.** Bir edge OS'ta en zor ve en çok yanlış yapılan şey
verified-boot tedarik-zinciri güven zinciridir (Eksen A) — o burada gerçekten enterprise-grade,
fail-closed ve yol haritasının önünde. Mimari IEC 62443 SL2 / CRA ile hizalı, `production_ready`
doğru şekilde tutuluyor, hiçbir yerde sahte "tamamlandı" iddiası yok.

**Ama cihaz-güveni katmanı (Eksen B) henüz büyük ölçüde iskele.** Attestation, TPM seal, `/data`
at-rest provisioning, kriptografik cihaz kimliği hepsi placeholder. En somut aksiyon: **`/data`
LUKS2 provisioning'i uygulamak** — bugün prod cihazda `/data` şifreli değil (iddia ediliyor,
kod yok). Detaylı eksik/risk kaydı: [security-gaps-and-risks.md](security-gaps-and-risks.md).

## Kod haritası (hızlı referans)

- İmzalama/HSM: `scripts/production-artifacts.sh`, `scripts/create-rauc-bundle.sh`,
  `scripts/evidence/validate-hsm-signing-evidence.py`, `package/suderra-keys/suderra-keys.mk`
- Fail-closed build gate: `board/suderra/common/post-image.sh` (`enforce_production_contract`)
- Boot: `board/suderra/aarch64-rpi4/{uboot-fragment.config,boot.scr.cmd}`,
  `board/suderra/x86_64/grub.cfg`, `scripts/qemu/enroll-secureboot-vars`
- OTA/anti-rollback: `userspace/suderra-ota/src/main.rs`, `package/suderra-rauc-config/*`
- /data unlock: `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock`
- Runtime crate'ler: `userspace/suderra-{ota,installer,watchdog,config}` (gerçek);
  `userspace/suderra-{firstboot,telemetry,attestation,factory-reset}` (iskele)
- Kanıt kapıları: `ci/evidence-contract.yml`, `scripts/evidence/station-acquisition.py`,
  `scripts/ci/validate-build-matrix.py`
