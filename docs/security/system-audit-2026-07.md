# Suderra OS — Tam Sistem Denetimi ve Fazlı Yol Haritası (2026-07)

> Tüm branch'ler ve tüm ağaç (build sistemi, CI, userspace, board overlay'leri, testler,
> dokümantasyon) güvenlik / performans / kod kalitesi / test kapsamı eksenlerinde baştan
> sona okunarak hazırlanmıştır. Her bulgu `dosya:satır` temelinde koda dayanır.
>
> Mevcut teyitli açık kaydını **kopyalamaz, üstüne ekler** — RT-*/HW-*/DOC-*/SC-*/MIN-*
> maddeleri için tek otorite [security-gaps-and-risks.md](security-gaps-and-risks.md)'dir.
> Bu rapordaki yeni bulgular **AUD-n** kimliğiyle numaralanır.
> Tarih: 2026-07-11. İncelenen main tepe commit'i: `f3bbb33` (#82).

## 1. Yönetici özeti

**Hüküm:** Kod denetiminde **yeni kritik veya yüksek seviye açık bulunmadı.** Tedarik
zinciri / boot güveni ekseni (Eksen A) olağandışı derecede olgun ve fail-closed; en büyük
riskler zaten [security-gaps-and-risks.md](security-gaps-and-risks.md)'de dürüstçe kayıtlı
(başta RT-1 `/data` at-rest şifrelemesi) ve `production_ready:false` ile kapılı.

**En yüksek değerli tek aksiyon kod yazmak değil, merge etmektir:** PR **#84**
(`claude/security-docs-merge-dg2are`) main'e temiz merge olan, NEW-1 (Yüksek), RT-1/RT-5,
NEW-2, NEW-6 ve C-1..C-5 düzeltmelerini içeren hazır bir güvenlik dalgasıdır ve draft'ta
bekliyor. Ayrıntı: §3.

Kalan boşluklar üç kümede toplanıyor:

1. **Eksen B (cihaz-içi runtime güvenliği)** — LUKS/TPM/kimlik; register'da kayıtlı,
   #84 + ADR-0008 dalgalarıyla plan mevcut.
2. **CI derinliği** — CodeQL semantik SAST yok; CVE taraması yalnız kaynak ağaçta,
   üretilen imaj rootfs'i taranmıyor (AUD-2, AUD-3).
3. **Kod kalitesi ince işçilik** — OTA imza kanonikalizasyonunun iki dilde kırılgan
   kopyası (AUD-4), tokio/overflow-checks/atıl test binary'si gibi düşük seviye kalemler.

## 2. Metodoloji

- **Branch'ler:** `main` (`f3bbb33`), `claude/security-docs-merge-dg2are` (PR #84, 8 commit),
  `codex/enterprise-evidence-architecture` (3 commit, bayat), 6 dependabot branch'i.
- **Alanlar:** `docs/` (mimari + güvenlik kayıtları), `.github/workflows/` + `ci/` (21 workflow,
  build-matrix/evidence sözleşmeleri), `userspace/` (8 Rust crate, exhaustive grep +
  imza/anti-rollback yolu satır satır), `scripts/` + `board/` (23 shell script, post-build/post-image
  kontratları, rootfs overlay/systemd/nftables/sysctl), `package/`, `host-tools/`, `tests/`.
- **Yöntem:** Üç bağımsız tarama (mimari+CI envanteri; kod-seviyesi denetim; branch-diff analizi),
  bulgular `dosya:satır` ile doğrulandı, mevcut register'la çakışanlar elendi.

## 3. Branch durumu ve tavsiye edilen merge sırası

| Branch / PR | Durum | İçerik | Tavsiye |
|---|---|---|---|
| **#84** `claude/security-docs-merge-dg2are` | Draft, main'e **çakışmasız** | NEW-1 (Yüksek, prod-detection trust root → os-release VARIANT), RT-1/RT-5/DOC-1 (`/data` LUKS2 provisioning, TPM2-seal varsayılan), NEW-2 (fail-closed egress allow-list), NEW-6 (console'a parola basmayı kes), C-1..C-5 (env-downgrade, mark-good DoS, watchdog self-reset, strict sig verify), ADR-0008, `reqwest` kaldırma (perf), dl-cache `restore-keys` (build perf), DOC-2/DOC-3 | **1. sırada merge.** Her commit'te "Verified" bölümü var; tek kozmetik pürüz: Kategori-6 tablosunda NEW-6 "Açık" kalmış ama aynı branch'te `2b3bead` düzeltiyor — merge sonrası tabloyu güncelle. |
| Dependabot: #47, #51, #52, #69, #80, #81 | Açık | actions/checkout 6→7 (major), attest-build-provenance, upload-sarif, actionlint, install-action, rustls 0.23.41 + chrono 0.4.45 | **2. sırada merge.** #47 major bump — workflow'lar SHA-pinned olduğundan davranış değişikliğini release notlarından teyit ederek al. |
| `codex/enterprise-evidence-architecture` | **Bayat / fiilen aşılmış** | Merge-base `d8939bc` çok geride; main bu işin evrilmiş halini ~24 PR'da (#53–#82) zaten içeriyor. Olduğu gibi merge `+314/−6481` — main'den ~6.500 satır yeni işi **siler**. `779722d` zaten main'de (`0403128`); `suderra-ota` rollback mantığı, #84'ün kaldırdığı `SUDERRA_OTA_PRODUCTION` bayrağına dayanıyor (doğrudan semantik çakışma, #84 kazanmalı). | **Merge ETME.** Tek kurtarılacak delta: GRUB2 linux16 warning-fingerprint kanonikalizasyonu (`db58625`, `scripts/ci/classify-build-warnings.py`) — yeni main üstüne cherry-pick/yeniden türet, sonra branch'i kapat. |

## 4. Bulgular

Ciddiyet ölçeği register ile aynı (Kritik/Yüksek/Orta/Düşük). "Register" sütunu mevcut
kayıtla ilişkiyi gösterir.

### 4.1 Güvenlik

| ID | Ciddiyet | Bulgu | Register |
|---|---|---|---|
| AUD-1 | Orta-Düşük | Prod modu çalışma zamanı env bayrağı: `suderra-ota/src/main.rs:643-656` — `is_production()` yalnız `SUDERRA_OTA_PRODUCTION=1` ise true. Bayrak unutulursa `dev_override()` (`main.rs:504,525,559,735,846`) sessizce devreye girer: manifest expiry, anti-rollback floor, `rauc`/`reboot` binary seçimi ve state dizini operatör/saldırgan kontrolüne açılır (**ihmalle fail-open**). | Yeni. **#84 kökten çözüyor** (imzalı RO `/etc/os-release` VARIANT trust root) — merge'ün ana gerekçelerinden biri. |
| AUD-5 | Düşük/Bilgi | Prod imajda atıl test binary'si: `suderra-qemu-semantic-collector` her imaja `0755` kuruluyor (`board/suderra/common/post-build.sh:125`) ve `.service` dosyası ortak overlay'de; yalnız QEMU hedeflerinde etkinleştiriliyor ama diğer imajlarda dosya olarak kalıyor. Karşılaştırma: `suderra-runtime-scenario` doğru şekilde siliniyor (`post-build.sh:207-219`). QEMU-dışı imajlardan collector'ı da sil. | Yeni |
| AUD-6 | Düşük | `suderra-provision-worker.service` en ayrıcalıklı birim: root, `NoNewPrivileges=false`, `ReadWritePaths` içinde `/etc/shadow`; tetikleyici ayrıcalıksız `provision` kullanıcısı (uid 201). Risk iyi sınırlanmış (yalnız dev — prod'da maskeli `post-build.sh:261`; atomik `mv` + tip yeniden kontrolü ile TOCTOU-güvenli; edge-install Ed25519 + `--proto '=https'` doğruluyor) ama en değerli yükseltme hedefi — periyodik yeniden incelemeye al. | Yeni (izleme kalemi) |
| — | Orta | Egress hâlâ port-bazlı, hedef-bazlı değil (`etc/nftables.conf:42-66`): 443/8883'e her IP'ye çıkış var → ele geçirilmiş agent exfiltrasyon yapabilir. | Biliniyor; **NEW-2 düzeltmesi #84'te**. Dikkat: **NEW-5 açık kaldıkça sahada etkisiz** — prod'da firewall appliance-locked ruleset'e hiç geçmiyor (bkz. §4.6). |
| — | Düşük | Provisioning parolası console'a basılıyor (`suderra-firstboot.service:73-78`). | **NEW-6, düzeltmesi #84'te** (`2b3bead`). |

### 4.2 CI / tedarik zinciri

| ID | Ciddiyet | Bulgu |
|---|---|---|
| AUD-2 | Orta | **CodeQL semantik SAST yok.** `github/codeql-action` yalnız `upload-sarif` için kullanılıyor (Trivy/Grype/hadolint sonuçlarını yüklemek) — hiçbir workflow'da `init`/`analyze` yok. Rust/Python/shell için dataflow analizi eksik; statik analiz Clippy + shellcheck ile sınırlı. ~35 Python evidence validator'ı (`scripts/evidence/`) için özellikle değerli olur. |
| AUD-3 | Orta | **CVE taraması yalnız kaynak ağaçta.** `security-scan.yml`'de Trivy `fs` / Grype `dir:.` repo'yu tarıyor (`buildroot,output,dl` hariç) — **üretilen rootfs imajı (kernel, BusyBox, systemd, RAUC, nftables) hiçbir workflow'da CVE-taranmıyor**; imajın CVE maruziyeti gating olmayan SBOM sürecine kalıyor. Ek olarak Grype `--fail-on high --only-fixed` upstream'de düzeltilmemiş CVE'leri gizliyor, Trivy fs CRITICAL/HIGH ile sınırlı. |
| AUD-7 | Düşük | Prod runtime kanıt workflow'ları (`production-runtime-qemu.yml`, `arm-production-build.yml`) yalnız `workflow_dispatch` — PR başına çalışan runtime kapsamı dev QEMU boot smoke'tan ibaret. (ADR-0007 MED2 ile ilişkili, bkz. AUD-8.) |

**İyi durumda (yeniden denetleme):** Tüm GitHub Action'lar SHA-pinned; indirilen tarayıcı
binary'leri SHA256+versiyon pinli; gitleaks iki workflow'da; cargo-deny (advisory+ban+lisans+kaynak,
`wildcards=deny`, openssl yasak) hem `userspace/` hem `host-tools/`'ta; Scorecard + Dependabot aktif;
Buildroot submodule SHA drift kontrolü; `Cargo.lock --locked`. `cargo audit` yokluğu bilinçli ve
belgeli (`rust.yml:184` — RustSec cargo-deny'dan geliyor).

### 4.3 Performans / boyut

| ID | Ciddiyet | Bulgu |
|---|---|---|
| AUD-9 | Düşük | Senkron binary'de tam tokio: `suderra-ota` tamamen senkron (`#[tokio::main]`, hiç `.await` yok — `main.rs:141-167`) ama multi-thread runtime linkleniyor; `opt-level="z"`+LTO boyut hedefiyle çelişiyor. Telemetry/attestation stub'ları da öyle. `rt` (current-thread) özelliğine indir ya da tokio'yu kaldır. |
| AUD-10 | Düşük | `overflow-checks = false` release profilinde (`userspace/Cargo.toml:86`) — güvenlik cihazında doğrulama crate'leri için açık bırakmak ya da checked aritmetik tercih edilmeli. (Kod kalitesiyle kesişir.) |
| — | Düşük | Bilinen/ertelenmiş perf kalemleri (takip): `CCACHE_MAXSIZE` sınırlama (#84 `d4981e9` bilinçli erteledi — docker-build içine değer taşınımı doğrulanmalı), Docker builder katman-cache miss'i, çift TLS yığını (OpenSSL+rustls), prod'da tüketicisiz `tpm2-tools`, `network-online.target` DHCP kötü-durum ~120 sn boot gecikmesi. |

### 4.4 Kod kalitesi

| ID | Ciddiyet | Bulgu |
|---|---|---|
| AUD-4 | Orta-Düşük | **OTA manifest imza kanonikalizasyonu iki dilde kopyalı ve kırılgan.** Rust doğrulayıcı `serde_json::to_vec(unsigned)` ile *struct alan sırası* üzerinden imza baytı üretiyor (`suderra-ota/src/main.rs:366-370`); Python imzalayıcı aynı sırayı elle kurup `json.dumps(separators=(",",":"), ensure_ascii=False)` basıyor (`scripts/create-os-update-manifest.py:54-75,165`). Bugün eşleşiyor ama bir alan yeniden sıralansa/`skip_serializing_if` eklense imza sessizce kırılır. Installer'daki açık BTree-sorted kanonik form (`suderra-installer/src/contracts.rs:864-902` ↔ post-image Python `sort_keys=True`) doğru desen — OTA'yı buna birleştir + **diller-arası golden-vector testi** ekle. |
| AUD-11 | Düşük | `suderra-watchdog`'da 0 unit test — eşik yükseltme, `valid_unit_name`, env clamp gibi gerçek mantık test edilmemiş. (Installer 24, ota 5, config 3 testli.) |
| — | Düşük | `#![forbid(unsafe_code)]` 8 crate'ten yalnız 2'sinde; `[workspace.lints]` yok — kayıtta MIN-3 olarak mevcut. |

**İyi durumda:** Non-test kodda `.unwrap()`/`.expect()`/`panic!` **sıfır** (68 unwrap'ın tamamı
`#[cfg(test)]` içinde — teker teker doğrulandı); yalnız 2 `unsafe` blok (watchdog `ioctl`,
SAFETY yorumlu); 23/23 shell script `set -euo pipefail`; `eval`/`curl|bash` yok;
imza doğrulama zinciri (pubkey-SHA256 pinleme, expiry, key-epoch, semver floor, hedef bağlama,
bundle hash — `ota main.rs:179-497`; installer `safe_join`, https-only, boyut tavanları)
satır satır incelendi ve doğru.

### 4.5 Test kapsamı

| ID | Ciddiyet | Bulgu |
|---|---|---|
| AUD-8 | Orta | ARM FIT reject-at-boot testi (`tests/qemu/arm-fit-signature-boot.sh`) **hiçbir workflow'a bağlı değil** (ADR-0007 MED2'nin kendisi) — ARM imza reddi yalnız build-time'da kanıtlanıyor, boot'ta değil. |
| AUD-12 | Orta | `tests/security/` (verity-tamper, lynis-baseline, nmap-external) **hiçbir workflow'dan çağrılmıyor** — gating değil, kanıt-analizörü konumunda. |
| — | — | Eksen B runtime testi fiilen yok (kod olmadığı için — RT-1..RT-7 sonucu); G4/G5 donanım kapılarının otomasyonu yok (tasarım gereği, `scripts/evidence/station-acquisition.py` kontratı hazır); Rust parser'larda fuzzing/property test yok. |

**İyi durumda:** `tests/image-contracts/` (~48 test) build/release kontratlarını gerçek
kriptografik kapılarla (openssl dgst, `veritysetup verify`, `sbverify`, `dumpimage`) doğruluyor;
`post-image.sh:378-629` prod kontratı fail-closed.

### 4.6 Kayıtlı olup açık kalanlar (bu denetimde teyit edildi)

PR #84 merge edilse bile açık kalacak, ADR-0008 Wave 3-4'e planlı kalemler:

- **NEW-4 (Orta):** `suderra-agent.service` harici agent'a `/dev/tpm0` + `/dev/watchdog` veriyor.
- **NEW-5 (Düşük ama NEW-2'yi kilitliyor):** Prod'da firewall appliance-locked ruleset'e hiç
  geçmiyor — provisioning ruleset'i kalıcı. NEW-2'nin egress allow-list'i cihaz kilitlenene dek
  sahada **etkisiz**.
- **NEW-7 (kısmi):** `verify_strict` indi; imzalayıcı-taraf kanonik-bayt değişikliği açık.
- **C-6 (Düşük-Orta):** OTA bundle / installer manifest'te verify→use TOCTOU.
- **C-7 (Düşük):** SemVer-dışı `VERSION_ID` OTA'yı kilitler (fail-closed erişilebilirlik sorunu).
- **RT-2/RT-3, RT-6 Tier-2, HW-1/HW-2 (G4/G5), SC-1:** donanım/HSM-kapılı; register'da.

## 5. Fazlı yol haritası

### Faz 0 — Bu hafta (kod yazmadan en yüksek getiri)

1. **PR #84'ü draft'tan çıkar, incele, merge et.** (NEW-1 Yüksek dahil 10+ bulgu kapanır;
   AUD-1 kökten çözülür.) Merge sonrası register Kategori-6'da NEW-6 satırını "kapalı" yap.
2. Dependabot PR'larını merge et (#47 checkout v7 major — release notlarıyla teyit).
3. `codex/enterprise-evidence-architecture`'dan **yalnız** GRUB2 fingerprint deltasını
   (`db58625`) yeni main üstüne taşı; branch'i kapat/arşivle.

### Faz 1 — Kısa vade (CI derinliği)

1. **CodeQL** `init`/`analyze` workflow'u ekle (AUD-2) — öncelik: Python (`scripts/evidence/`),
   sonra Rust.
2. **İmaj-seviyesi CVE taraması** (AUD-3): nightly `image-build.yml` çıktısındaki rootfs'i
   Grype/Trivy ile tara (SBOM'dan `grype sbom:` yolu da olur); `--only-fixed`'i imaj taramasında
   kaldır, düzeltmesiz CVE'leri VEX ile yönet.
3. `arm-fit-signature-boot.sh`'ı CI'a bağla (AUD-8 / MED2); `tests/security/*`'i en az nightly
   gating yap (AUD-12).

### Faz 2 — Orta vade (kod kalitesi + kalan bulgular)

1. OTA imza kanonikalizasyonunu installer'ın sorted-key formuna birleştir + golden-vector
   testi (AUD-4; NEW-7'nin imzalayıcı-taraf işiyle birlikte tek PR mantıklı).
2. tokio küçültme (AUD-9), `overflow-checks` (AUD-10), collector temizliği (AUD-5),
   watchdog unit testleri (AUD-11), `forbid(unsafe_code)`+`workspace.lints` (MIN-3).
3. NEW-4 (agent capability mediation), NEW-5 (appliance-locked firewall geçişi), C-6, C-7 —
   ADR-0008 Wave 3-4 ile hizalı.
4. `CCACHE_MAXSIZE` takibi + Docker katman-cache iyileştirmesi.

### Faz 3 — Donanım kapıları (takvimi donanım erişimine bağlı)

- G4/G5 lab kanıtları (HW-1/HW-2/HW-3), RT-2 (TPM quote), RT-3 (kriptografik cihaz kimliği),
  RT-6 Tier-2 (gerçek TPM-NV floor), SC-1 (HSM canlı attestation), HW-4 (cihaz-tarafı SB
  enrollment prosedürü).

## 6. Kapsam dışı / not

- `host-tools/` derinlemesine okunmadı (host-only, cihaz saldırı yüzeyinde değil; cargo-deny
  ile aynı disipline tabi).
- Bu rapor bir kerelik denetim anlık görüntüsüdür; kalıcı kayıt
  [security-gaps-and-risks.md](security-gaps-and-risks.md)'de tutulmaya devam etmelidir.
  AUD-* maddelerinden kapanmayanlar bir sonraki register güncellemesinde oraya taşınmalıdır.
