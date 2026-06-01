# Operasyon Runbook

> **Status:** Release RC adımları aktiftir; saha pilot bölümü Faz 7'de
> detaylanacaktır.

## Enterprise RC Release Runbook

Bu akış `v0.1.0-rc.1` için fail-closed sıradır. Eski Image Build run'ı, workflow
ve validator patch'leri merge edildikten sonra tekrar kullanılamaz.

1. Hardening branch'i PR ile merge et:

   ```bash
   git switch -c release/rc-evidence-hardening
   ./scripts/run-tests.sh image-contracts
   git diff --check
   git add .
   git commit -S -s -m "Harden enterprise release evidence gates"
   git push -u origin release/rc-evidence-hardening
   gh pr create --base main --head release/rc-evidence-hardening --fill
   gh pr checks --watch
   gh pr merge --squash --delete-branch
   git switch main
   git pull --ff-only origin main
   ```

2. GitHub governance bootstrap tamamlanmadan RC'ye geçme:

   - repository Organization/Enterprise altında olmalı veya kabul edilmiş audit
     export/replay evidence sağlanmalı,
   - branch, ruleset, environment ve required check adları aşağıdaki generated
     governance policy yansımasıyla uyumlu olmalı,
   - `GOVERNANCE_READ_TOKEN`, release tag signing trust vars/secrets,
     `SUDERRA_OPERATOR_BUNDLE_ALLOWED_HOST`,
     `SUDERRA_OPERATOR_BUNDLE_CERTIFICATE_IDENTITY`,
     `SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64` ve
     `SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64` tanımlı olmalı.

   <!-- suderra-generated: governance-policy -->
   | Category | Name |
   | --- | --- |
   | `required_check` | `Build / Build matrix contract` |
   | `required_check` | `Build / Buildroot defconfig parse smoke (pi-cm4-revpi-usb-installer)` |
   | `required_check` | `Build / Buildroot defconfig parse smoke (qemu-x86_64)` |
   | `required_check` | `Build / Buildroot defconfig parse smoke (revpi4)` |
   | `required_check` | `Build / Buildroot defconfig parse smoke (rpi4)` |
   | `required_check` | `Build / Syntax and workflow contracts` |
   | `required_check` | `Hadolint (Dockerfile lint) / Hadolint` |
   | `required_check` | `Lint / Build Matrix Contract` |
   | `required_check` | `Lint / DCO (Signed-off-by) Check` |
   | `required_check` | `Lint / GitHub Actions Lint` |
   | `required_check` | `Lint / Image Contract + Installer Tests` |
   | `required_check` | `Lint / Markdown Lint` |
   | `required_check` | `Lint / Secret Scan (gitleaks)` |
   | `required_check` | `Lint / ShellCheck` |
   | `required_check` | `Lint / YAML Lint` |
   | `required_check` | `Rust Userspace / Build (aarch64-unknown-linux-musl)` |
   | `required_check` | `Rust Userspace / Build (x86_64-unknown-linux-musl)` |
   | `required_check` | `Rust Userspace / Format + Clippy + Test` |
   | `required_check` | `Rust Userspace / MSRV check (Rust 1.86)` |
   | `required_check` | `Rust Userspace / Security (audit + deny)` |
   | `required_check` | `Security Scan / Gitleaks (secret scan)` |
   | `required_check` | `Security Scan / Grype (filesystem)` |
   | `required_check` | `Security Scan / Trivy (config / Dockerfile)` |
   | `required_check` | `Security Scan / Trivy (filesystem)` |
   | `required_check` | `Security Scan / VEX JSON syntax` |
   <!-- /suderra-generated -->

3. Yeni `origin/main` SHA için push kaynaklı Image Build'i yakala:

   ```bash
   REPO=Okan-wqm/Suderra-OS
   VERSION=v0.1.0-rc.1
   SOURCE_SHA="$(git rev-parse origin/main)"
   IMAGE_BUILD_RUN_ID="$(gh run list --repo "$REPO" --workflow "Image Build" \
     --branch main --event push --commit "$SOURCE_SHA" --limit 1 \
     --json databaseId --jq '.[0].databaseId')"
   gh run watch "$IMAGE_BUILD_RUN_ID" --repo "$REPO" --exit-status
   gh api "repos/${REPO}/actions/runs/${IMAGE_BUILD_RUN_ID}" \
     > /tmp/image-build-run.json
   IMAGE_BUILD_RUN_ATTEMPT="$(jq -r '.run_attempt' /tmp/image-build-run.json)"
   ```

4. Operator bundle'ı trusted operator signing workflow veya kabul edilmiş
   GitHub Actions OIDC identity ile imzala. Bundle URL'leri redirect
   döndürmemeli ve host repo/org policy'deki allowlist ile eşleşmelidir.

5. Evidence ingress'i dispatch et; host/signer policy input değildir:

   ```bash
   OPERATOR_BUNDLE_SHA256="$(sha256sum operator-evidence-${VERSION}.tar.gz | awk '{print $1}')"
   gh workflow run "Release Evidence Ingress" --repo "$REPO" --ref main \
     -f version="$VERSION" \
     -f source_sha="$SOURCE_SHA" \
     -f source_image_build_run_id="$IMAGE_BUILD_RUN_ID" \
     -f source_image_build_run_attempt="$IMAGE_BUILD_RUN_ATTEMPT" \
     -f operator_bundle_url="$OPERATOR_BUNDLE_URL" \
     -f operator_bundle_sha256="$OPERATOR_BUNDLE_SHA256" \
     -f operator_bundle_signature_url="$OPERATOR_BUNDLE_SIGNATURE_URL" \
     -f operator_bundle_certificate_url="$OPERATOR_BUNDLE_CERTIFICATE_URL"
   ```

6. Ingress artifact digest'ini kaydet, sonra release-candidate preflight çalıştır:

   ```bash
   EVIDENCE_INGRESS_RUN_ID=<successful-run-id>
   gh run watch "$EVIDENCE_INGRESS_RUN_ID" --repo "$REPO" --exit-status
   gh run download "$EVIDENCE_INGRESS_RUN_ID" --repo "$REPO" \
     --name "rei-${VERSION}-${SOURCE_SHA}-${IMAGE_BUILD_RUN_ID}-${IMAGE_BUILD_RUN_ATTEMPT}" \
     --dir /tmp/evidence-ingress
   EVIDENCE_INGRESS_MANIFEST_SHA256="$(sha256sum \
     "/tmp/evidence-ingress/release-ingress/${VERSION}/evidence-ingress-manifest.json" | awk '{print $1}')"

   gh workflow run "Release Preflight" --repo "$REPO" --ref main \
     -f version="$VERSION" \
     -f source_sha="$SOURCE_SHA" \
     -f source_run_id="$IMAGE_BUILD_RUN_ID" \
     -f evidence_ingress_run_id="$EVIDENCE_INGRESS_RUN_ID" \
     -f evidence_ingress_manifest_sha256="$EVIDENCE_INGRESS_MANIFEST_SHA256" \
     -f profile=release-candidate
   ```

7. Preflight success sonrası `PREFLIGHT_RUN_ID`, attempt, artifact ID ve final
   `ingress-manifest.json` digest'ini tag annotation'a koy. Tag signed,
   annotated ve trusted fingerprint ile doğrulanmış olmalıdır. Draft release
   publish akışı final public proof asset'lerini tekrar indirip cosign ile
   doğrulamadan undraft yapmaz.

8. Abort durumunda tag ve draft release'i silmeden önce ingress, preflight,
   tag-binding, draft asset listesi ve failure loglarını generated retention
   policy'deki durable evidence store'a export et.

   <!-- suderra-generated: retention-policy -->
   - Policy ID: `suderra-enterprise-7y-immutable-evidence`
   - Minimum years: `7`
   - Store class: `immutable-encrypted-evidence-archive`
   - Required replay: `release-input-binding, runtime-suite, hsm-signing-manifest, station-acquisition, scanner-raw-replay, governance-snapshot, publication-manifest`
   <!-- /suderra-generated -->

## Saha Operasyon Runbook

Bu doküman saha personeline yöneliktir. Teknik detay değil, **adım adım eylem** içerir.

## Acil Durum Telefon Hattı

- **Suderra OS support:** +90-XXX-XXX-XXXX (24/7)
- **Eskalasyon:** <support@suderra.example>

## Yaygın Senaryolar

### S1: Cihaz veri göndermiyor

**Belirti:** Dashboard'da cihaz "offline" 5+ dk.

**Çözüm adımları:**

1. Cihazda LED durumu kontrol et:
   - Yeşil → çalışıyor, network problemi olabilir
   - Sarı → boot devam ediyor, 2 dk bekle
   - Kırmızı → hata, devam et
2. Ağ kablosu fiziksel kontrol
3. Switch port LED
4. Cihaz güç durumu (PSU LED)
5. Hala sorun → support'a bildirim aç (cihaz seri no + zaman damgası)

### S2: Cihaz boot etmiyor

**Belirti:** Power LED yanıyor ama ağ aktivitesi yok 5 dk+.

**Çözüm:**

1. **YAPMA:** Cihaza müdahale etme, açma
2. Güç kapat (30 sn bekle) → tekrar aç
3. Hala boot etmiyor → support, cihazı yerinde bırak

### S3: Sensör değeri saçma

**Belirti:** Su sıcaklığı -100 derece, vs.

**Çözüm:**

1. Fiziksel sensör kontrol (kablo, korozyon, biyolojik kirlilik)
2. Modbus terminator?
3. Hala sorun → support'a sensör tipi + cihaz seri no

### S4: Update sonrası garip davranış

**Belirti:** Yeni update sonrası anomali.

**Çözüm:**

1. Cihaz 5 dk içinde otomatik rollback yapmadıysa support'a haber ver
2. Dashboard'dan "rollback" komutu (yetkili kullanıcı)
3. Manuel: cihazı reboot et (3× — otomatik rollback tetiklenir)

## Saha Personeli Yetkileri

| Eylem | Yetki |
|---|---|
| Cihazı görsel inceleme | Operatör |
| Ağ kablosu kontrol/değiştirme | Operatör |
| Güç kapatma/açma | Operatör |
| Cihaz fiziksel taşıma | Saha mühendisi |
| Cihaz açma/donanım müdahale | YALNIZCA Suderra teknisyeni |
| Update tetikleme | Cloud admin |
| Factory reset | Cloud admin + müşteri onayı |

## Veri ve Gizlilik

- Cihazda biriken veri /data partition'da şifreli
- Sensör verisi sadece müşteriye gider (mTLS)
- Cihaz çalınırsa: /data anahtar TPM-sealed → veri kullanılamaz

## Yapılacaklar (Faz 7)

- [ ] Detaylı LED durum kodu tablosu
- [ ] Müşteri operatör eğitim materyali
- [ ] Olay yönetimi süreci
- [ ] SLA matrisi (response time)
- [ ] On-call rotation
