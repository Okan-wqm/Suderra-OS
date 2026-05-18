# SBOM (Software Bill of Materials) Süreci

> **Status:** Release workflow'da CycloneDX üretimi aktif; local fallback
> yolu Buildroot `legal-info/manifest.csv` çıktısından CycloneDX ve SPDX
> üretir. Boş component listesi release kapısında ve local script'te reddedilir.

## Amaç

CRA Article 13(2) ve NIST SSDF PS.3.2 her release için SBOM zorunlu kılar.
SBOM:

- İmajdaki yazılım bileşenlerini makine-okunabilir biçimde listeler
- CVE ve VEX eşleştirmesi için girdi sağlar
- Müşteri ve denetçi doğrulamasına release artifact'i olarak sunulur

## Format

Release artifact formatı **CycloneDX JSON** (`*.cyclonedx.json`). Local SBOM
üretimi ayrıca audit ve lisans süreçleri için **SPDX 2.3 JSON**
(`sbom.spdx.json`) üretir.

## Üretim Akışı

```text
Buildroot release image (*.img.xz)
    ↓
release.yml / sbom job
    ↓
syft "$image" -o cyclonedx-json
    ↓
suderra-<target>.cyclonedx.json
    ↓
release.yml / release-evidence job
    ↓
cosign keyless signature (*.sig + *.cert)
    ↓
GitHub Release asset
```

`ci/build-matrix.yml` Buildroot target ve release artifact adları için tek
source of truth'tur. Workflow matrix değerlerini
`scripts/ci/validate-build-matrix.py` ile üretir; SBOM adları image artifact
taban adıyla eşleşir.

## Yayınlanan Dosyalar

Her release image için:

- `suderra-<target>.img.xz`
- `suderra-<target>.img.xz.sha256`
- `suderra-<target>.manifest.txt`
- `suderra-<target>.cyclonedx.json`
- `suderra-<target>.cyclonedx.json.sig`
- `suderra-<target>.cyclonedx.json.cert`

Release ayrıca installer binary'leri, `SHA256SUMS`, `manifest.json` ve tüm
non-signature release asset'leri için cosign imza/sertifika dosyalarını yayınlar.
Provenance ayrı bir SBOM asset'i değildir; OS image'ları, installer binary'leri
ve `manifest.json` için GitHub Artifact Attestations üzerinden doğrulanır.

## İçerik Beklentisi

SBOM en azından syft'in image üzerinden tespit ettiği paketleri veya Buildroot
`legal-info/manifest.csv` paket satırlarını içermelidir. Release workflow'u ve
`scripts/gen-sbom.sh` boş `components` listesi üreten SBOM'ları reddeder.

Hedef zenginleştirmeler:

- Linux kernel versiyonu ve applied patch referansları
- Rust userspace dependency bilgileri
- Bootloader ve firmware versiyonları
- Anahtar referansları (key material dahil edilmez)

## Tooling

- **syft** — release workflow'da aktif CycloneDX üretimi
- **scripts/gen-sbom.sh** — syft yoksa Buildroot legal-info manifest'inden
  deterministic CycloneDX/SPDX üretimi; boş component listesi fail-closed
- **cosign** — SBOM imzası ve sertifikası
- **GitHub Artifact Attestations** — image, installer ve manifest provenance
- **Trivy/Grype** — CVE eşleştirme
- **Buildroot legal-info** — local fallback SBOM ve lisans kanıtı girdisi
- **cargo-sbom** — ileride Rust dependency zenginleştirme girdisi

## Operasyonel Kontroller

- SBOM dosyası release asset listesinde bulunmalı
- `.sig` ve `.cert` dosyaları aynı taban adla bulunmalı
- `cosign verify-blob` repository workflow identity'siyle geçmeli
- Release image adları `ci/build-matrix.yml` `release_artifact` değerleriyle
  uyumlu olmalı
- `gh attestation verify` release image, installer binary ve `manifest.json` için geçmeli

## Yapılacaklar

- [ ] Rust userspace dependency SBOM'unu image SBOM'una bağla
- [ ] SBOM diff tool (release-to-release değişiklik)
- [ ] Müşteri sunum şablonu (PDF render)

## Referanslar

- [CycloneDX](https://cyclonedx.org/)
- [GitHub Artifact Attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [CRA Annex II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [NIST SSDF PS.3.2](https://csrc.nist.gov/Projects/ssdf)
