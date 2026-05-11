# SBOM (Software Bill of Materials) Süreci

> **Status:** Skeleton — Faz 5 (operasyonel olgunluk) içinde tamamlanacak.

## Amaç

CRA Article 13(2) ve NIST SSDF PS.3.2 her release için SBOM zorunlu kılar. SBOM:

- Imajdaki tüm yazılım bileşenlerini listeler
- CVE eşleştirme yapabilmek için makine-okunabilir format
- Müşteriye + denetleyiciye sunulur

## Format

**CycloneDX 1.5+** (JSON). Alternatif: SPDX 2.3+.

Neden CycloneDX:

- VEX (Vulnerability Exploitability eXchange) desteği
- Daha hafif, daha modern
- OWASP arkasında

## Üretim Akışı

```
Buildroot build
    ↓
output/legal-info/manifest.csv     (Buildroot'un kendi raporu)
    ↓
scripts/gen-sbom.sh                (CSV → CycloneDX JSON)
    ↓
output/sbom.cyclonedx.json         (artifact)
    ↓
CI uploads to release
```

## SBOM İçeriği

- Tüm Buildroot paketleri (versiyon, lisans, URL)
- Linux kernel (versiyon, applied patches)
- Suderra Edge Agent (cargo manifest dependencies)
- Bootloader (shim, systemd-boot/GRUB versiyonları)
- Anahtarlar (sadece referans, key material değil)

## Tooling

- **syft** (Anchore) — container/filesystem'den otomatik SBOM
- **buildroot-make-show-info** — Buildroot native
- **cargo-sbom** — Rust toolchain için
- **Trivy** — CVE eşleştirme + VEX üretimi

## Yapılacaklar

- [ ] `scripts/gen-sbom.sh` implementasyonu (Faz 5)
- [ ] CI workflow'da otomatik SBOM artifact
- [ ] SBOM diff tool (release-to-release değişiklik)
- [ ] Müşteri sunum şablonu (PDF render)

## Referanslar

- [CycloneDX](https://cyclonedx.org/)
- [CRA Annex II](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [NIST SSDF PS.3.2](https://csrc.nist.gov/Projects/ssdf)
