# VEX (Vulnerability Exploitability eXchange)

Bu klasör, Suderra OS imajları için VEX dokümanlarını içerir.

## Neden VEX?

SBOM'da görünen her CVE gerçekten exploitable değildir. VEX:
- Hangi CVE'lerin etkisiz olduğunu (`not_affected`) açıklar
- Hangi CVE'lerin etkilendiğini (`affected`) ve düzeltildiğini (`fixed`) belirtir
- Müşteri scanner'larındaki false-positive yükünü azaltır
- CRA Annex I.II.2 "promptly informing users" yükümlülüğünü karşılar

## Format

OpenVEX 0.2.0 (Sigstore tarafından sürdürülen) tercih edilir. CycloneDX VEX 1.5 de desteklenir.

## Dosya İsimlendirme

```
vex/
├── README.md                                # Bu dosya
├── suderra-os-vYYYY.MM.DD.openvex.json      # Her release için bir VEX
└── archive/                                 # Eski sürümler
```

## Yaşam Döngüsü

1. Yeni release: SBOM üret → Trivy/Grype ile CVE listesi çıkar
2. Her CVE için triage yap:
   - `not_affected`: Suderra OS bu bileşeni kullanmıyor / etkin değil → justification yaz
   - `affected`: etkilenir → düzeltme planı (patch SLA)
   - `fixed`: bu sürümde düzeltildi → referans CVE/patch
   - `under_investigation`: henüz değerlendiriliyor
3. VEX dokümanını yayınla (release artifact olarak)
4. Müşteri: SBOM + VEX = gerçek risk durumu

## Justification Etiketleri (OpenVEX)

`not_affected` için zorunlu:
- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

## Otomasyon

Faz 5'te:
- `scripts/gen-vex.sh` — SBOM'dan VEX template
- CI'da PR review için VEX diff
- Müşteriye dashboard üzerinden VEX teslimi

## Referanslar

- [OpenVEX Specification](https://github.com/openvex/spec)
- [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
- [CISA VEX](https://www.cisa.gov/sites/default/files/2024-10/CSAF-VEX-Profile.pdf)
- [docs/security/cve-process.md](../docs/security/cve-process.md)
