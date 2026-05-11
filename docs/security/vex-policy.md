# VEX (Vulnerability Exploitability eXchange) Politikası

> **Status:** Skeleton — Faz 5'te otomasyona geçer.

## Amaç

Suderra OS, müşterinin SBOM-tabanlı CVE tarama araçlarında çıkan her bulguya değil, **gerçekten exploitable olanlara** odaklanmasını sağlamak için her release ile bir VEX dokümanı yayınlar.

## Standart

OpenVEX 0.2.0 (Sigstore community). Alternatif: CycloneDX VEX 1.5.

## Akış

```
1. SBOM üret (CycloneDX, scripts/gen-sbom.sh)
   ↓
2. CVE tarama (Trivy + Grype)
   ↓
3. Triage (her CVE için):
   - not_affected: justification zorunlu
   - affected: patch ne zaman çıkacak
   - fixed: bu sürümde düzeltildi
   - under_investigation: değerlendirme aşamasında
   ↓
4. OpenVEX JSON oluştur
   ↓
5. Cosign ile imzala
   ↓
6. Release artifact olarak yayınla
```

## Triage Karar Ağacı

```
CVE: paket X, versiyon Y'da bug Z var
│
├─ Bu paket Suderra OS'te var mı?  ──── HAYIR ─→ not_affected (component_not_present)
│
├─ Var ama bu özellik etkin mi?    ──── HAYIR ─→ not_affected (vulnerable_code_not_present)
│
├─ Etkin ama bu code path çalıştırılıyor mu?  ── HAYIR ─→ not_affected (vulnerable_code_not_in_execute_path)
│
├─ Çalıştırılıyor ama saldırgan kontrol edebilir mi?  ── HAYIR ─→ not_affected (vulnerable_code_cannot_be_controlled_by_adversary)
│
├─ Suderra'da mevcut mitigation var mı (örn. seccomp blocks)?  ── EVET ─→ not_affected (inline_mitigations_already_exist)
│
├─ Patch yayınlandı mı (sürümde)?  ── EVET ─→ fixed
│
└─ Patch bekliyor → affected
```

## SLA (CVE Triage)

| Severity | Triage SLA | Patch SLA |
|---|---|---|
| Critical (CVSS ≥9.0) | 24 saat | 7 gün |
| High (7.0-8.9) | 72 saat | 30 gün |
| Medium (4.0-6.9) | 7 gün | 90 gün |
| Low (<4.0) | 30 gün | Yıllık release |

## Yayınlama

VEX dokümanları:
- `vex/suderra-os-<version>.openvex.json` (repo)
- Release artifact (cosign-signed)
- HTTPS feed: `https://updates.suderra.example/vex/`
- Müşteri dashboard üzerinden

## Otomasyon Yol Haritası

| Faz | Eylem |
|---|---|
| 0 | Manuel template (`vex/suderra-os-sample.openvex.json`) |
| 5 | `scripts/gen-vex.sh` — SBOM + Trivy çıktısından VEX template |
| 6 | CI'da PR diff (yeni CVE varsa triage zorunlu) |
| 7 | Müşteri dashboard entegrasyonu |

## Yapılacaklar

- [ ] `scripts/gen-vex.sh` (Faz 5)
- [ ] CI'da otomatik triage prompt (Faz 5)
- [ ] Müşteri sunum API (Faz 7)

## Referanslar

- [OpenVEX Specification](https://github.com/openvex/spec)
- [vexctl](https://github.com/openvex/vexctl)
- [CISA VEX Profile](https://www.cisa.gov/sites/default/files/2024-10/CSAF-VEX-Profile.pdf)
- [docs/security/cve-process.md](cve-process.md)
- CRA Annex I.II.2
