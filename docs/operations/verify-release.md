# Release Doğrulama (Verify Release)

Müşteri veya yetkili teknisyen, indirdiği Suderra OS artifact'inin Suderra
release workflow'undan geldiğini ve değişmediğini doğrulayabilir.

Alpha/pre-release artifact'leri lab validation içindir. Production doğrulama
akışı ancak `production-readiness` ve production-tier release evidence geçtiğinde
tamamlanmış sayılır.

`rc-evidence-dry-run` artifact'leri release doğrulama girdisi değildir. Bu
profil yalnız SSOT planlarını ve production gap raporunu prova eder; signed tag
ve yayın doğrulaması için `release-candidate` veya `production-candidate`
preflight artifact'i gerekir.

Live release gate, signed annotated tag içinde `Suderra-Preflight-Profile`
alanını zorunlu tutar. Pre-release tag'ler yalnız `release-candidate`, GA tag'ler
yalnız `production-candidate` preflight artifact'iyle yayın yetkisi alır. Bu
alanı taşımayan legacy tag metadata'sı sadece offline/archive verification
bağlamında incelenebilir; güncel release authorization veya promotion sağlamaz.

Enterprise production doğrulaması aynı release subject graph'a bağlı şu güncel
şemaları bekler:

<!-- suderra-generated: verification-schemas -->
| Role | Schema Version |
| --- | --- |
| `release_evidence` | `suderra.release-evidence.v6` |
| `release_subject_graph` | `suderra.release-subject-graph.v1` |
| `production_runtime_suite` | `suderra.qemu-production-runtime-suite.v2` |
| `runtime_observation` | `suderra.runtime-observation.v1` |
| `signing_manifest` | `suderra.signing-manifest.v2` |
| `hardware_subject` | `suderra.hardware-subject.v1` |
| `release_security_report` | `suderra.release-security-report.v2` |
| `retention_manifest` | `suderra.retention-manifest.v1` |
<!-- /suderra-generated -->

Örnekler `v1.0.0` ve Raspberry Pi 4 artifact'i içindir. Diğer imajlar
`ci/build-matrix.yml` içindeki `release_artifact` değerleriyle aynı adları
kullanır.

## Hızlı Doğrulama

```bash
VERSION=v1.0.0
REPO=Okan-wqm/Suderra-OS
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARTIFACT=suderra-rpi4-target.img.xz

curl -fsSLO "${BASE_URL}/${ARTIFACT}"
curl -fsSLO "${BASE_URL}/${ARTIFACT}.sha256"
curl -fsSLO "${BASE_URL}/${ARTIFACT}.sig"
curl -fsSLO "${BASE_URL}/${ARTIFACT}.cert"

sha256sum -c "${ARTIFACT}.sha256"

cosign verify-blob \
    --certificate "${ARTIFACT}.cert" \
    --signature "${ARTIFACT}.sig" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${ARTIFACT}"
```

Beklenen sonuç: hash doğrulaması geçer ve `cosign verify-blob` `Verified OK`
yazar.

## GitHub Provenance Doğrulama

Release workflow `actions/attest-build-provenance` ile GitHub Artifact
Attestations üretir. Workflow ayrı bir `attestations.intoto.jsonl` release
asset'i yayınlamaz; provenance GitHub attestation servisi üzerinden
doğrulanır. Aşağıdaki komut, attestation sertifika kimliğini release tag
workflow'una pinler.

```bash
gh attestation verify "${ARTIFACT}" \
    -R "${REPO}" \
    --cert-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

Offline doğrulama gerekiyorsa online bir makinede bundle ve trusted root alın:

```bash
gh attestation download "${ARTIFACT}" -R "${REPO}"
gh attestation trusted-root > trusted_root.jsonl
```

Sonra artifact, bundle dosyası ve `trusted_root.jsonl` offline ortama taşınıp
şu şekilde doğrulanır:

```bash
gh attestation verify "${ARTIFACT}" \
    -R "${REPO}" \
    --bundle sha256:<artifact-digest>.jsonl \
    --custom-trusted-root trusted_root.jsonl
```

## SBOM Doğrulama

Her release imajı için aynı taban adla CycloneDX JSON SBOM yayınlanır ve cosign
ile imzalanır.

```bash
SBOM=suderra-rpi4-target.cyclonedx.json

curl -fsSLO "${BASE_URL}/${SBOM}"
curl -fsSLO "${BASE_URL}/${SBOM}.sig"
curl -fsSLO "${BASE_URL}/${SBOM}.cert"

cosign verify-blob \
    --certificate "${SBOM}.cert" \
    --signature "${SBOM}.sig" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${SBOM}"
```

## Manifest ve SHA256SUMS

`manifest.json` `suderra-installer` tarafından tüketilen release manifest'idir.
`SHA256SUMS` toplu hash dosyasıdır. İkisi de protected `release-sign` job'ında
cosign keyless ile imzalanır; GitHub Release yayını protected
`release-publish` environment'ına bağlı publish job'ında yapılır.

```bash
for f in manifest.json SHA256SUMS; do
    curl -fsSLO "${BASE_URL}/${f}"
    curl -fsSLO "${BASE_URL}/${f}.sig"
    curl -fsSLO "${BASE_URL}/${f}.cert"
    cosign verify-blob \
        --certificate "${f}.cert" \
        --signature "${f}.sig" \
        --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "${f}"
done
```

## Publication Manifest ve Evidence Archive

`release-publication-manifest.json` yayınlanan byte setinin authoritative
envanteridir. Manifest kendisini kapsamaz; kendi `.sig` ve `.cert` sidecar'ları
ile doğrulanır. Manifest içindeki her dosya adı, byte sayısı ve SHA-256 digest'i
GitHub Release asset'lerinden indirilen dosyalarla eşleşmelidir.

```bash
for f in \
    release-publication-manifest.json \
    release-evidence-${VERSION}.tar.zst; do
    curl -fsSLO "${BASE_URL}/${f}"
    curl -fsSLO "${BASE_URL}/${f}.sig"
    curl -fsSLO "${BASE_URL}/${f}.cert"
    cosign verify-blob \
        --certificate "${f}.cert" \
        --signature "${f}.sig" \
        --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "${f}"
done
```

Manifest doğrulaması:

```bash
python3 scripts/evidence/release-publication-manifest.py validate \
    release-publication-manifest.json \
    --release-dir . \
    --expected-version "${VERSION}" \
    --require-self-sidecars \
    --require-asset-sidecars
```

Release workflow bu doğrulamayı CI workspace kopyası üzerinde bırakmaz; draft
GitHub Release oluşturulduktan sonra asset'leri temiz bir dizine tekrar indirir,
aynı manifest validator'ını indirilen byte setine karşı çalıştırır, ardından
`release-post-publication-verification.json` ve
`release-publication-proof-manifest.json` proof asset'lerini yayınlayıp release'i
public yapar. Harici doğrulamada güven kaynağı CI çalışma dizini değil, yalnız
GitHub Release asset'leri olmalıdır.

Minimal bağımsız doğrulama:

```bash
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

manifest = json.loads(Path("release-publication-manifest.json").read_text(encoding="utf-8"))
for item in manifest["files"]:
    path = Path(item["name"])
    if not path.is_file():
        raise SystemExit(f"missing release asset: {path}")
    if path.stat().st_size != item["bytes"]:
        raise SystemExit(f"size mismatch: {path}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
        raise SystemExit(f"sha256 mismatch: {path}")
print("publication manifest verified")
PY
```

Evidence archive doğrulaması:

```bash
mkdir -p evidence
tar --zstd -xf "release-evidence-${VERSION}.tar.zst" -C evidence
find "evidence/${VERSION}" -name evidence.json -print0 | \
  while IFS= read -r -d '' evidence_json; do
    python3 scripts/evidence/release-evidence.py validate \
      --require-pass \
      --check-files \
      --validate-subject-graph \
      "${evidence_json}"
  done
```

Enterprise retention doğrulaması:

```bash
python3 scripts/evidence/evidence_contract.py retention-plan \
    --version "${VERSION}" \
    --source-sha "<release-source-sha>" \
    --source-run-id "<image-build-run-id>" \
    > expected-retention-plan.json

python3 scripts/evidence/validate-release-inputs.py \
    --version "${VERSION}" \
    --release-tier production \
    --profile production-candidate \
    --root evidence \
    --binding-manifest "evidence/release-inputs/${VERSION}/production-candidate.json" \
    --source-sha "<release-source-sha>" \
    --source-run-id "<image-build-run-id>" \
    --check-files
```

Production-candidate verification also expects `release-ota/`, scanner-native
raw reports, signing manifests, hardware subjects, role bindings, station
registry, and retention manifest entries to close over the same subject graph.
The retention manifest must prove restore/replay from the immutable archive and
the restored archive digest must equal the archived object digest.

## VEX Doğrulama

OpenVEX dosyaları yayınlandığında aynı cosign pattern'i ile doğrulanır ve
tarayıcıya verilir:

```bash
VEX=suderra-os.openvex.json
curl -fsSLO "${BASE_URL}/${VEX}"
curl -fsSLO "${BASE_URL}/${VEX}.sig"
curl -fsSLO "${BASE_URL}/${VEX}.cert"
cosign verify-blob \
    --certificate "${VEX}.cert" \
    --signature "${VEX}.sig" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${VEX}"
trivy image --vex "${VEX}" suderra-os:"${VERSION}"
```

## Cihaz Üzerinde dm-verity Doğrulama

Cihaz boot ederken zaten yapar, ama manuel kontrol:

```bash
dmsetup table
```

Beklenen çıktı `verity` target'ı, rootfs partition'ı ve release manifest'iyle
uyumlu root hash içerir.

## RAUC Bundle Doğrulama

```bash
rauc info --keyring=/etc/rauc/keyring.pem suderra-os-v1.0.0.raucb
```

Beklenen:

```text
Compatible: suderra-os-x86_64
Version: v1.0.0
Verification: OK
```

## Tam Doğrulama Akışı (Üretim)

1. Artifact ve `.sha256` indir, hash doğrula.
2. Artifact `.sig` + `.cert` ile cosign keyless imzasını doğrula.
3. GitHub Artifact Attestation provenance doğrula.
4. SBOM imzasını doğrula.
5. `manifest.json` ve `SHA256SUMS` imzalarını doğrula.
6. VEX yayınlandıysa imzasını doğrula ve tarama aracına ver.
7. Cihaza yükle.
8. Boot sonrası dm-verity durumunu kontrol et.
9. RAUC bundle varsa `rauc info` ile keyring doğrulaması yap.
10. Evidence archive içinde signing manifest, hardware subject, governance role
    bindings ve retention manifest'in aynı subject ID'ye bağlı olduğunu doğrula.
11. Retained archive üzerinden restore/replay testlerini çalıştır.

## Trust Anchor'lar

| Anchor | Lokasyon | Güven kaynağı |
|---|---|---|
| Cosign keyless | Sigstore Fulcio + transparency log | İmzalama olayı public log'a yazılır |
| GitHub Artifact Attestations | GitHub attestation servisi | Workflow provenance ve artifact digest |
| GitHub repo identity | OIDC issuer (`token.actions.githubusercontent.com`) | GitHub Actions OIDC token |
| RAUC keyring | İmaj içinde `/etc/rauc/keyring.pem` | Suderra public key |
| UEFI db | Cihaz UEFI variables | OEM veya MOK enrollment |

## Yapılacaklar

- [ ] `scripts/verify-release.sh` — yukarıdaki adımları otomatize et
- [ ] PGP-signed release notes (alternative trust path)
- [ ] Hardware-based attestation (TPM PCR remote attestation, Faz 6+)

## Referanslar

- [Sigstore cosign](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub Artifact Attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [GitHub offline attestation verification](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline)
- [docs/security/vex-policy.md](../security/vex-policy.md)
