# Release Doğrulama (Verify Release)

Müşteri veya yetkili teknisyen, indirdiği Suderra OS artifact'inin Suderra
release workflow'undan geldiğini ve değişmediğini doğrulayabilir.

Örnekler `v1.0.0` ve Raspberry Pi 4 artifact'i içindir. Diğer imajlar
`ci/build-matrix.yml` içindeki `release_artifact` değerleriyle aynı adları
kullanır.

## Hızlı Doğrulama

```bash
VERSION=v1.0.0
REPO=Okan-wqm/suderra-os
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
doğrulanır. Aşağıdaki komut için `--signer-workflow` ve `--source-ref`
destekleyen güncel GitHub CLI gerekir.

```bash
gh attestation verify "${ARTIFACT}" \
    -R "${REPO}" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${VERSION}"
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
`SHA256SUMS` toplu hash dosyasıdır. İkisi de release job'ında cosign keyless
ile imzalanır.

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
