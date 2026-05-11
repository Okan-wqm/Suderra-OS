# Release Doğrulama (Verify Release)

Müşteri veya yetkili teknisyen, indirdiği Suderra OS imajı/RAUC bundle'ının **gerçekten Suderra'dan geldiğini** ve **değiştirilmediğini** doğrulayabilir.

## Hızlı Doğrulama

```bash
# 1. cosign yükle
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo install cosign-linux-amd64 /usr/local/bin/cosign

# 2. İmza dosyalarını indir (release'den)
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/disk.img
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/disk.img.sig
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/disk.img.cert

# 3. Cosign keyless doğrulama
cosign verify-blob \
    --certificate disk.img.cert \
    --signature disk.img.sig \
    --certificate-identity-regexp "https://github.com/Okan-wqm/suderra-os/.github/workflows/release.yml.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    disk.img
```

Çıktı: `Verified OK`

## SLSA Provenance Doğrulama

Her release ile birlikte `.intoto.jsonl` (in-toto attestation) yayınlanır:

```bash
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/suderra-os.intoto.jsonl

# slsa-verifier yükle
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

slsa-verifier verify-artifact disk.img \
    --provenance-path suderra-os.intoto.jsonl \
    --source-uri github.com/Okan-wqm/suderra-os \
    --source-tag v1.0.0
```

## SBOM Doğrulama

```bash
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/sbom.cyclonedx.json
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/sbom.cyclonedx.json.sig

cosign verify-blob \
    --certificate sbom.cyclonedx.json.cert \
    --signature sbom.cyclonedx.json.sig \
    --certificate-identity-regexp "https://github.com/Okan-wqm/suderra-os/.github/workflows/release.yml.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    sbom.cyclonedx.json
```

## VEX Doğrulama

```bash
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.0.0/suderra-os.openvex.json

# Cosign ile imza doğrula (yukarıdaki ile aynı pattern)
# Sonra Trivy ile birleştir:
trivy image --vex suderra-os.openvex.json suderra-os:v1.0.0
```

## Cihaz Üzerinde dm-verity Doğrulama

Cihaz boot ederken zaten yapar, ama manuel kontrol:

```bash
# Verity root hash kontrolü (cihaz üzerinde, dev variant)
dmsetup table

# Beklenen çıktı:
# 0 1048576 verity 1 /dev/disk/by-partlabel/rootfs-a /dev/disk/by-partlabel/verity 4096 4096 ... <root-hash>
```

## RAUC Bundle Doğrulama

```bash
rauc info --keyring=/etc/rauc/keyring.pem suderra-os-v1.0.0.raucb

# Beklenen:
# Compatible: suderra-os-x86_64
# Version: v1.0.0
# Verification: OK
```

## Tam Doğrulama Akışı (Üretim)

```
1. SHA256 hash check (release notes'tan)
2. Cosign signature verify
3. SLSA provenance verify (slsa-verifier)
4. SBOM signature verify
5. VEX signature verify
6. Cihaza yükle (flash)
7. Boot → dm-verity otomatik check
8. RAUC info → keyring verify
```

## Trust Anchor'lar

| Anchor | Lokasyon | Güven kaynağı |
|---|---|---|
| Cosign keyless | Sigstore Fulcio (Transparency log) | İmzalama olayı public log'a yazılıyor |
| GitHub repo identity | OIDC issuer (token.actions.githubusercontent.com) | GitHub OIDC token |
| RAUC keyring | İmaj içinde `/etc/rauc/keyring.pem` | Suderra'nın yayınladığı public key |
| UEFI db | Cihaz UEFI variables | OEM veya MOK enrollment |

## Yapılacaklar

- [ ] `scripts/verify-release.sh` — yukarıdaki adımları otomatize et (Faz 5)
- [ ] PGP-signed release notes (alternative trust path)
- [ ] Hardware-based attestation (TPM PCR remote attestation, Faz 6+)

## Referanslar

- [Sigstore cosign](https://docs.sigstore.dev/cosign/verifying/verify/)
- [SLSA verifier](https://github.com/slsa-framework/slsa-verifier)
- [in-toto attestations](https://docs.sigstore.dev/cosign/verifying/attestation/)
- [docs/security/vex-policy.md](../security/vex-policy.md)
