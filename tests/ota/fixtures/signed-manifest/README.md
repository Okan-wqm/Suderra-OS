# Diller-arası imza fixture'ı (`ed25519-suderra-os-update-manifest-v2`)

`manifest.json`, `scripts/create-os-update-manifest.py` ile **tek kullanımlık**
(commit edilmeyen) bir Ed25519 test anahtarıyla imzalanmıştır;
`test-key.ed25519.pub` o anahtarın 64-hex public key formudur (cihazdaki
`/etc/suderra/os-update-manifest.ed25519.pub` ile aynı format).

Bu fixture'ı `suderra-ota`'nın `python_signed_fixture_verifies_in_rust` unit
testi tüketir: Python imzalayıcının ürettiği kanonik baytların Rust
doğrulayıcının (`suderra_config::canonical`) baytlarıyla bayt-bayt aynı
olduğunun uçtan uca kanıtıdır. `release_notes` alanı bilinçli olarak Türkçe
karakter içerir (non-ASCII kaçış sözleşmesini de sınar).

## Yeniden üretme (imza sözleşmesi değişirse)

```bash
openssl genpkey -algorithm ed25519 -out /tmp/fixture-key.pem
openssl pkey -in /tmp/fixture-key.pem -pubout -out /tmp/fixture-key.pub
printf 'suderra canonical-v2 fixture bundle\n' > /tmp/fixture-bundle.raucb
python3 scripts/create-os-update-manifest.py create \
  --bundle /tmp/fixture-bundle.raucb \
  --version v0.2.0 --target suderra-os-x86_64 \
  --min-current-version v0.1.0 --rollback-floor v0.1.0 \
  --key-epoch 1 --key-id canonical-v2-fixture \
  --expires-at 2099-01-01T00:00:00Z \
  --release-notes "Diller-arası golden fixture — Türkçe karakter: ğüşöçİ" \
  --signing-key /tmp/fixture-key.pem --public-key /tmp/fixture-key.pub \
  --output tests/ota/fixtures/signed-manifest/manifest.json
openssl pkey -pubin -in /tmp/fixture-key.pub -outform DER | tail -c 32 \
  | od -A n -t x1 | tr -d ' \n' > tests/ota/fixtures/signed-manifest/test-key.ed25519.pub
printf '\n' >> tests/ota/fixtures/signed-manifest/test-key.ed25519.pub
rm /tmp/fixture-key.pem
```

Özel anahtar bilinçli olarak commit EDİLMEZ (gitleaks + hijyen); fixture'ın
doğrulanması için yalnız public key gerekir.
