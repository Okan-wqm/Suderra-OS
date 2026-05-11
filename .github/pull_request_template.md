<!--
Pull Request Template — Suderra OS

Lütfen aşağıdaki alanları doldur. PR title'ı Conventional Commits formatında olsun:
  feat(scope): kısa açıklama
  fix(scope): ...
  security(scope): ...
-->

## Özet

<!-- Bu PR ne yapıyor? Tek paragraf. -->

## Motivasyon

<!-- Neden bu değişiklik? Hangi issue'yu kapatıyor? Closes #XXX -->

## Değişiklik Türü

- [ ] Bug fix (mevcut davranışı düzeltir, geriye uyumlu)
- [ ] Yeni özellik (mevcut davranışı kırmaz)
- [ ] Breaking change (mevcut davranışı kırar — major version bump)
- [ ] Security fix (CVE referansı gövdede)
- [ ] Dokümantasyon
- [ ] Refactor (davranış değişmez)
- [ ] CI/CD / build sistem
- [ ] Yeni paket / paket güncelleme

## Mimari Etki

- [ ] ADR yazıldı (mimari değişiklik için)
- [ ] Threat model güncellendi (güvenlik etkisi varsa)
- [ ] Tehlikeli/destruktif değişiklik (data migration, partition layout, anahtar rotation)

## Test

- [ ] Yerel build geçiyor: `make build-qemu`
- [ ] QEMU smoke test geçti: `./tests/qemu/boot-test.sh`
- [ ] Yeni testler eklendi (varsa)
- [ ] Mevcut testler hala geçiyor
- [ ] Manuel test edildi (donanım üzerinde, eğer ilgili ise)

## Güvenlik

- [ ] `cargo audit` / `trivy` temiz (varsa)
- [ ] Yeni bağımlılıkların lisans/hash kontrolü yapıldı
- [ ] CVE referansı içeriyor (security fix ise)

## Dokümantasyon

- [ ] README güncellendi (kullanıcı görür değişiklik için)
- [ ] CHANGELOG.md altında [Unreleased] başlığına eklendi
- [ ] İlgili docs/*.md dosyaları güncellendi

## DCO

- [ ] Tüm commit'ler `Signed-off-by:` içeriyor (DCO)

## Ek Notlar

<!-- Reviewer'a not, ekran görüntüsü, vs. -->
