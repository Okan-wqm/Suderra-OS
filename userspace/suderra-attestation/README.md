# suderra-attestation

TPM 2.0 PCR remote attestation. Cihaz boot state'ini cloud'a kriptografik
olarak kanıtlar.

## Neden

Saldırgan rootkit kursa bile, TPM PCR'lar boot zincirinin hash'lerini tutar.
PCR değerleri eşleşmiyorsa = cihaz manipüle edilmiş = cloud uyarır.

Kanıtlanan zincir:
```
UEFI firmware → bootloader → kernel → initrd → rootfs (dm-verity root hash)
```

Tüm bu adımlar TPM PCR'lara ölçülür (measured boot). suderra-attestation
PCR değerlerini TPM tarafından imzalı quote ile cloud'a gönderir.

## Faz

Faz 8+ (SL3 hazırlığı veya yüksek-güven müşteri).

SL2 hedefi için **zorunlu değil**. SL3'e geçişte aktive olur.

## Akış

```
1. Boot sırasında: kernel + bootloader PCR ölçüm yapar
2. Runtime: bu daemon tpm2_pcrread + tpm2_quote
3. Quote'u AIK private key ile imzala
4. Cloud'a gönder (mTLS endpoint)
5. Cloud: known-good golden value ile karşılaştır
6. Match → cihaz "trusted" durumda
7. Mismatch → cihaz quarantine + alert
```

## Bağımlılıklar

- TPM 2.0 chip (Infineon SLB9670 veya benzer)
- tpm2-tools (Buildroot package)
- tss-esapi Rust crate (Faz 8+ ekleniyor)
- Cloud-side attestation verifier (ayrı servis)
