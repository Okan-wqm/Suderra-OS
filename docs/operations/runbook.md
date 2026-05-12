# Saha Operasyon Runbook

> **Status:** Skeleton — Faz 7 (pilot saha) için detaylanacak.

Bu doküman saha personeline yöneliktir. Teknik detay değil, **adım adım eylem** içerir.

## Acil Durum Telefon Hattı

- **Suderra OS support:** +90-XXX-XXX-XXXX (24/7)
- **Eskalasyon:** <support@suderra.example>

## Yaygın Senaryolar

### S1: Cihaz veri göndermiyor

**Belirti:** Dashboard'da cihaz "offline" 5+ dk.

**Çözüm adımları:**

1. Cihazda LED durumu kontrol et:
   - Yeşil → çalışıyor, network problemi olabilir
   - Sarı → boot devam ediyor, 2 dk bekle
   - Kırmızı → hata, devam et
2. Ağ kablosu fiziksel kontrol
3. Switch port LED
4. Cihaz güç durumu (PSU LED)
5. Hala sorun → support'a bildirim aç (cihaz seri no + zaman damgası)

### S2: Cihaz boot etmiyor

**Belirti:** Power LED yanıyor ama ağ aktivitesi yok 5 dk+.

**Çözüm:**

1. **YAPMA:** Cihaza müdahale etme, açma
2. Güç kapat (30 sn bekle) → tekrar aç
3. Hala boot etmiyor → support, cihazı yerinde bırak

### S3: Sensör değeri saçma

**Belirti:** Su sıcaklığı -100 derece, vs.

**Çözüm:**

1. Fiziksel sensör kontrol (kablo, korozyon, biyolojik kirlilik)
2. Modbus terminator?
3. Hala sorun → support'a sensör tipi + cihaz seri no

### S4: Update sonrası garip davranış

**Belirti:** Yeni update sonrası anomali.

**Çözüm:**

1. Cihaz 5 dk içinde otomatik rollback yapmadıysa support'a haber ver
2. Dashboard'dan "rollback" komutu (yetkili kullanıcı)
3. Manuel: cihazı reboot et (3× — otomatik rollback tetiklenir)

## Saha Personeli Yetkileri

| Eylem | Yetki |
|---|---|
| Cihazı görsel inceleme | Operatör |
| Ağ kablosu kontrol/değiştirme | Operatör |
| Güç kapatma/açma | Operatör |
| Cihaz fiziksel taşıma | Saha mühendisi |
| Cihaz açma/donanım müdahale | YALNIZCA Suderra teknisyeni |
| Update tetikleme | Cloud admin |
| Factory reset | Cloud admin + müşteri onayı |

## Veri ve Gizlilik

- Cihazda biriken veri /data partition'da şifreli
- Sensör verisi sadece müşteriye gider (mTLS)
- Cihaz çalınırsa: /data anahtar TPM-sealed → veri kullanılamaz

## Yapılacaklar (Faz 7)

- [ ] Detaylı LED durum kodu tablosu
- [ ] Müşteri operatör eğitim materyali
- [ ] Olay yönetimi süreci
- [ ] SLA matrisi (response time)
- [ ] On-call rotation
