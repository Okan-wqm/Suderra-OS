# Factory Reset

> **Status:** Skeleton — Faz 5'te detaylanır.

## Factory Reset Nedir?

- /data partition silinir (kullanıcı state, config, queue, retain.db)
- TPM-sealed anahtarlar yeniden generate edilir
- Cihaz "first boot" durumuna döner
- Rootfs (A ve B) korunur (OS sürümü değişmez)

## Tetikleme Yolları

| Yol | Erişim | Senaryo |
|---|---|---|
| **Fiziksel buton** (3 sn basılı) | Sahada operatör | RMA öncesi, yeniden devreye alma |
| **Cloud komut** (mTLS) | Yetkili uzaktan | Pilotta deneme, müşteri talebi |
| **Bootloader menü** (serial, dev) | Lab | Geliştirme |

## Prosedür

```
1. Trigger algılanır
   ↓
2. systemctl stop suderra-edge-agent
   ↓
3. /data unmount
   ↓
4. cryptsetup luksFormat /dev/<data-partition>
   (eski anahtar destroyed, yeni TPM seal)
   ↓
5. mkfs.ext4 /dev/<data-partition>
   ↓
6. Boot flag: "first-boot"
   ↓
7. reboot
   ↓
8. suderra-firstboot.service çalışır
   - TPM yeni anahtar seal
   - Default config restore
   - Provisioning prompt (cloud'a ilk kayıt)
```

## Güvenlik

- Factory reset YALNIZ fiziksel erişimle veya mTLS authenticated cloud komutla
- Pure remote command yetmez (cihaz alındıysa veri silinemez tehdidi)
- Reset komutu audit log'a yazılır

## Yapılacaklar

- [ ] `suderra-factory-reset.service` implement (Faz 5)
- [ ] GPIO buton handler (board-specific)
- [ ] Cloud komut endpoint (Faz 5)
- [ ] Audit log
