# Raspberry Pi 4 / Compute Module 4 — Hardware Rehberi

> **Konu:** Suderra OS için Pi 4 / CM4 hardware seçimi, BOM, GPIO pin haritası,
> endüstriyel deployment notları.

## 1. Hangi Variant?

### 1.1. Pi 4 Model B vs CM4

| Özellik | Pi 4 Model B | Compute Module 4 |
|---|---|---|
| **Kullanım** | Prototyping, dev | Endüstriyel deployment |
| **Form factor** | Standalone board | SO-DIMM benzeri, carrier board gerekir |
| **Storage** | SD card sadece | SD + opsiyonel eMMC (8/16/32 GB) |
| **RAM** | 1/2/4/8 GB | 1/2/4/8 GB |
| **WiFi/BT** | Lehimli, kapatılabilir | Opsiyonel (non-W variant tercih) |
| **GPIO** | 40-pin header | Carrier board üzerinden |
| **Endüstriyel kabin** | Zor (USB/HDMI kabloları) | Kolay (carrier'a entegre) |
| **Üretim ömrü** | ~7 yıl (2027'ye kadar) | 10+ yıl (2031'e kadar) |
| **Fiyat (2026)** | ~$55 (4GB) | ~$80 (4GB Lite) |
| **Suderra önerisi** | Geliştirme + test | **Production** |

### 1.2. CM4 SKU seçimi

CM4 ismi: `CM4<RAM><STORAGE><WiFi>`

| SKU | RAM | eMMC | WiFi | Suderra önerisi |
|---|---|---|---|---|
| **CM4001000** | 1GB | yok (Lite) | yok | Min config |
| **CM4002032** | 2GB | 32GB | yok | **Endüstriyel default** ✅ |
| **CM4004032** | 4GB | 32GB | yok | Edge Agent + workload |
| **CM4108032** | 8GB | 32GB | var | Heavy ML / video |

**Endüstriyel için kural:**
- ❌ WiFi'lı variant — saldırı yüzeyi + EMI sorunları
- ✅ eMMC'li variant — SD card'tan 5-10x güvenilir
- ✅ Min 2GB RAM (Edge Agent + systemd + headroom)

### 1.3. Carrier Board

**Resmi CM4 IO Board:**
- Geliştirme için ideal
- Tüm CM4 sinyalleri açık
- USB-C güç, mini HDMI x2, USB-A x2, eth, microSD slot
- ~$35

**Endüstriyel carrier'lar:**
- **Revolution Pi Connect 4** — DIN rail, klemensler, RS-485
- **Waveshare CM4-IO-BASE-B** — minimal industrial
- **EDATEC CM4 Nano** — fanless mini-PC kabin
- **Custom carrier** — büyük projeler için

Suderra OS treats **Pi 4 / CM4** and **RevPi Connect 4** as separate Buildroot
targets:

- `suderra_aarch64_rpi4_defconfig`
- `suderra_aarch64_rpi4_usb_installer_defconfig`
- `suderra_aarch64_revpi4_defconfig`

Custom carrier'lar device tree overlay gerektirir (Faz 2-B).

## 2. Bill of Materials (BOM)

Minimum endüstriyel kurulum (örnek aquaculture sensör node):

| Parça | Model | Adet | Birim Fiyat | Toplam |
|---|---|---|---|---|
| CM4 module | CM4002032 (2GB+32GB eMMC) | 1 | $55 | $55 |
| Carrier | RevPi Connect 4 veya Waveshare | 1 | $60-300 | $60-300 |
| Güç | 5V/3A regülatörlü, DIN rail | 1 | $25 | $25 |
| Kabin | IP54+ polikarbonat | 1 | $40 | $40 |
| Heatsink | Aluminyum, termal pad | 1 | $5 | $5 |
| Ethernet kablo | Cat6, M12 connector (endüstriyel) | 1 | $15 | $15 |
| Sensör (örnek) | DS18B20 + BME280 + ADS1115 | - | - | $20 |
| **TOPLAM (minimal)** | | | | **~$220** |
| **TOPLAM (RevPi)** | | | | **~$460** |

## 3. GPIO Pin Haritası

CM4 üzerinde Pi 4 ile aynı 40-pin GPIO. Carrier board pin layout'unu kontrol et.

### 3.1. Genel pin tablosu

```
        +5V  - 1   2 - +5V
       GPIO2 - 3   4 - +5V    (I2C SDA1)
       GPIO3 - 5   6 - GND    (I2C SCL1)
       GPIO4 - 7   8 - GPIO14 (UART0 TX) ← Seri konsol
        GND  - 9  10 - GPIO15 (UART0 RX) ← Seri konsol
      GPIO17 -11  12 - GPIO18 (PCM CLK)
      GPIO27 -13  14 - GND
      GPIO22 -15  16 - GPIO23
       +3.3V -17  18 - GPIO24
      GPIO10 -19  20 - GND    (SPI MOSI)
       GPIO9 -21  22 - GPIO25 (SPI MISO)
      GPIO11 -23  24 - GPIO8  (SPI SCLK / CE0)
        GND  -25  26 - GPIO7  (SPI CE1)
       GPIO0 -27  28 - GPIO1  (ID EEPROM — DOKUNMA)
       GPIO5 -29  30 - GND
       GPIO6 -31  32 - GPIO12 (PWM0)
      GPIO13 -33  34 - GND    (PWM1)
      GPIO19 -35  36 - GPIO16
      GPIO26 -37  38 - GPIO20
        GND  -39  40 - GPIO21
```

### 3.2. Suderra OS'ta aktif edilenler

**Default kernel config'de aktif:**
- I2C1 (GPIO2/3) — sensör bus
- SPI0 (GPIO7-11) — high-speed sensör/ADC
- UART0 (GPIO14/15) — seri konsol (debug için ŞART)
- 1-Wire (GPIO4) — DS18B20 sıcaklık sensörü
- PWM (GPIO12/13) — fan/valve kontrolü

**Edge Agent için ayrılan:**
- GPIO 17, 22, 23, 24, 25 — Generic GPIO (alarm, röle, indicator LED)
- GPIO 5, 6, 26, 27 — Edge Agent customizable

### 3.3. CM4 IO Board ekstraları

CM4 IO Board'da ek olarak:
- microSD slot
- USB 2.0 host x2 (PCIe yok, USB 3.0 disabled)
- Ethernet (BCM54213PE PHY)
- HDMI x2
- DSI / CSI
- Fan header (PWM kontrol)
- PCIe x1 (Faz 4'te M.2 NVMe testi)
- RTC battery holder (DS3231)

## 4. Boot Zinciri

```
   [Pi Power-On]
       ↓
   [ROM bootloader]  ← Read-only, Broadcom-signed
       ↓
   [SPI EEPROM]      ← bootcode.bin yüklenir (CM4'te SPI flash'tan)
       ↓
   [start4.elf]      ← /boot vfat partition'dan
       ↓
   [config.txt]      ← Suderra OS configuration
       ↓
   [DTB seçimi]      ← Otomatik (board rev EEPROM'dan)
       ↓
   [kernel Image]    ← Linux 6.12 LTS yüklenir
       ↓
   [cmdline.txt]     ← Kernel command line
       ↓
   [Linux kernel]    ← BCM2711 driver'lar
       ↓
   [systemd]         ← PID 1
       ↓
   [firstboot]       ← temporary forced-command provision user
       ↓
   [Edge Agent]      ← tenant manifest ile indirildiğinde çalışır
```

**Önemli:** Suderra OS U-Boot kullanmaz — Pi firmware doğrudan Linux yükler. Faz 4'te RAUC A/B slot için U-Boot eklenir.

## 5. Endüstriyel Notlar

### 5.1. Güç Stabilizasyonu

Pi 4 / CM4 endüstriyel ortamda (12V / 24V kabin DC) ek regülatör gerektirir:

- **5V/3A buck converter** — kabin DC'yi 5V'a indir
- **Input filter** — EMI bastırma
- **Crowbar circuit** — overvoltage koruma
- **TVS diode** — surge protection

Önerilen modüller: Recom RPM-2.5A, Traco TSR1-2450.

### 5.2. Sıcaklık Yönetimi

- BCM2711 ısınır — pasif heatsink **şart**
- 70°C üstü throttling, 85°C shutdown
- Kabin içi ortam sıcaklığı 50°C'ye kadar → uygun heatsink + fan
- Industrial-grade SD/eMMC kullan (`-40 to +85°C`)

### 5.3. SD Card vs eMMC

| | SD Card | CM4 eMMC |
|---|---|---|
| Yazma döngüsü | ~10K | ~30K |
| Veri retention | 1 yıl (yazmadan) | 10 yıl |
| Hız | A1/A2 etiketli (~30 MB/s) | ~100 MB/s |
| Boyut | 8-256 GB | 8/16/32 GB |
| Endüstriyel grade | Var (~$30-60) | Standart dahil |
| Suderra önerisi | Dev / pilot | **Production** ✅ |

**SD kullanılacaksa:** SLC veya pSLC mode (industrial-grade), `noatime` mount option ŞART.

### 5.4. Watchdog

BCM2835 hardware watchdog otomatik aktif:
- 15 saniye timeout
- systemd `WatchdogSec=10` ile besle
- Hang durumunda hardware reset

Kontrol:
```bash
systemctl show suderra-edge-agent | grep -i watchdog
journalctl -k | grep watchdog
```

### 5.5. RTC

CM4 IO Board'da DS3231 var, custom carrier'da yok. RTC olmadan:
- Boot sonrası saat 1970'ten başlar
- NTP sync gerekli (chrony default aktif)
- TLS sertifika doğrulaması fail edebilir

Çözüm:
- DS3231 modülü I2C bus'a ekle
- DTB'de `dtoverlay=i2c-rtc,ds3231` ekle (config.txt)
- Pil ile saat korunur (CR2032)

## 6. Gelişmiş Konular

### 6.1. eMMC'ye Bootloader Yazma (CM4)

CM4 SD card slot'u carrier board'a bağlıdır. eMMC'li CM4'te SD slot'u eMMC için bypass edilir.

```bash
# Pi 4'te USB OTG ile CM4'ün eMMC'sine yaz:
sudo apt install -y rpiboot
git clone https://github.com/raspberrypi/usbboot
cd usbboot/recovery
make
sudo ./rpiboot
# CM4 USB OTG ile bilgisayara bağlanır, eMMC /dev/sdX olarak görünür
sudo ./scripts/flash-sd.sh /dev/sdX output/.../suderra-rpi4-target.img.xz
```

### 6.2. PXE Network Boot

Faz 4+'da: CM4 SPI EEPROM'una network boot bootloader'ı yaz, eMMC/SD olmadan boot.

### 6.3. Custom Carrier Board

CM4 sinyalleri için Schmitt trigger'lar + ESD protection + DTB overlay:

```bash
# Pi DTB overlay derleme:
dtc -@ -I dts -O dtb -o custom-carrier.dtbo custom-carrier.dts

# Suderra OS'a entegre:
# 1. board/suderra/aarch64-rpi4/overlays/ altına .dtbo koy
# 2. config.txt'e ekle: dtoverlay=custom-carrier
```

## 7. Test Edilmiş Konfigürasyonlar

| # | Hardware | Test | Notlar |
|---|---|---|---|
| 1 | Pi 4 Model B 4GB + 32GB Samsung A2 SD | ✅ Boot | Faz 2-A doğrulandı |
| 2 | CM4002032 + CM4 IO Board | ⏳ Beklemede | Faz 2-A test sırasında |
| 3 | CM4002032 + Waveshare CM4-IO-BASE-B | ⏳ Beklemede | DTB overlay olmadan |
| 4 | CM4002032 + Revolution Pi Connect 4 | ❌ Faz 2-B | RevPi-spesifik defconfig gerekli |

## 8. Referanslar

- Raspberry Pi 4 Compute Module datasheet: https://datasheets.raspberrypi.com/cm4/cm4-datasheet.pdf
- BCM2711 ARM Peripherals: https://datasheets.raspberrypi.com/bcm2711/bcm2711-peripherals.pdf
- config.txt reference: https://www.raspberrypi.com/documentation/computers/config_txt.html
- Device tree overlays: https://github.com/raspberrypi/firmware/tree/master/boot/overlays
