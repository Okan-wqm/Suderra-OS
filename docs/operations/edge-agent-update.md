# Edge Agent Install And Update Runbook

Suderra OS saha akışı üç aşamalıdır:

1. **OS install:** Raspberry Pi için SD karta Suderra OS yazılır; Edge agent
   image içine gömülmez.
2. **Provisioning mode:** OS boot eder, IP üzerinden geçici `provision` SSH
   user'ı açılır. Bu user forced command çalıştırır; genel shell yoktur.
3. **Appliance mode:** `suderra-agent` kurulunca SSH/login/getty/debug shell kapanır
   ve cihaz sadece zorunlu sistem servisleri + Suderra Edge çalıştırır.

Firstboot console'da tek kullanımlık provisioning parolasını yazar:

```text
user: provision
pass: <firstboot-generated one-time password>
```

Tenant paneli bu kullanıcıyla `install-manifest-url` veya `install-manifest-json`
forced command'ını çalıştırır. `suderra-lockdown` root/provision password
login'i, dropbear/SSH'yi ve provisioning firewall kuralını kapatır.

## Runtime Install

Agent artifact, OS içine gömülmez.
`/opt/suderra/edge/releases/<version>/suderra-agent` altına root-owned kurulur;
`/opt/suderra/edge/current` symlink'i aktif sürümü gösterir.
Mutable config `/var/lib/suderra/config/config.yaml` altındadır.

Önceden yapılandırılmış kurulum için:

```bash
vi /etc/suderra/edge-install.env
```

```sh
SUDERRA_EDGE_VERSION="1.6.0"
SUDERRA_EDGE_URL="https://releases.example.com/suderra-agent-x86_64.tar.gz"
SUDERRA_EDGE_SHA256="<artifact sha256>"
SUDERRA_EDGE_SIGNATURE_URL="https://releases.example.com/suderra-agent-x86_64.tar.gz.sig"
SUDERRA_EDGE_ARTIFACT_FORMAT="tar.gz"
SUDERRA_EDGE_BINARY_NAME="suderra-agent"
SUDERRA_LOCKDOWN_AFTER_INSTALL="1"
```

Sonra:

```bash
/usr/sbin/suderra-edge-install
```

Production flow doğrudan bu dosyayı elle düzenlemez; tenant panelinden gelen
Suderra OS manifest URL'i kullanılır:

```bash
ssh provision@DEVICE install-manifest-url https://tenant.example/install/suderra-os/<token>.json
```

## Artifact Kuralları

- Artifact `tar.gz` içinde `suderra-agent` binary'si taşımalı ya da
  `SUDERRA_EDGE_ARTIFACT_FORMAT=raw` ile direkt binary olmalı.
- SHA256 zorunlu. Hash olmadan kurulum yapılmaz.
- İleride SHA256 tek başına yeterli kabul edilmeyecek; release imzası veya
  cosign/minisign doğrulaması üretim kapısıdır.
- `SUDERRA_LOCKDOWN_AFTER_INSTALL=1` default üretim davranışıdır. Lab'da geçici
  debug gerekirse `0` yapılabilir; saha imajında kapalı bırakılmaz.

## OS Tarafında Değişmesi Gereken Durumlar

Agent güncellemesi aşağıdakilerden birini değiştirirse OS tarafını da güncelle:

| Agent değişikliği | OS dosyası |
|---|---|
| Binary adı değişti | `/etc/suderra/edge-install.env`, `SUDERRA_EDGE_BINARY_NAME` |
| Runtime path değişti | `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service` |
| Config schema değişti | `package/suderra-edge-agent/config.yaml`, `suderra-firstboot.service` |
| Yeni cihaz dosyası gerekiyor | `suderra-agent.service` içindeki `DeviceAllow=` |
| Yeni Linux capability gerekiyor | `CapabilityBoundingSet=` ve `AmbientCapabilities=` |
| Yeni writable path gerekiyor | `ReadWritePaths=` ve firstboot dizin hazırlığı |
| Yeni outbound port gerekiyor | `board/suderra/common/rootfs-overlay/etc/nftables.conf` |
| Yeni Rust minimum sürümü gerekiyor | Edge release pipeline toolchain'i ve opsiyonel embedded Buildroot paketi |

## Opsiyonel Embedded Build

`package/suderra-edge-agent` paketi repo içinde tutulur ama default defconfig'lerde
kapalıdır. Buildroot `2025.05.3` cargo vendor arşiv formatı `cargo4` olduğu için
paket, cargo4 hash yeniden üretilene kadar Kconfig gate arkasında tutulur.
QEMU/lab için agent'ı OS image içine gömmek gerekirse önce
`BR2_PACKAGE_SUDERRA_EDGE_AGENT_CARGO4_HASH_REVALIDATED` gate'i bilinçli olarak
açılır ve hash yenilenir:

```make
BR2_PACKAGE_SUDERRA_EDGE_AGENT_CARGO4_HASH_REVALIDATED=y
BR2_PACKAGE_SUDERRA_EDGE_AGENT=y
```

Bu modda commit SHA ve Cargo vendor hash güncellenir:

```make
SUDERRA_EDGE_AGENT_VERSION = <aquaculture_platform commit sha>
```

```bash
buildroot_source_dir="$(/var/suderra-os/Suderra-OS/scripts/buildroot-source.sh prepare --defconfig suderra-agent-sourcecheck)"
make -C "${buildroot_source_dir}" BR2_EXTERNAL=/var/suderra-os/Suderra-OS \
  O=/tmp/suderra-agent-sourcecheck suderra_qemu_x86_64_defconfig
make -C "${buildroot_source_dir}" BR2_EXTERNAL=/var/suderra-os/Suderra-OS \
  O=/tmp/suderra-agent-sourcecheck suderra-edge-agent-source
sha256sum "${buildroot_source_dir}/dl/suderra-edge-agent/suderra-edge-agent-<sha>-cargo4.tar.gz"
```

Hash sonucu `package/suderra-edge-agent/suderra-edge-agent.hash` dosyasına yazılır.

## Lockdown Doğrulama

Kurulum ve reboot sonrası local console'da login prompt görünmemeli. Servis
durumu ve kilit yüzeyi seri konsol veya debug imajında şu komutla doğrulanır:

```bash
/usr/sbin/suderra-lockdown-status
```

Komut root password lock, masked getty/debug/remote shell unit'leri, agent
binary'si ve `suderra-agent.service` enable durumunu kontrol eder.
