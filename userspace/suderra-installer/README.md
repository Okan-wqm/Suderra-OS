# suderra-installer

> **Ubuntu apt-like UX** for Suderra OS package management. Edge Agent ve plugin'ler
> bu binary ile indirilir, doğrulanır ve kurulur. OS minimal kalır, Edge ayrı release.

## Vizyon

Suderra OS sabit bir base sağlar. Edge Agent + plugin'ler ayrı release artifact'leri
olarak GitHub Releases'a yüklenir. Cihaz boot ettikten sonra:

```bash
sudo suderra-installer install edge --version 1.6.0
# ✓ Manifest doğrulandı
# ✓ Bundle indirildi (SHA256 verify)
# ✓ Cosign signature doğrulandı (Sigstore keyless, GitHub OIDC)
# ✓ /opt/suderra/edge/ kuruldu
# ✓ systemd unit etkin
# ✓ Audit log: /var/log/suderra/installer.log
```

## Komutlar

| Komut | Açıklama |
|---|---|
| `install <pkg>` | Paket kur (latest veya `--version`) |
| `upgrade <pkg>` | En son sürüme yükselt |
| `rollback <pkg>` | Önceki sürüme dön (veya `--to-version`) |
| `list [<pkg>]` | Kurulu paketler (veya `--available` ile remote) |
| `status [<pkg>]` | Detaylı paket durumu |
| `remove <pkg>` | Paketi kaldır (`--purge` ile config dahil) |

## Mirror Stratejisi

```bash
# GitHub primary (default)
suderra-installer install edge

# Suderra mirror (releases.suderra.com)
suderra-installer install edge --mirror suderra

# Auto: GitHub başarısızsa Suderra fallback
suderra-installer install edge --mirror auto
```

## Güvenlik

1. **HTTPS only** — TLS 1.2+ (rustls, OpenSSL yok)
2. **SHA256 verify** — manifest'teki hash zorunlu eşleşmeli
3. **Cosign keyless** — Sigstore + GitHub Actions OIDC ile signature doğrulama
4. **Audit log** — `/var/log/suderra/installer.log` (JSON Lines, SIEM uyumlu)
5. **State integrity** — `/var/lib/suderra/installed.json` (root-only write)

## Air-gapped Kurulum

Internet bağlantısı olmayan saha cihazı:

```bash
# Başka makinede indir:
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.6.0/suderra-edge-v1.6.0-aarch64.raucb
wget https://github.com/Okan-wqm/suderra-os/releases/download/v1.6.0/suderra-edge-v1.6.0-aarch64.raucb.sig

# USB ile cihaza transfer, sonra:
sudo suderra-installer install edge \
  --from-file suderra-edge-v1.6.0-aarch64.raucb \
  --signature suderra-edge-v1.6.0-aarch64.raucb.sig
```

## Çalışma Akışı

```
┌──────────────────────────────────────────────────────────┐
│  suderra-installer install edge                          │
└──────────────────────────────────────────────────────────┘
              │
              ↓
┌──────────────────────────────────────────────────────────┐
│  1. Manifest indir                                        │
│     https://github.com/.../releases/.../v1.6.0/           │
│       manifest.json                                       │
│     → versiyon + file + sha256 + arch                     │
└──────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────┐
│  2. Bundle indir (progress bar)                          │
│     suderra-edge-v1.6.0-aarch64.raucb                     │
│     → SHA256 streaming verify                             │
└──────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────┐
│  3. Signature indir + cosign verify                       │
│     suderra-edge-v1.6.0-aarch64.raucb.sig                 │
│     → certificate-identity-regexp = github.com/Okan-wqm/  │
└──────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────┐
│  4. RAUC install (Faz 4'te aktif)                        │
│     rauc install suderra-edge-v1.6.0-aarch64.raucb        │
│     → A/B slot switch + integrity check                   │
│     [Faz 2-D MVP: /opt/suderra/<pkg>/ direkt kopya]        │
└──────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────┐
│  5. systemd unit enable + start                          │
│     systemctl enable suderra-edge-agent.service           │
│     systemctl start suderra-edge-agent.service            │
└──────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────┐
│  6. State + audit                                         │
│     /var/lib/suderra/installed.json güncellendi           │
│     /var/log/suderra/installer.log'a event yazıldı        │
└──────────────────────────────────────────────────────────┘
```

## Faz İlerlemesi

| Faz | Özellik | Durum |
|---|---|---|
| 2-D MVP | CLI + download + sha256 + cosign verify + state + audit | ✅ Bu PR |
| 2-D | RAUC integration | ⏳ Stub (Faz 4) |
| 2-D+ | systemd-via-dbus (subprocess yerine) | ⏳ |
| 3 | sigstore-rs native (subprocess'e gerek yok) | ⏳ |
| 4 | A/B slot switch + rollback otomatik | ⏳ |
| 5 | SBOM verify (CycloneDX in-process) | ⏳ |

## Geliştirici Notları

### Test

```bash
cd userspace
cargo test -p suderra-installer
cargo clippy -p suderra-installer
```

### Cross-compile (aarch64 musl)

```bash
# Workspace root'tan:
cargo build -p suderra-installer --target aarch64-unknown-linux-musl --release
ls -lh target/aarch64-unknown-linux-musl/release/suderra-installer
# Beklenen: ~3-5 MB statik binary
```

### Env Override (debug için)

| Env var | Açıklama |
|---|---|
| `SUDERRA_AUDIT_LOG` | Audit log dosyası override (test) |
| `SUDERRA_STATE_PATH` | installed.json yol override (test) |
| `SUDERRA_INSECURE=1` | TLS doğrulamasını kapat (sadece dev) |
| `SUDERRA_TARGET_ARCH` | Mimari override (cross-compile için) |
| `COSIGN_BINARY` | cosign binary path override |
| `RUST_LOG=debug` | Verbose log |
