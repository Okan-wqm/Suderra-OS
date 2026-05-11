# suderra-config

Suderra OS userspace için ortak konfigürasyon kütüphanesi.

## Amaç

Diğer userspace crate'leri (firstboot, ota, telemetry, watchdog, vb.) aynı
config dosyasını okur. Bu lib crate kod tekrarını ve tutarsızlığı önler.

## Faz

Faz 2 (Edge Agent paketleme) ile birlikte ilk gerçek implementasyon.
Şu an: tip iskeletleri + validation.

## API

```rust
use suderra_config::SuderraConfig;

let cfg = SuderraConfig::load_from_file("/etc/suderra/config.yaml")?;
println!("Device: {}", cfg.device_id);
```

## Test

```bash
cargo t -p suderra-config   # host'ta unit testler
```

## Faz 2'de eklenecekler

- TLS cert paths (mTLS client cert + key + CA bundle)
- MQTT/HTTPS endpoint config
- Modbus/OPC-UA backend config (Edge Agent ile uyumlu)
- Watchdog timeout config
- Logging level
- Feature flags (telemetry, attestation, vb.)
