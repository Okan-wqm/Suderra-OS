# suderra-telemetry

Cihaz sağlık ve uygulama metriklerini cloud'a push eden daemon.

## Metrikler

**System:**

- CPU %, load average
- RAM (total/free/cached)
- Disk (per mount: total/free, I/O wait)
- Sıcaklık (hwmon sensor)
- Uptime, boot reason
- Network rx/tx, interface state

**Edge Agent (Modbus/OPC-UA proxy):**

- Modbus read rate per slave
- MQTT publish success/failure
- Error count, last error timestamp
- Backlog (offline queue size)

**OS:**

- Boot partition (rootfs.A / rootfs.B)
- RAUC durumu (last update, slot state)
- systemd unit failures
- Kernel taint flags

## Push Stratejisi

- JSON structured (her 60s batch)
- mTLS HTTPS endpoint (`SuderraConfig.telemetry_endpoint`)
- Offline fallback: SQLite ring buffer (~7 gün)
- Network down: store-and-forward, max disk 50MB

## Faz

Faz 5 (operasyonel olgunluk) ile birlikte tam implementasyon.
