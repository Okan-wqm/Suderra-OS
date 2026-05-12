# suderra-ota

RAUC OTA orchestrator. RAUC daemon'unu wrap eder ve Suderra-spesifik update
politikasını uygular.

## Sorumluluk

- Update server poll (HTTPS + mTLS endpoint)
- Bundle download (resumable, retry, bandwidth limit)
- İmza doğrulama (RAUC native + cosign attestation)
- RAUC install + reboot orchestration
- Boot sonrası health check (suderra-watchdog koordinasyonu)
- Başarısız update otomatik rollback (RAUC fallback)

## Faz

Faz 4 (OTA sistemi) ile birlikte tam implementasyon.

## RAUC ile İlişki

- `rauc` C binary'si: low-level bundle install/verify
- `suderra-ota` Rust: high-level policy (poll, download, health check, rollback decision)

CLI veya systemd timer:

```ini
[Unit]
Description=Suderra OTA check
[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
[Install]
WantedBy=timers.target
```
