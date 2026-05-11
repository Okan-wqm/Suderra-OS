# suderra-firstboot

İlk boot provisioning. Cihaz fabrikadan çıktıktan sonra ilk açılışta çalışır.

## Lifecycle

```ini
# /etc/systemd/system/suderra-firstboot.service
[Unit]
Description=Suderra OS first boot provisioning
ConditionPathExists=!/var/lib/suderra/.provisioned
Before=suderra-edge-agent.service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/suderra-firstboot
RemainAfterExit=yes
Restart=on-failure
RestartSec=10
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
```

## Yapacakları

1. **/data partition init**: LUKS2 ile şifreli volume oluştur (TPM-sealed key)
2. **machine-id generate**: `/etc/machine-id` boşsa systemd-machine-id-setup
3. **Cloud enroll**: Mfg bootstrap cert ile cloud'a kayıt → device cert al
4. **TPM seal**: Master key'i TPM PCR'lara seal et
5. **Mark provisioned**: `/var/lib/suderra/.provisioned` dokunma flag'i

## Faz

Faz 2 (Edge Agent paketleme) ile birlikte ilk gerçek implementasyon.
