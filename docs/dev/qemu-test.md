# QEMU'da Test

> **Status:** Skeleton.

## Hızlı Test

```bash
make build-qemu
./scripts/qemu-run.sh
```

## QEMU Komutu (manuel)

```bash
qemu-system-x86_64 \
    -m 512M \
    -smp 2 \
    -drive file=output/suderra_qemu_x86_64_defconfig/images/disk.img,format=raw,if=virtio \
    -nographic \
    -serial mon:stdio \
    -netdev user,id=net0,hostfwd=tcp::5555-:8080 \
    -device virtio-net-pci,netdev=net0 \
    -enable-kvm
```

## QEMU İçinde

```bash
# Boot tamamlandığında:
suderra login: root
Password: suderra      # DEV variant default

# Servis durumu
systemctl status

# Edge agent
journalctl -u suderra-edge-agent -f
```

## TPM Emulation

```bash
# swtpm ile TPM 2.0 emulation
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state \
    --ctrl type=unixio,path=/tmp/swtpm-sock &

qemu-system-x86_64 \
    -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    ...
```

## UEFI Boot

```bash
qemu-system-x86_64 \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    ...
```

## CI Headless Test

```bash
# tests/qemu/boot-test.sh
#!/bin/bash
# QEMU başlat (timeout 60s), boot logunu yakala
# Beklenen string: "Suderra OS v"
# Beklenen exit code: 0
```

## Sorun Giderme

- **QEMU çok yavaş:** `-enable-kvm` veya nested virt
- **Network yok:** `-netdev user` ve `hostfwd` ekle
- **Display görünmüyor:** `-nographic -serial mon:stdio`

## Yapılacaklar

- [ ] `scripts/qemu-run.sh` ARM versiyonu (qemu-system-aarch64)
- [ ] swtpm wrapper script
- [ ] Otomatik test framework (expect/pexpect)
