# USB Installer Alpha Validation

This runbook validates the Pi/CM4/RevPi USB installer as an alpha/lab artifact.
It does not approve production use.

## Inputs

- Git commit and GitHub Actions build run ID.
- Artifact: `suderra-pi-cm4-revpi-usb-installer.img.xz`.
- Evidence root: `release-evidence/<version>/`.
- Flash host with `gh`, `xz`, `sha256sum`, `lsblk`, `udevadm`, and serial tooling.

Download the CI artifact from the exact green run:

```bash
gh run download <run-id> \
  --repo Okan-wqm/Suderra-OS \
  --name suderra_aarch64_rpi4_usb_installer_defconfig-image \
  --dir release-evidence/<version>/artifacts/usb-installer
```

Validate before flashing:

```bash
xz -t suderra-pi-cm4-revpi-usb-installer.img.xz
sha256sum suderra-pi-cm4-revpi-usb-installer.img.xz
cat MANIFEST.txt
```

## Flash Station

Record host state before writing:

```bash
lsblk -o NAME,SIZE,MODEL,TRAN,RM,SERIAL,MOUNTPOINTS
udevadm info --query=property --name=/dev/sdX
dmesg --ctime | tail -200
```

Flash with the fail-closed wrapper:

```bash
script -f release-evidence/<version>/flash/usb-flash-session.typescript
sudo ./scripts/flash-sd.sh /dev/sdX \
  release-evidence/<version>/artifacts/usb-installer/suderra-pi-cm4-revpi-usb-installer.img.xz
```

Do not use `--skip-verify`. Use `--force` only for a recorded lab exception.
Use `--lab-allow-missing-hash` only for a non-release lab image with an explicit
residual-risk entry.

## Hardware Matrix

Minimum alpha acceptance:

| Evidence board ID | Required path |
|---|---|
| `raspberry-pi-4-model-b` | USB installer boot and target-media boot |
| `cm4-lite-sd` | SD target install |
| `cm4-emmc-io-board` | `rpiboot` direct flash and boot |
| `revpi-connect-4` | USB boot only with boot-order evidence; otherwise `rpiboot` fallback |

Each board evidence bundle must include board model string, serial log, payload
verification output, target selection output, flash transcript, post-install
boot log, partition/mount output, failed-unit output, network/firewall output,
and board-specific IO checks.

If `/proc/device-tree/model` reports a generic `Raspberry Pi Compute Module 4`
string, the installer must fail closed unless `/proc/device-tree/compatible`
contains a RevPi-specific compatible string or the operator sets
`SUDERRA_INSTALLER_TARGET_BOARD=rpi4-cm4` or `revpi4` with recorded board
identity evidence.

## Acceptance Commands

Run after booting from the installed target:

```bash
cat /etc/os-release
tr -d '\0' </proc/device-tree/model
uname -a
lsblk -f
blkid
findmnt -R /
systemctl --failed --no-pager
journalctl -b --no-pager
ip addr
ip route
ss -lntup
nft list ruleset
timedatectl
dmesg
```

Pass criteria: target disk boots, root identity matches the written `PARTUUID`,
payload verification passed before writing, no unexpected failed units remain,
network works, and no unexpected listening services are present.

## Negative Tests

- No valid target disk: installer must fail closed.
- Multiple equally preferred targets: installer must refuse to choose.
- USB target without explicit by-id/removable override: installer must refuse.
- Tampered payload image, manifest, or signature: payload verify must fail.
- Wrong board, wrong arch, expired manifest, low key epoch, or rollback-floor
  violation: payload verify must fail.
- Target below minimum storage: installer must fail before writing.
