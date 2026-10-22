# ADR-0007: ARM (Pi 4 / CM4 / RevPi) doğrulanmış boot + dm-verity + A/B zinciri

- **Status:** Proposed
- **Date:** 2026-07-02
- **Deciders:** @okan-wqm
- **Tags:** security, boot, verity, ota, hardware

## Context

x86 production hattı UEFI/UKI + dm-verity + RAUC mimarisine sahipken ARM
hattı (rpi4, revpi4, usb-installer) bugün düz, imzasız, tek-slot imaj sevk
ediyor. `ci/build-matrix.yml` bunu blocker alanlarıyla dürüstçe işaretliyor
(`signed-fit-dm-verity-rauc-and-hardware-evidence-missing`), README varyant
tablosu da aynı boşluğu gösteriyor.

ARM'da x86'daki zincir birebir kopyalanamaz:

- Pi 4/CM4/RevPi Connect 4'te UEFI Secure Boot yok; ilk aşama (GPU firmware
  → `bootcode`/EEPROM) **doğrulanamaz** ve Broadcom'a kapalıdır.
- BCM2711'de vendor imza zorlaması pratikte kullanılamaz; kök güven ancak
  U-Boot'tan itibaren kurulabilir.
- RevPi Connect 4'te SPI TPM 2.0 (SLB9670 serisi) var; Pi 4'te TPM yok.
- Kernel tarafı hazırlığı tamam: `linux-rpi4-hardening.config` DM_INIT,
  DM_VERITY(+FEC), DM_CRYPT ve TPM SPI sürücülerini içeriyor (Phase 2a).

Bu depoda ARM imajı **derlenip boot'lanarak doğrulanamaz**; yanlış partition
düzeni veya kernel/U-Boot kombinasyonu sahadaki cihazı brick edebilir. Bu
yüzden uygulama, aşağıdaki kanıt kapılarına bağlanır ve her adım GitHub
Actions'ta ya da donanım lab'ında kanıtlanmadan bir sonrakine geçilmez.

## Decision

**U-Boot'u güven kökü yaparak kısaltılmış zincir:**

```
GPU firmware + EEPROM  (DOĞRULANAMAZ — kabul edilen risk, aşağıda)
    ↓ yükler (FAT boot bölümü)
U-Boot (CONFIG_FIT_SIGNATURE=y, embedded RSA pubkey, env yazma kilitli)
    ↓ imza doğrular
Signed FIT = kernel + DTB + initramfs (+ bootargs: verity root hash)
    ↓ initramfs, dm-verity map eder
dm-verity rootfs (RO, squashfs/erofs) — slot A veya B
    ↓
systemd + RAUC (U-Boot boot-count/bootargs backend ile slot seçimi)
    ↓
/data: LUKS2 — RevPi'de TPM2-sealed anahtar, Pi 4'te dosya-tabanlı anahtar
        (daha zayıf; tabloda açıkça işaretlenir)
```

**Partition düzeni (MBR — Pi firmware FAT boot bölümü ister):**

| # | Bölüm | İçerik |
|---|---|---|
| 1 | `boot` (FAT32) | RPi firmware, U-Boot, config.txt; FIT imajları A/B |
| 2 | `rootfs-a` | dm-verity korumalı RO rootfs (slot A) |
| 3 | `rootfs-b` | slot B (ilk flash'ta boş, RAUC sahipliğinde) |
| 4 | `verity-a` / `verity-b` + `data` (extended) | Merkle ağaçları + LUKS2 /data |

**Kabul edilen risk:** İlk aşama (GPU firmware) imzasız kalır. Fiziksel
SD-swap saldırısına karşı tam koruma ancak vendor secure-boot olan
platformlarda mümkün; tehdit modelinde "ARM hattı: fiziksel erişimli
saldırgan boot zincirinin ilk aşamasını değiştirebilir" olarak kayda girer.
U-Boot sonrası her aşama kriptografik doğrulanır.

## Kanıt kapıları (gate'ler)

Her kapı geçilmeden `ci/build-matrix.yml` blocker'ı sökülmez ve bir sonraki
kapının işi başlamaz:

| Gate | Ne kanıtlanır | Nerede |
|---|---|---|
| G0 (bugün) | Kernel verity/TPM hazırlığı + fragment sözleşmesi | Actions: defconfig parse + `arm-hardening-contract-test.sh` |
| G1 | U-Boot FIT_SIGNATURE build + imzalı FIT üretimi; `mkimage -l`/pubkey doğrulaması | Actions: rpi4 build job'ına eklenecek contract adımı |
| G2 | Yeni genimage düzeni + host-side `veritysetup verify` artifact üstünde | Actions: image-contract adımı |
| G3 | QEMU aarch64 (virt + U-Boot) ile FIT imza reddi/kabulü smoke | Actions |
| G4 | Pi 4/CM4/RevPi gerçek boot, RAUC A/B switch + rollback, güç kesme testi | Donanım lab; kanıt mevcut release-evidence hattına yazılır |
| G5 | LUKS2 /data: RevPi TPM2 seal/unseal, Pi 4 keyfile akışı | Donanım lab |

`production_ready` ancak G4+G5 kanıtı release-evidence'ta saklandığında
tartışılır (x86 hattıyla aynı politika).

## Alternatives Considered

| Seçenek | Artılar | Eksiler | Neden seçilmedi |
|---|---|---|---|
| A: TianoCore UEFI (RPi4) + shim + x86 zinciriyle aynı yol | x86 ile tek mimari | RPi UEFI portu endüstriyel olgunlukta değil; DT/donanım desteği eksik | Olgunluk riski |
| B: RPi firmware doğrudan kernel yükler (bugünkü durum + verity) | Basit | Kernel imzası hiç doğrulanmaz; verity hash'i korumasız cmdline'da | Kök güven yok |
| C: U-Boot + signed FIT (seçilen) | Kernel+DTB+initramfs+cmdline imza altında; RAUC'un U-Boot backend'i hazır | İlk aşama yine imzasız; U-Boot bakım yükü | — |

## Consequences

- Yeni genimage cfg'leri ve `post-image.sh` ARM dalı; USB installer payload
  düzeni değişir (installer sözleşme testleri güncellenecek).
- initramfs gerekir (bugün ARM imajlarında yok) — boyut bütçesi ~4-6 MB.
- FIT imza anahtarı `docs/security/key-management.md` ve key-ceremony
  sürecine eklenir; CI'da yalnız lab anahtarı, prod anahtar HSM'de.
- RAUC system.conf ARM slot tanımları ve U-Boot env alanı eklenir
  (ADR-0004'ün ARM somutlaması).
- ADR-0005'in "UEFI Secure Boot" bölümü x86'ya özgü kalır; bu ADR ARM
  karşılığıdır (ADR-0005'i değiştirmez, tamamlar).

## Production build lane (PR-A9)

ARM prod imajı, x86 desenini (ayrı `_prod_ab` defconfig) izleyen ayrı, gated bir
hatta kurulur:

- **`configs/suderra_aarch64_{rpi4,revpi4}_prod_ab_defconfig`** — `VARIANT_PROD`,
  kilitli appliance (dropbear/getty yok). Dev `rpi4`/`revpi4` defconfig'leri
  DOKUNULMAZ; her-PR standart Image Build yeşil kalır. Prod hedefler
  `ci/build-matrix.yml`'de `image_build: false` ile standart build'den hariç
  tutulur (tıpkı `qemu_x86_64_prod_ab`).
- **`.github/workflows/arm-production-build.yml`** — `workflow_dispatch`, korumalı
  `production-runtime` environment. `SUDERRA_SIGNING_MODE=prod` FIT/imaj/RAUC
  imzalamasını **PKCS#11/HSM** anahtarına zorlar (`need_signing_key` dosya
  anahtarını reddeder). Gerçek imzalı build yalnız HSM signing material
  sağlandığında koşar; SoftHSM audited gate (`validate-hsm-signing-evidence.py`
  softhsm negatif kontrolü + allowlist) tarafından reddedilir.
- **`ci/evidence-contract.yml`** — `rpi4-prod-ab`/`revpi4-prod-ab` OTA hedefleri
  `backend: uboot-rauc`, `ota_capable: true`, U-Boot env monotonic rollback.
- `production_ready` tüm prod hedeflerde `false` kalır; gerçek donanım kanıtı
  (G4/G5, A10/A11) release/ingress join'de gelene dek fail-closed.

## FIT signature enforcement and the U-Boot boot chain (ADR-048 DEC-18; EI-013, EI-034, EI-035, EI-036)

The first version of this chain trusted four assumptions of mainline U-Boot that
do not hold on `rpi_arm64`, and the audit found each of them (T85-T88, EI-013,
EI-034, EI-035, EI-036). What replaced them, and what proves it:

1. **The control FDT is the firmware's device tree, so the key goes there.** On
   `rpi_arm64` U-Boot runs with the device tree the VideoCore firmware loads and
   passes in (`OF_BOARD`); the keyed `u-boot.dtb` of the first version was a file
   nothing loaded, and with no `/signature` node in the control FDT U-Boot accepts
   *any* FIT (`boot/image-fit-sig.c`). `OF_BOARD` stays, because the firmware's tree
   is the accurate description of the Pi 4B, the CM4 and the CM4 IO board, and the
   tree compiled into U-Boot is the Pi 4B's alone. The image build
   (`production-artifacts.sh key_firmware_dtbs`) inserts the `mkimage -K` key
   into a copy of every stock tree the firmware may load (`firmware-dtb/`), the
   boot partition carries those copies, and the production default environment's
   `bootcmd` boots only if the control FDT (`fdtcontroladdr`, which U-Boot sets itself
   after the environment loads) holds `/signature/key-fit-signing` with
   `required = "conf"`. There is no `u-boot.dtb` and no `BR2_TARGET_UBOOT_FORMAT_DTB`.
2. **The command line is the signed device tree's `/chosen/bootargs`.** U-Boot reads
   no `bootargs` property from a FIT configuration; it keeps the device tree image's
   `/chosen/bootargs` unless the environment has a `bootargs` variable
   (`boot/fdt_support.c`). The producer bakes the slot's command line (verity root
   hash, `rauc.slot`, lockdown) into the device tree the FIT signs, the environment
   has no `bootargs` and cannot get one, so the signature covers the arguments the
   kernel receives.
3. **Nothing but the compiled-in `bootcmd` boots.** `board/suderra/uboot/hardening.config`
   removes distro boot (BOOTSTD), `booti`/`bootz`/`bootefi`, `sysboot`, PXE, DHCP/TFTP,
   USB, `source`, the legacy image formats and the serial loaders, sets
   `BOOTDELAY=-2` (-1 stops AT the prompt in this U-Boot) and makes the console input
   the null device. The A/B slot choice is the compiled-in `bootcmd`
   (`board/suderra/uboot/suderra.env`), not an unsigned `boot.scr` on a writable FAT
   (the file is gone); it reads RAUC's counters, spends one try of the slot it chooses
   and saves it before the kernel starts (the behaviour of RAUC's own U-Boot reference
   script, `contrib/uboot.sh`), and ends in `reset`, never in a prompt. A FIT that does
   not load or verify costs that one try, never the slot: the first version zeroed the
   slot's counter on any failure, so one failed `load` (a read error, a supply that
   sags at power-up) left a factory board, which has no slot B, with no slot to boot and
   no console to say so. A slot out of tries yields to the other, and when no slot has
   a try left both are armed again with RAUC's `boot-attempts`, so a cause that was
   transient never leaves a board down; a slot that is genuinely broken keeps failing,
   which is the same as stopping. RAUC's mark-good, after the health gate, arms the
   booted slot again.
4. **The stored environment can change only the boot counters.**
   `ENV_WRITEABLE_LIST` makes U-Boot start from the compiled-in environment and take
   only `BOOT_ORDER`, `BOOT_A_LEFT` and `BOOT_B_LEFT` from the stored one (the flag
   list is set by `board/suderra/uboot/patches`, U-Boot 2025.04 has no Kconfig symbol
   for it). The environment is two raw CRC-checked copies in front of the first
   partition (`SYS_REDUNDAND_ENVIRONMENT`, the symbol earlier text spells
   `ENV_REDUNDANT`), not a file on the boot FAT, and `fw_env.config` names the same
   offsets.

Proofs, none of them a grep of a file nobody loads:

- `scripts/ci/check-uboot-config.py` checks the policy on the fragments of every
  defconfig and, in `post-build.sh`, on the `.config` Buildroot resolved (Kconfig
  drops a line whose dependency is gone and keeps a value the base defconfig set
  first: the resolved `.config` of the first fragment kept `LEGACY_IMAGE_FORMAT=y`).
- `production-artifacts.sh arm-boot-gate` (run by the producer and by `post-image.sh`)
  checks the built artifacts: the key in every firmware device tree as a required key,
  both slot FITs verified against it by U-Boot's own `fit_check_sign`, and the slot's
  command line in every device tree of every FIT.
- `tests/qemu/arm-fit-signature-boot.sh` boots a real U-Boot built from the pinned
  sources with the same fragment and the same default environment on
  `qemu-system-aarch64` (QEMU's `-dtb` plays the firmware): the signed FIT boots and the
  kernel gets the signed command line; a control FDT without the key boots nothing,
  and the same U-Boot built without the guard boots an unsigned FIT, which is the
  hole; a tampered, re-signed, unsigned or legacy FIT is refused; a stored environment
  that sets `bootcmd`, `bootargs`, `stdin` or `preboot` changes none of them; no prompt
  appears under a stream of keystrokes. CI: `.github/workflows/uboot-boot-chain.yml`.

What stays hardware-only: that the Pi firmware really hands U-Boot the keyed tree from
the boot partition (the `OF_BOARD` path of `rpi.c`), that the raw environment on the
eMMC/SD card survives a power cut, and the integrity of the boot partition, which is
the next section (H2).

### Partition identity, the verity policy and the USB policy (ADR-048 DEC-18; EI-049, EI-050)

- **Partitions are identified by PARTUUID, never by a label, and the running system
  names only the ones on the disk of the verified root.** `board/suderra/common/
  gpt-partuuids.conf` lists the GPT PARTUUID of every partition of the production
  layouts; the genimage-prod configs (and the A/B x86 config) write them, and the
  signed command line carries `suderra.verity.root_partuuid` / `hash_partuuid`. The
  verity initramfs resolves the two partitions by PARTUUID and refuses to continue
  when a second device carries the same one (the old `blkid -t PARTLABEL=... | head
  -n 1` took whichever disk answered first).

  The list is public, so a PARTUUID is only a claim, and a `/dev/disk/by-partuuid`
  link goes to whichever claimant udev saw last: the first version named RAUC's
  slots, the boot mount and `/data` by such links, so a USB stick whose blank
  partition carried the data PARTUUID, plugged in before boot, could be classified
  blank and provisioned (luksFormat, TPM seal, mkfs, FACTORY) on someone else's
  media; the QEMU test reproduces exactly that with a second virtio disk. Now
  `suderra-disk-layout.service` (`usr/sbin/suderra-disk-layout`) runs before
  anything mounts, opens or writes a partition: the boot disk is the whole disk under
  the device-mapper device `suderra-root` (read from sysfs), every partition of every
  disk is asked for its PARTUUID with `blkid -p` (which reads the parent disk's
  partition table, so a blank partition has one), and a PARTUUID of the layout that
  two partitions carry, or that a partition of another disk carries, refuses the
  whole layout: nothing is named, the reasons are in the journal and in
  `/run/suderra-os/disk/refusal`, `suderra-data-unlock` reports them as its
  `data-unmountable` alarm and touches nothing, and the `/boot` mount, RAUC and
  mark-good do not start (`Requires=`). Only an accepted layout gets its links,
  `/run/suderra-os/disk/<partition>`, which are the one name the `/boot` mount
  (`boot.mount*`), RAUC's slots (`system.conf*`) and `/data` use; the table
  (`usr/lib/suderra/partuuids.conf`) is rendered from `gpt-partuuids.conf` by
  `post-build.sh`. `tests/image-contracts/disk-layout-contract-test.sh` runs the
  script on a stand-in sysfs (one disk, a second disk with a copied PARTUUID, a root
  that spans disks, mutations of each rule) and `tests/qemu/data-unlock-vm-test.py`
  runs it in a guest with a real kernel and blkid and a second disk. What this does
  not bind: `fw_env.config` names `/dev/mmcblk0`, the node of the board's boot
  card or eMMC, not a partition identity (a USB device cannot take an `mmcblk` name);
  a board with both an SD slot and an eMMC would need the environment located from
  the boot disk as well (hardware check 7).
- **The verity table carries `restart_on_corruption`.** A block that fails its hash
  restarts the machine, and because every boot spends one of the slot's tries (and
  mark-good restores them once the health gate passed), a slot whose root file system
  is corrupt runs out of tries and the other slot boots, confirmed or not. The first
  version counted only freshly installed slots ("a confirmed boot writes nothing"), so
  a confirmed slot restarted into itself for ever; the premise was also wrong end to
  end, because RAUC's mark-good runs `fw_setenv` on every boot anyway
  (`src/bootloaders/uboot.c`, `r_uboot_set_state`). Two environment writes per boot (the
  spend before the kernel, the mark-good after the health gate) go to the redundant raw
  copies, whose writer fills the copy that is not current (`env/mmc.c`, `env_mmc_save`),
  so a power cut leaves the old or the new counters. What the restart-to-fallback chain
  has run: U-Boot's side (a slot that boots and never confirms yields after its tries,
  `tests/qemu/arm-fit-signature-boot.sh` S7) and the choice table (`tests/image-contracts/
  uboot-env-exec-contract-test.sh`). Not run: the kernel's `restart_on_corruption` reset
  on a real root file system with a flipped byte (EI-050 stays open until the hardware
  check 6 below, or a VM with the production initramfs, shows it).
- **The ARM command line has `debugfs=off` and `module.sig_enforce=1`** like the x86
  one. `module.sig_enforce` is a kernel parameter only where the kernel has
  `CONFIG_MODULE_SIG` (the RevPi production kernel does; the Pi 4 production kernel
  does not yet, EI-048) and is ignored otherwise. The console of the generic image
  is `console=tty1`, never the UART of the agent's fieldbus, and the firmware's
  second stage no longer writes to it (`uart_2ndstage=0`).
- **USB:** `usbguard` runs in every production image with `etc/usbguard/rules.conf`:
  storage is blocked, hubs, serial adapters and HID are allowed by `equals` rules
  (`all-of` would let a keyboard that also carries a network interface in). The
  rules parse with usbguard's own parser in `tests/image-contracts/
  usbguard-contract-test.sh`; which descriptors a field adapter really has is the
  hardware list.
- **U-Boot environment on the boot disk:** two raw copies in the gap in front of
  the first partition (user area of the eMMC or SD card, one definition for every
  board; the eMMC hardware boot partitions the ADR prefers do not exist on an SD
  card and would be a RevPi-only variant that needs the hardware to validate).

### Hardware checks of the boot chain (what the QEMU test cannot show)

Each is a step of the G4 test on a Pi 4 / CM4 and on a Revolution Pi Connect 4, with
a production image:

1. `cat /proc/cmdline` holds `suderra.verity.root_hash=`, `lockdown=confidentiality`
   and `suderra.verity.root_partuuid=` (the Pi firmware hands U-Boot the keyed device
   tree of the boot partition; a build whose tree lacked the key would never boot,
   the compiled-in `bootcmd` refuses it).
2. Replace `suderra-A.fit` on the boot partition (rw remount) with an unsigned FIT
   and with one signed by another key: the device resets and takes slot B, or
   resets again; it never starts the kernel.
3. `fw_printenv` shows the counters U-Boot saved (the raw environment at 0x60000 and
   0x80000 of `/dev/mmcblk0`); install an update and look at `BOOT_ORDER` and
   `BOOT_<slot>_LEFT` change (a boot spends one try before the kernel starts, mark-good
   restores it); cut the power while `fw_setenv` or U-Boot's `saveenv` runs, a thousand
   times, and the device still boots with a valid environment.
4. A USB stick inserted while the device runs is blocked (`usbguard list-devices`),
   a serial adapter of the hardware list is allowed.
5. A Modbus master flooding the RS485 port during a power cycle does not stop the
   boot and leaves no console bytes on the line after U-Boot's own output
   (U-Boot's output uses the `enable_uart` UART of the firmware: whether it may stay
   on a HAT that must be silent at power-up is decided on the hardware).
6. Flip one byte of the active root file system on disk, read the file: the device
   restarts, and after the slot's three tries it takes the other slot.
7. A second disk with the same PARTUUIDs attached at boot: the initramfs refuses
   (`PARTUUID ... is on 2 devices`) instead of choosing one; with only the data
   PARTUUID copied to a USB stick (a partition of any size) the device boots, the
   journal of `suderra-disk-layout.service` says the PARTUUID is carried twice,
   `/data` is not provisioned or opened, the stick is untouched (`blkid` shows no
   signature) and the unit's `refusal` file is the data alarm; unplugging the stick
   and rebooting restores the normal boot. On a board that has both an SD slot and an
   eMMC, check which one `/dev/mmcblk0` is against the boot disk.

Not code: the Raspberry Pi OTP secure boot that authenticates the boot partition
(H2 below), `bekliyor: operatör`.

## Remaining hardware/kernel gates before ARM production_ready (audit G4/G5)

The audit's remaining findings are either implemented above or gated below on a
real Pi/RevPi + kernel/U-Boot build. `production_ready` stays `false` until each
is closed with on-device evidence. Each is specified so it runs turnkey when
hardware is attached.

- **H2 — physical root of trust (OTP secure boot).** The FAT boot chain
  (`u-boot.bin`, the keyed device trees, the FITs) is loaded by the Pi ROM with no
  signature check unless CM4/RevPi **OTP secure boot** is provisioned (signed
  bootcode + key hash burned into OTP). The FIT key lives in the device trees on that
  FAT, so until OTP secure boot is on, whoever can write the boot partition can
  replace the key and the FIT together: the signed FIT protects against a modified
  FIT or a modified environment, not against that. The OTP step is an operator action
  (`bekliyor: operatör`, ADR-048 Q-OTP). Done in software already: `/boot` is mounted
  read-only (`boot.mount.arm`) and written only by RAUC's slot hook for the one FIT it
  installs; U-Boot has no console, no prompt and `BOOTDELAY=-2`.
- **M3 — kernel module signing.** `lockdown=confidentiality` only rejects
  unsigned modules when `CONFIG_MODULE_SIG` is built in. Enable
  `CONFIG_MODULE_SIG_FORCE` + `CONFIG_MODULE_SIG_ALL` in a **prod-only** kernel
  fragment (the current `linux-rpi4.config` is shared with dev, which has no
  signing key) and add `module.sig_enforce=1` to the ARM prod cmdline — then
  confirm the full BCM2711 driver set still boots (G4). Alternative: go
  monolithic (`# CONFIG_MODULES`) once the driver set is validated.
- **H3 — verity cmdline delivery: closed.** The command line is the `/chosen/bootargs`
  of the signed device tree (checked on every built FIT by `arm-boot-gate`, and on the
  command line the kernel receives by the QEMU boot test).
- **MED2 — executed boot enforcement: closed.** `tests/qemu/arm-fit-signature-boot.sh`
  runs in `.github/workflows/uboot-boot-chain.yml`; the hardware part is the G4 test.
- **corr-M3 — cross-flash guard.** rpi4 and revpi4 share `compatible=suderra-os-aarch64`
  (RAUC accepts a cross-board bundle; both are CM4-class). The RAUC config is
  arch-shared today (x86 has the same qemu-vs-hardware gap), so a proper fix needs
  board-aware config: distinct `compatible` (`suderra-os-rpi4` / `suderra-os-revpi4`,
  already declared in `ci/evidence-contract.yml`) plumbed through both
  `system.conf.arm` and `write_arm_manifest`, or a runtime board-identity guard.
  Partially mitigated by the multi-board FIT (a wrong-board image has no matching
  signed config).
