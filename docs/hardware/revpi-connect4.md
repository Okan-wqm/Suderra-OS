# Revolution Pi Connect 4 (`revpi-connect4`)

The Revolution Pi Connect 4 is the primary production target of Suderra OS
(ADR-048 DEC-8). Its images are **not** generic CM4 images: they are built on
the KUNBUS RevolutionPi kernel, load KUNBUS's `piControl` driver, and boot a
device tree that has the Connect 4's own hardware merged into the CM4 tree.

| | |
|---|---|
| Board profile / RAUC compatible | `revpi-connect4` / `suderra-os-revpi-connect4` (`contracts/suderra-edge/v1/boards.json`) |
| Images | `suderra_aarch64_revpi4_defconfig` (dev), `suderra_aarch64_revpi4_prod_ab_defconfig` (production, signed FIT, A/B, dm-verity, LUKS2 `/data`) |
| Board directory | `board/suderra/aarch64-revpi-connect4/` |
| Agent profile | `suderra-os`, features `revpi-io`, `scada-display`; no `gpio` (the kernel owns the digital I/O lines) |
| TPM | Infineon SLB9670, SPI1 `tpm@0` |
| RTC | NXP PCF2129, I2C1 `rtc@51`, CR2032 backed |
| RS485 | UART5, `/dev/ttyAMA5` |
| Console | mini-UART (`serial0`, `ttyS0`), the debug UART |

## 1. What the image is built from

| Component | Pin | Where it is pinned |
|---|---|---|
| Kernel | KUNBUS `revpi-6.12`, tag `v6.12.91-revpi0`, commit `756591ec4845ec0114ee7a3a99768f69bcd8bed3` | `BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION` in both defconfigs, sha256 in `board/suderra/buildroot-hashes/linux/linux.hash` |
| Base kernel config | KUNBUS `arch/arm64/configs/revpi-v8_defconfig` (`PREEMPT_RT`) | `BR2_LINUX_KERNEL_DEFCONFIG="revpi-v8"` |
| piControl | upstream tag `v2.6.2`, commit `7acf6e9110dd558b434b57f50ee5d4b5d54b5d91` | `package/revpi-picontrol/` (`.mk`, `.hash`) |
| Device tree | `bcm2711-rpi-cm4.dtb` + `revpi-connect4.dtbo`, both built by the pinned kernel | `board/suderra/aarch64-revpi-connect4/board-boot.conf` |

Sources (the kernel tag resolves to the same commit on both hosts; piControl was checked on GitLab only):

- Kernel: <https://gitlab.com/revolutionpi/linux> (mirror: <https://github.com/RevolutionPi/linux>), GPL-2.0 (`COPYING`).
  The overlay is `arch/arm/boot/dts/overlays/revpi-connect4-overlay.dts` (GPL-2.0-only, KUNBUS).
- piControl: <https://gitlab.com/revolutionpi/piControl>. The module is GPL-2.0-only,
  `json.c` and `RS485FwuCommand.c` are LGPL-2.1-only, the userspace header `piControl.h` is MIT
  (`LICENSES/` of the repository; hashes in `revpi-picontrol.hash`).

The kernel tarball is GitLab's archive of the pinned commit. Its hash was computed from the
downloaded file, not copied from anywhere (two independent downloads hashed identically), and
Buildroot re-verifies it on every build (`BR2_DOWNLOAD_FORCE_CHECK_HASHES=y`). `github.com`'s `codeload` host was not reachable from the
environment this was prepared in, so the GitHub archive of the same commit was not compared.

### 1.1 piControl is v2.6.2, not the newest release

piControl is an out-of-tree module and is not part of the KUNBUS kernel tree (only the PiBridge
serdev master, `CONFIG_SERIAL_DEV_MUX_PIBRIDGE`, is). A piControl release works only with the
kernel it was built against:

- KUNBUS builds `piControl` `debian/2.6.2-1+deb12+4` "for linux-image-6.12.91-revpi0-rpi-v8"
  (`debian/2.6.2-1+deb12+4`, commit `94fba2a8…`). Its source is byte-identical to the upstream tag
  `v2.6.2` apart from the `debian/` directory, which is what this image builds.
- Releases from 2.7 on are built for the 6.18 KUNBUS kernel. piControl 2.8.2 calls
  `pibridge_req_io_tmt`, `pibridge_get_iop_crc16` and `pibridge_set_iop_crc16`, which
  `drivers/tty/serdev/pibridge.c` of `revpi-6.12` does not export, so it cannot link against this
  kernel. 2.6.2 uses only exported symbols (`pibridge_send`, `_clear_fifo`, `_get`, `_req_io`,
  `_req_gate_datagram`, `_req_gate_tmt`, `_req_send_gate`).
- 2.6.2 compiles against the pinned kernel tree with the aarch64 gcc 13 toolchain.

**Userspace ABI.** Code written against the piControl 2.8.2 header works with this 2.6.2 driver for
everything the agent's ioctl allowlist uses (checked by compiling both headers and reading both
driver sources):

- `SDeviceInfo` is 72 bytes in both releases (`i8uActive` at offset 39). 2.8.2's `i16uFeatures`
  sits at offset 40, in what 2.6.2 calls the first two reserved bytes, and the 2.6.2 driver allocates
  the device list zeroed (`kcalloc`) and never writes the reserve, so `features` reads 0 on this
  driver.
- `KB_PI_LEN` (2.6.2) and `PICONTROL_PROCESS_IMAGE_LEN` (2.8.2) are both 4096;
  `REV_PI_DEV_CNT_MAX` and `PICONTROL_MAX_DEVICES` are both 64.
- The handlers of `KB_GET_DEVICE_INFO_LIST`, `KB_GET_VALUE`, `KB_SET_VALUE`, `KB_FIND_VARIABLE`,
  `KB_SET_OUTPUT_WATCHDOG` and `KB_WAIT_FOR_EVENT` differ between the releases by refactoring
  (`scoped_guard`, helper functions, renamed constants) and by three behaviours a caller must
  allow for (read from `src/piControlMain.c` of both tags; the agent's `abi.rs` header carries the
  same table):
  - `KB_SET_OUTPUT_WATCHDOG` reads a C `unsigned long` from its argument in 2.6.2
    (`get_user(priv->tTimeoutDurationMs, (unsigned long __user *) usr_addr)`: 8 bytes on aarch64,
    4 on 32-bit ARM) and an `unsigned int` in 2.8.2. A caller passes an `unsigned long`-wide
    buffer with the period in its low four bytes and the rest zero; a 4-byte buffer makes 2.6.2
    arm whatever lies beside it, or fail to disarm, and `piControlRelease()` then zeroes every
    output when the descriptor closes.
  - `KB_FIND_VARIABLE` of an unknown name returns `EFAULT` in 2.6.2 (the status is never set) and
    `ENOENT` in 2.8.2; both copy the "not found" defaults (`0xFFFF`, `0xFF`, `0xFFFF`) back.
  - `KB_WAIT_FOR_EVENT` interrupted by a signal returns `EFAULT` in 2.6.2 (the status is never set)
    and the interrupted wait's error (`EINTR`) in 2.8.2.
  - 2.6.2's `KB_GET_DEVICE_INFO_LIST` also prints a firmware-update hint to the user message buffer.
- The 2.8.2 header drops `KB_CONFIG_STOP`, `KB_CONFIG_SEND` and `KB_CONFIG_START` (ioctls 23 to 25) and
  deprecates `KB_GET_LAST_MESSAGE` and `KB_SET_POS`; none is allowlisted.

The release that defines the driver's behaviour on the board is 2.6.2: a behaviour question is
answered by `src/piControlMain.c` of that tag, not of a newer one.

## 2. Boot chain and the device tree

Production: Pi firmware → U-Boot (`rpi_arm64`, FIT signature enforced) → signed FIT of the active
RAUC slot → kernel + dm-verity initramfs. U-Boot hands the kernel the device tree **inside the FIT**.
A `dtoverlay=` or `dtparam=` line in `config.txt` only changes the device tree the firmware builds for
U-Boot, so it never reaches the production kernel (EI-024, EI-029). The RevPi therefore does not
use such lines at all (`tests/image-contracts/revpi-board-contract-test.sh` rejects them in both
firmware configs), and the board's nodes come from one place:

1. The pinned kernel builds `broadcom/bcm2711-rpi-cm4.dtb` and `overlays/revpi-connect4.dtbo` with
   `dtc -@` (`BR2_LINUX_KERNEL_DTB_OVERLAY_SUPPORT=y`).
2. `scripts/production-artifacts.sh arm-board-dtb` merges them with `fdtoverlay` into
   `bcm2711-revpi-connect4.dtb` and fails unless the result enables every node of
   `dt-required.txt`.
3. Production: `arm-pre-genimage` signs that tree into a one-configuration FIT
   (`revpi-connect4.its`, configuration compatible `kunbus,revpi-connect4`), then extracts the tree
   back out of the built FIT and gates it again, so the check judges what U-Boot hands the kernel.
   Dev: the firmware loads the same file through `config.txt` `device_tree=`.

The merged tree's root compatible is `kunbus,revpi-connect4`, `brcm,bcm2711`. Its `model` string stays
"Raspberry Pi Compute Module 4" (the overlay changes `compatible` only), which is why the board
identity comes from the signed image (`/etc/suderra/board`) and the device-tree compatible is only a
cross-check (DEC-8.2). There is no `bcm2711-rpi-cm4-io` tree, no firmware overlays directory and no
raw CM4 configuration in the FIT.

What `revpi-connect4-overlay.dts` provides, as read from the pinned tree and confirmed in the merged
tree:

| Node | Detail |
|---|---|
| `spi1` / `tpm@0` | `infineon,slb9670`, SPI1 (the BCM2711 auxiliary SPI), interrupt GPIO10 |
| `i2c1` / `rtc@51` | `nxp,pcf2129`, `reset-source` (the RTC can reset the board) |
| `i2c1` / `gpio@21`, `gpio@22` | `nxp,pcal6416`, `nxp,pcal6524` expanders behind the LEDs and the PiBridge sniff lines |
| `/pibridge` | `kunbus,pibridge`: connect/sniff/termination GPIOs |
| `uart3` / `pi_bridge` | PiBridge serdev master (`kunbus,pi-bridge`), driven by piControl |
| `uart5` | RS485 (`linux,rs485-enabled-at-boot-time`, RTS active low), `serial5` = `ttyAMA5` |
| `uart1` | mini-UART, `serial0` = `ttyS0`: the debug console (TX on GPIO14), so the FIT's bootargs use `console=ttyS0,115200` |
| `/leds` | 15 RGB status LEDs A1–A5 and `power_red` on the expanders; triggers are registered by piControl |
| watchdog | `/soc/watchdog@7e100000` (`brcm,bcm2835-pm-wdt`, enabled by default) and the PCF2129's `reset-source` |

KUNBUS's separate `tpm-slb9670-overlay` is **not** used: it describes an add-on board on SPI0 CE1,
while the Connect 4's TPM is on SPI1 and already in the `revpi-connect4` overlay.

The kernel's `Image` is copied by U-Boot out of the FIT's own load area, so it must be smaller than the
gap between `fitaddr` (`board/suderra/uboot/suderra.env`) and the load address,
33,030,144 bytes today. `production-artifacts.sh` checks the real `Image` and refuses to build a
FIT it would overwrite. This kernel has not been built in the environment this was prepared in
(see section 5), so its real size is unknown.

## 3. Kernel configuration

Three layers, in the order they win (`BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES`):

1. `linux-revpi-suderra.config`: what the board and the image need built in (boot path, firewall,
   LUKS2, agent sandbox, SPI TPM, I2C/GPIO expanders, PCF2127 RTC, serial, LEDs, `IPV6=y`, hardening
   defaults). The KUNBUS defconfig has most of these as modules or absent.
2. `board/suderra/aarch64-rpi4/linux-rpi4-hardening.config`: the arm64 hardening all BCM2711 boards
   share (lockdown LSM, `INIT_ON_*`, unprivileged BPF off, KEXEC/hibernation off, …).
3. Production only, `linux-revpi-suderra-prod.config`: `MODULE_SIG`, `MODULE_SIG_FORCE`,
   `MODULE_SIG_ALL`, `MODULE_SIG_SHA512` and `LOCK_DOWN_KERNEL_FORCE_INTEGRITY` (ADR-0007 M3,
   EI-048). The kernel keeps loadable modules (the monolithic alternative needs the driver set
   validated on the board) but refuses any module its own build did not sign. `modules_install`
   signs piControl with the same per-build key; the private key lives only in the build tree.

`scripts/ci/check-kernel-config.py` derives the required symbols from what the image runs and checks
them in the fragments on every PR (`kernel-config-contract-test.sh`) and on the resolved `.config` of
every image build (`post-build.sh`). The RevPi adds the capabilities `revpi-field-io`, `revpi-rtc`,
`revpi-console`, `revpi-rt`, `arm64-hardening` and, for the production image,
`module-signing`.

Resolving the real kernel config showed two defects a fragment-only check cannot see, both fixed in the
fragment: `IPV6` is a module in the KUNBUS defconfig, which caps `NFT_REJECT`/`NFT_REJECT_INET` at `m`
(the `nft_reject` dependency `!NF_TABLES_INET || (IPV6!=m || m)`), and `NFT_SET_HASH`/`NFT_SET_RBTREE`
no longer exist in 6.12.

KUNBUS's kernel is a distribution kernel: the resolved config has about 1,800 modules. The rootfs is
384 MB for that reason (inside the 512 MB A/B slot); a rootfs that does not fit fails the image
build. A smaller or monolithic kernel is the hardware-gated follow-up of ADR-0007 and is not done
here.

## 4. Bumping the kernel (monthly, and on a CVE)

1. Pick the new `v6.12.<n>-revpi<m>` tag of `revpi-6.12` and its commit
   (`git ls-remote https://gitlab.com/revolutionpi/linux.git 'refs/tags/v6.12*'`).
2. Find the piControl release KUNBUS built for it: the tag message of the piControl
   `debian/<version>-1+deb12+<n>` tags says "Build for linux-image-<kernel version>". Use that
   release's upstream commit, never a newer one (section 1.1).
3. Download both archives, compute their sha256, and update the two defconfigs, `linux.hash`,
   `revpi-picontrol.mk` and `revpi-picontrol.hash` in one change. Download each archive twice and
   compare the hashes.
4. `tests/image-contracts/revpi-board-contract-test.sh` and `kernel-config-contract-test.sh`.
5. Resolve the kernel config and build the board device tree (section 5) and confirm the contract
   passes on the resolved `.config`.
6. Build both images. The module link step proves piControl against the new kernel
   (an unexported symbol is a modpost error), and the production build runs the device-tree
   and `Image`-size gates.
7. Hardware (section 6) before a release.

## 5. What was verified, and how

With real tools in a scratch Buildroot output directory (not a full image build: the build host had
about 2 GB of free disk, too little for the Buildroot toolchain):

- Buildroot's own download path verified both pinned archives against the hash files
  (`make linux-source`, `make revpi-picontrol-source`).
- Buildroot's kernel-configure sequence was replayed on the extracted pinned tree
  (`revpi-v8_defconfig`, `merge_config.sh -m`, `olddefconfig`, the 66–68 fixup commands Buildroot
  expands for this defconfig including this package's, `olddefconfig`) with the system aarch64 gcc
  13.3 standing in for the Buildroot toolchain (gcc 13.4). Result for production: 1,797 modules,
  1,944 built in; `check-kernel-config.py resolved` passed for both defconfigs. The dev image does not
  force module signatures (`MODULE_SIG_FORCE` off, lockdown `FORCE_NONE`).
- `broadcom/bcm2711-rpi-cm4.dtb` and `overlays/revpi-connect4.dtbo` were built with `DTC_FLAGS=-@`;
  `arm-board-dtb` merged them and all 18 required nodes were present; `arm-pre-genimage` built
  the signed A/B FITs from that tree (with a stand-in kernel `Image` and a stand-in rootfs) and the
  gate passed on the tree extracted from each.
- Buildroot's `host-dtc` (1.7.2), built from the same defconfig, installs `fdtoverlay`, `fdtget` and
  `fdtput`, and `fdtoverlay` merged a test overlay with it; `host-uboot-tools` installs `dumpimage`
  (the tools `arm-board-dtb` and the FIT gate use).
- piControl 2.6.2 compiled and linked into `piControl.ko` against the pinned tree
  (`modules_prepare`; without a full kernel build there is no `Module.symvers`, so symbol
  resolution was checked by reading the exports of `pibridge.c` instead).

Not done here, because it needs more disk, a full image build, or the board:

- A full kernel and image build, so the real `Image` size, the real module size and the rootfs fit
  are unmeasured. CI's image build runs the resolved-config check, the module link and both gates.
- Whether the firmware hands U-Boot the keyed device tree from the boot partition (the control
  FDT), and U-Boot then selects the single FIT configuration and starts the kernel with the
  `/chosen/bootargs` of the device tree that configuration signs. U-Boot never reads a
  configuration's own `bootargs` property (ADR-0007); the command line is part of the signed device
  tree, so what the board has to show is that `/proc/cmdline` carries it (section 6).

## 6. Hardware checklist (needs a Revolution Pi Connect 4)

These are hardware-in-the-loop criteria; QEMU cannot stand in for them. Run the collector on the
board as root, then do the rest by hand:

```sh
scripts/evidence/revpi-connect4-board-checks.sh --out /tmp/revpi-checks --variant prod --try-unsigned-insmod
```

It reads the kernel's views of the hardware, prints `PASS`/`FAIL` per check, and writes
`<check>.txt` plus `checks.json` in the per-check record shape `scripts/evidence/suderra-lab.py`
takes (`board-identity`, `watchdog` and `revpi-io` are lab-required checks; the rest are additional
RevPi evidence). `--variant dev` judges a dev image (no forced signatures). Its logic runs in CI
against fixture roots, and its `tpm-seal` check runs its real `tpm2-tools` sequence against a
software TPM (`tests/image-contracts/revpi-board-checks-contract-test.sh`, with `swtpm`); only a
board can show that the real kernel and the real SLB9670 produce what it reads and does.

Covered by the collector:

- `board-identity`: `/etc/suderra/board` is `revpi-connect4` and the device-tree compatible is
  `kunbus,revpi-connect4`.
- `kernel`: a `6.12.<n>-v8` `PREEMPT_RT` kernel.
- `revpi-io`: `/dev/piControl0` exists and the `piControl` module is loaded.
- `tpm`: `/dev/tpmrm0` exists and `tpm0` is a TPM 2.0.
- `tpm-seal`: the TPM seals and releases a secret the way `/data` does. It seals a throw-away secret
  to PCR 7 and PCR 16 under the TPM's null hierarchy (no owner or endorsement authorisation is used
  or set, the objects vanish at the next TPM reset), unseals it and compares, extends PCR 16 and
  requires the policy to refuse the unseal (`a policy check failed`), then resets PCR 16. PCR 7 is
  never written: the `/data` seal binds it. PCR 16 is the debug PCR, so the check leaves the board
  as it found it unless the TPM refuses the reset, which the evidence then says. `--tcti` names
  another TPM (default `device:/dev/tpmrm0`).
- `rtc`: `rtc0` is the PCF2127 driver (`rtc-rpi`, the firmware RTC, binds only to a
  `raspberrypi,rpi-rtc` node that none of the CM4 trees has, so the PCF2129 is `rtc0`).
- `rtc-hctosys`: `/sys/class/rtc/rtc0/hctosys` is `1`, i.e. the kernel set the system clock from
  the PCF2129 at boot, which it does only when it read a valid time from it. A flat CR2032 or a
  never-set RTC reads `0`: set it (`hwclock --systohc` once the clock is right) and reboot.
- `rs485`: `/dev/ttyAMA5` exists.
- `leds`: the 15 status LEDs and `power:1:fault`.
- `watchdog`: the BCM2835 watchdog is registered.
- `module-signing`: `sig_enforce=Y` and lockdown at integrity or confidentiality (production).
- `boot-chain`: the FIT's bootargs carry `suderra.verity.root_hash=` and `console=ttyS0,115200`
  (production), or the dev root `root=PARTUUID=5d3e0a11-02`.
- `unsigned-module-rejected` (`--try-unsigned-insmod`): the smallest installed module, with its
  appended signature stripped, is refused by `insmod` with `Key was rejected by service`.

Hardware-only, by hand:

- Boots; the console shows the boot; `dmesg` shows the PiBridge master probing.
- `KB_GET_DEVICE_INFO_LIST` lists the DIO/AIO modules on the PiBridge.
- RS485 loopback on `/dev/ttyAMA5`; the status LEDs follow piControl's triggers.
- Which watchdog resets the board and what it resets (BCM2711 PM watchdog or the PCF2129).
- The kernel `Image` is below the FIT load window; rootfs headroom with the real module set.
- The second Ethernet port (a PCIe device behind `pcie0`; KUNBUS's defconfig carries `igb`,
  `lan743x` and `r8169` as modules) enumerates and brings up its driver.
- Tampered or unsigned FIT is rejected by U-Boot (ADR-0007 G4); U-Boot picks the one FIT
  configuration and hands the kernel the `/chosen/bootargs` of its signed device tree (H3);
  `mmc 0:1` in `board/suderra/uboot/suderra.env` is the Connect 4's eMMC boot partition, and
  `fw_printenv` on the device shows the same counters U-Boot saved (the raw environment at
  0x60000/0x80000 of `/dev/mmcblk0`, `package/suderra-rauc-config/fw_env.config`).

Operator actions (not code): OTP secure boot and the production key ceremony (ADR-0007 H2, ADR-048
DEC-14), the eMMC SKU (32 GB recommended, DEC-8). Both are pending the operator.
