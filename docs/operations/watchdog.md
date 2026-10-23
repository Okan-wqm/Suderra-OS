# The hardware watchdog: PID1 owns it

ADR-048 DEC-6.6 (EI-033). What resets a device that hangs, who owns the timer,
how a board's timer is chosen, and what is still verified only on hardware.
Everything below that can be checked without a board is checked by
`tests/image-contracts/watchdog-contract-test.sh` and
`tests/image-contracts/kernel-config-contract-test.sh`.

## Who owns it

systemd PID1, and nothing else. `RuntimeWatchdogSec=` makes PID1 open the
hardware watchdog, program the timeout and ping at least once in every half of
it; a PID1 that hangs, or a kernel that hangs, stops the pings and the board
resets. There is no second daemon: `suderra-watchdog` (the crate that was never
packaged) is gone, because a daemon that closes the device with the magic
character lets any root `systemctl stop` switch hang recovery off, and its health
escalation would turn an agent fault into a reboot loop of the whole machine.
`suderra-agent.service` may not name `/dev/watchdog` (`contracts/suderra-edge/v1/
unit-directives.json`, fixture `watchdog-granted`); the agent's own liveness is
its `WatchdogSec=` ping to systemd, which restarts the agent and never reboots
the machine (DEC-6.5).

A production kernel is built with `CONFIG_WATCHDOG_NOWAYOUT=y`, so once PID1 has
armed the timer nothing can stop it: not a root `systemctl stop`, not a crashed
daemon, not a magic close (`drivers/watchdog/Kconfig`: "the watchdog cannot be
stopped once it has been started"). A development kernel does not need it and
the checker does not hold it to it.

## What an image carries

`scripts/ci/board-watchdog.py install` (called by `post-build.sh`) copies the
image's own pair from `board/suderra/watchdog/<key>/`, where the key is the
image's `board_profile` or, for the model-independent x86 base that declares no
board, its pending family:

| File on the image | Content |
|---|---|
| `/etc/systemd/system.conf.d/10-suderra-watchdog.conf` | `WatchdogDevice=/dev/suderra-watchdog`, `RuntimeWatchdogSec=`, `RebootWatchdogSec=` |
| `/usr/lib/udev/rules.d/60-suderra-watchdog.rules` | links `/dev/suderra-watchdog` to the watchdog whose sysfs `identity` the board names |

The USB installer image and the generic aarch64 template have no key: they are
not boards and run no agent.

### Why a link by identity, and not `/dev/watchdog0`

`/dev/watchdogN` numbers follow probe order. A RevPi Connect 4 has two watchdogs
(the BCM2711 PM watchdog and the PCF2129 RTC's, which the overlay's `rtc@51`
`reset-source` makes the rtc driver register), and an x86 PC can have the chipset
timer, a Super I/O timer and a software one. A rule that names the board's own
timer by the identity its driver reports makes the owner a decision of this
repository instead of a race, and a software watchdog can never be the owner.

systemd 256.17 opens a configured `WatchdogDevice=` path exactly (it tries
`/dev/watchdog0` and `/dev/watchdog` only for the default), logs a missing path
at debug level and retries the open on every ping (`src/shared/watchdog.c`,
`manager_loop` in `src/core/manager.c`). So the timer arms as soon as udev has
created the link, a second or two after PID1 starts, and a kernel that never
makes the link leaves no hardware watchdog and no error at all. That is why the
kernel checker requires `CONFIG_WATCHDOG_SYSFS=y` on every board:
`drivers/watchdog/watchdog_dev.c` of Linux 6.12.114 builds no `identity`, `state`
or `nowayout` attribute without it, the rule would match nothing, and the board
would run exactly as EI-033 found it.

## The boards

| Key | Watchdog (sysfs `identity`) | Hardware maximum | `RuntimeWatchdogSec` | Source |
|---|---|---|---|---|
| `revpi-connect4` | `Broadcom BCM2835 Watchdog timer` | 15.999 s | 10 s | `drivers/watchdog/bcm2835_wdt.c`: `max_hw_heartbeat_ms` = 0xfffff ticks of 1/65536 s |
| `rpi4-cm4` | `Broadcom BCM2835 Watchdog timer` | 15.999 s | 10 s | the same driver; the BCM2711 `pm: watchdog@7e100000` node of `bcm2711.dtsi` (raspberrypi/linux `rpi-6.12.y` at 5bd564aa) has no `status = "disabled"`, so the signed FIT's device tree needs no `dtparam=watchdog=on` |
| `qemu-x86_64` | `iTCO_wdt` (q35's ICH9 LPC) or `i6300ESB timer` (`-device i6300esb`) | 37.8 s (TCO version 1) | 30 s | `drivers/watchdog/iTCO_wdt.c` (0x3f ticks of 0.6 s), `drivers/watchdog/i6300esb.c` |
| `x86-ipc` | `iTCO_wdt` | 37.8 s | 30 s | `drivers/watchdog/iTCO_wdt.c` |

The driver facts are those of Linux 6.12.114
(`https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/<path>?h=v6.12.114`).
The checker holds `RuntimeWatchdogSec` to at least 5 s (a loaded PID1 would
starve a shorter one) and below the smallest hardware maximum of the board's
watchdogs, and `RebootWatchdogSec` above it and at most systemd's own default of
10 min.

`RebootWatchdogSec=2min` guards the second phase of a reboot, after PID1 has been
replaced by `systemd-shutdown` (`man systemd-system.conf`). `systemd-shutdown`
closes the device without disarming it (`src/shutdown/shutdown.c`: "the watchdog
is explicitly not stopped here"), and the BCM2835 driver sets
`max_hw_heartbeat_ms`, so the watchdog core keeps the hardware alive for the
programmed 2 minutes while userspace is gone. Two minutes is a design value,
longer than a clean shutdown of these images should take; a measured shutdown on
hardware replaces it (below).

### What is not a given

- **x86 models.** `x86-ipc` is the model-independent base and names the chipset
  timer. A model whose BIOS leaves `NO_REBOOT` set (the iTCO driver then refuses
  to bind: "unable to reset NO_REBOOT flag, device disabled by hardware/BIOS"), or
  whose timer is a Super I/O or EC one (the kernel carries IT87, F71808E and
  W83627HF), becomes its own `x86-ipc-<model>` board at qualification, with its
  own rule. The model is not chosen (ADR-048 Soru 1), so no such board exists.
- **QEMU.** iTCO refuses to bind unless QEMU starts with
  `-global ICH9-LPC.noreboot=false`, and the VM resets only with
  `-action watchdog=reset`.

## Hardware verification still open (bekliyor: HIL / operator)

No board was available. These are written down, not assumed:

1. **RevPi Connect 4: which watchdog resets what.** The BCM2711 watchdog resets
   the SoC; whether the PCF2129's `reset-source` output resets the carrier board
   (the PiBridge, the RS485 transceivers, the relays' drivers) is a hardware fact.
   The rule names the BCM2711 one, which is always present and whose limits are
   known. If the carrier must reset too, the change is one identity in
   `board/suderra/watchdog/revpi-connect4/60-suderra-watchdog.rules` and in
   `KEYS`/`IDENTITIES` of `scripts/ci/board-watchdog.py` (the PCF2127 driver's
   identity is `NXP PCF2127/PCF2129 Watchdog`, default timeout 60 s, at least
   500 ms; `drivers/rtc/rtc-pcf2127.c` of the KUNBUS `v6.12.91-revpi0` kernel) plus
   its driver capability. The decision is the operator's after the lab result.
2. **`/dev/suderra-watchdog` appears and `state` is `active`** on each board, with
   `nowayout` 1 on a production image, and a deliberate hang resets the board within
   `RuntimeWatchdogSec` plus the hardware granularity. On a RevPi Connect 4
   `scripts/evidence/revpi-connect4-board-checks.sh` checks the first half (the link,
   the identity, `state`, PID1 holding the device, the programmed `timeout`,
   `nowayout`); on the other boards read the same files by hand (below). The hang is
   a crash of the kernel with nothing to reboot it, which stops PID1 and everything
   else at once. A production image has `kernel.sysrq = 0`
   (`etc/sysctl.d/90-suderra-hardening.conf`), so a lab console switches it on for the
   test only, with the console log of the board on a host that timestamps it:

   ```sh
   cat /sys/class/watchdog/$(basename "$(readlink /dev/suderra-watchdog)")/timeout
   sysctl -w kernel.sysrq=1 kernel.panic=0 kernel.panic_on_oops=1
   echo c > /proc/sysrq-trigger
   ```

   The console shows the panic and then nothing; the board must come back (the boot
   banner of the bootloader) between `RuntimeWatchdogSec` and `RuntimeWatchdogSec` plus
   a second or two later, counted from the panic line, and the second boot must have a
   new `/proc/sys/kernel/random/boot_id`. A board that stays dead has no hang recovery.
   `bootstatus` is no evidence: the BCM2835 and iTCO drivers do not report a card reset.
3. **A planned reboot and a poweroff** with NOWAYOUT and `RebootWatchdogSec=2min`:
   that the watchdog never resets a board that is shutting down cleanly, that a
   poweroff on the Raspberry Pi 4 family (which halts instead of cutting power)
   does not turn into a reboot, and the measured worst-case shutdown time that
   `RebootWatchdogSec` must exceed.
4. **A BIOS with `NO_REBOOT` clear** on each qualified x86 model.

## The gap before PID1 arms it

The timer is armed when udev has made the link, after the kernel and the initramfs
have run. A hang before that is not covered by this watchdog. What covers it is
the firmware: a bootloader that starts the BCM2835 watchdog makes the kernel's
watchdog core ping it
(`CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED`, default y) until userspace opens it, and
`CONFIG_WATCHDOG_OPEN_TIMEOUT` bounds how long it does that. Neither is set here:
the U-Boot environment and fragment belong to the boot chain (ADR-048 DEC-18) and
the A/B try counter of the boot chain only advances on a reset. That is a tracked
follow-up of the boot chain, not of this file.

## Look at a device

```sh
ls -l /dev/suderra-watchdog                                # the link udev made
readlink -f /dev/suderra-watchdog                          # /dev/watchdogN
cat /sys/class/watchdog/watchdog*/identity                 # every timer the kernel has
cat /sys/class/watchdog/watchdog*/state                    # active: PID1 holds it open
cat /sys/class/watchdog/watchdog*/nowayout                 # 1 on a production kernel
cat /sys/class/watchdog/watchdog*/timeout                  # the programmed timeout
journalctl -b _PID=1 | grep -i watchdog                    # "Using hardware watchdog", "Watchdog running with a hardware timeout of"
systemctl show -p RuntimeWatchdogUSec -p RebootWatchdogUSec
```
