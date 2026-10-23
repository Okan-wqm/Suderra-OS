# The health gate: what a booted slot has to prove

ADR-048 DEC-6.8 (EI-008, EI-012, EI-033). After every boot a production image
decides whether the slot it booted is good, and only a pending OS update's
trial boot can be undone by that decision. Everything below that does not need
a board is checked by the unit tests of `suderra-installer`
(`userspace/suderra-installer/src/cmd/health.rs`, `src/bsp.rs`) and by
`tests/image-contracts/board-file-contract-test.sh`,
`tests/image-contracts/time-state-helper-test.sh` and
`tests/image-contracts/watchdog-contract-test.sh`.

## The two halves

| Part | What it is | Where it runs |
|---|---|---|
| `suderra-installer health check` | The predicate: the OS and the agent. It does not know RAUC. It records a `health-gate` result (an alarm naming the first failed reason, every reason in the detail) on an image with a board and fails with the list. | every image |
| `suderra-rauc-health-gate` | The RAUC half: the slot state (`rauc status`, the boot state), then the predicate. | images with RAUC |
| `suderra-rauc-mark-good` | The only mark-good path, once per boot (`suderra-rauc-mark-good.service`). A pass is `suderra-ota mark-good`; a failure is `suderra-ota gate-failed`, which rolls back only the trial boot of a pending OTA. On a boot no OTA is pending for, a failure is an alarm and the slot stays good: it was proven by its own trial boot, and rolling it back would mark a slot bad that no update touched and start a rollback storm. | images with RAUC |

## What the predicate checks

It checks what the image declares in `/etc/suderra/features` (written by
`post-build.sh` from what the image is built with) and never what it happens to
find: a declared feature that is absent is a failure, an undeclared one is not
looked for. A development image declares only `rauc` and `tpm`.

| Check | Declared by | Reason (`health-gate` result) |
|---|---|---|
| dm-verity map `suderra-root` is active | `verity` (production) | `verity-inactive` |
| the `/data` LUKS mapper `suderra-data` exists | `luks` (production) | `data-mapper-missing` |
| the loaded nft ruleset is the one `policy apply` checked and recorded this boot (hash of `nft list ruleset`) | every image | `firewall-hash-mismatch` |
| the clock is not below the time floor (see below) | every image | `clock-below-floor` |
| the TPM answers: `/dev/tpmrm0` exists and `/sys/class/tpm/tpm0/tpm_version_major` reads 2 | `tpm` | `tpm-unavailable` |
| the system RTC: `/dev/rtc0` exists and a driver is bound (`/sys/class/rtc/rtc0/name`) | `rtc` | `bsp-probe-failed` |
| the hardware watchdog is armed: `/dev/suderra-watchdog` resolves to a `watchdogN` whose `state` is `active` (PID1 holds it) and, on a production image, whose `nowayout` is `1` | `watchdog` | `bsp-probe-failed` |
| `/dev/piControl0` exists (RevPi Connect 4) | `picontrol` | `bsp-probe-failed` |
| the EFI `SecureBoot` variable reads 1 (`/sys/firmware/efi/efivars`, needs `CONFIG_EFIVAR_FS`) | `secure-boot` (production x86) | `bsp-probe-failed` |

`bsp-probe-failed` alone does not say which probe failed: the result's detail and
the command's error name them (`probes failed: watchdog rtc`).

On an image with a board the predicate also judges the lifecycle and the agent:

| Check | Reason |
|---|---|
| the lifecycle is not `LOCKED` (an unreadable store reads `LOCKED`), and `ACTIVE` or `MAINTENANCE` has a root-verified activation receipt | `lifecycle-inconsistent` |
| an `ACTIVE` device has closed its technician path: `suderra-provision-mode.service` and `dropbear.service` are not active and no one-time-password shadow is bound over `/etc/shadow` | `lifecycle-inconsistent` |
| the receipt's agent ABI is inside the OS's `SUDERRA_AGENT_ABI` range | `abi-incompatible` |
| the agent: only when the lifecycle is `ACTIVE` **and** `/data/rauc/pre-update.json` (written by `suderra-installer health preflight` before the OS update) says it was healthy then: it reaches `active` within a bounded wait (90 s, polled every 3 s, so `activating` is waited for), and its `agent-health` view is not degraded | `agent-not-active`, `agent-degraded` |

A factory-fresh device, or an agent that was already down before the update,
therefore never rolls an OS update back, while an OS that breaks a healthy
activated agent does.

### The clock

`suderra-time-state floor-check` is the one reader of the time floor (DEC-7.2,
`docs/operations/time-sync.md`); the predicate runs it and treats a failure, and
a helper that cannot run at all, as `clock-below-floor`. It exits 1 when the
clock reads less than the floor (the larger of the image's build time and the
last good time saved on `/data`) and chrony has not corrected it, and it writes
nothing. A clock below the floor that chrony has synchronized is not a failure:
the authenticated clock is right and the floor was ahead of the real time, which
the next pass of the helper heals.

### What each image declares

| Image | Declares |
|---|---|
| any development image | `rauc` where RAUC is built, `tpm` with a TPM binding |
| production `revpi-connect4` | `verity luks rauc tpm rtc watchdog picontrol` |
| production `rpi4-cm4` | `verity luks rauc watchdog` (no TPM binding; no RTC: the signed FIT's device tree has no RTC overlay yet, EI-046) |
| production `qemu-x86_64` | `verity luks secure-boot rauc tpm rtc watchdog` |
| production x86 base (no board) | `verity luks secure-boot rauc rtc watchdog` |

## Not covered here

- The probes were run against fake roots (sysfs and device files in a temporary
  directory), not against a board: that each node and attribute appears on each
  board, and when, is the hardware check (`docs/operations/watchdog.md`,
  `docs/hardware/revpi-connect4.md`). On the production QEMU image the
  runtime lane (`production-runtime-qemu.yml`) runs the whole gate; it was not
  run for this change (no image build was possible).
- Whether a gate that is too strict starts a rollback storm is bounded by the
  design (only a pending OTA's trial boot rolls back), not by the checks.
