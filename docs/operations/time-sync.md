# The clock: NTS time, the time floor and `/run/suderra/time-state`

ADR-048 DEC-7 (EI-046, EI-052, EDGE-MEDIUM-077). Where the device's time comes
from, what it is allowed to read, and how the agent and the root installer learn
whether to trust it. Everything below is checked by
`tests/image-contracts/time-sync-contract-test.sh` and
`tests/image-contracts/time-state-helper-test.sh`.

## What the clock is

A signed statement is valid between `not_before` and `expires_at`; a command
envelope is fresh for a few minutes; a TLS certificate has a validity period.
All three are judged against the system clock, and a board without a usable RTC
starts every boot at epoch. So the clock has three parts:

1. **A floor**, applied before anything reads the clock: the clock never reads
   less than the build time of the image or the last good time saved on `/data`.
2. **Authenticated synchronization**: chrony, with NTS, to pinned servers.
3. **A document** that says which of these the clock has reached, written by
   root and read by the agent (which cannot call `adjtimex` under
   `ProtectClock=true`) and by the installer.

Units, in boot order: `suderra-timefloor.service` (applies the floor, saves it at
shutdown) → `chrony.service` → `suderra-chrony-wait.service` (the bounded wait,
before `time-sync.target`) and `suderra-time-state.service` (the document, every
15 s). `suderra-timefloor.timer` saves the floor hourly. The agent and the
provision worker order themselves after `time-sync.target` and `Want=` it;
nothing `Require=`s it.

## `/run/suderra/time-state`

`suderra.time-state.v1` (`contracts/suderra-edge/v1/schemas/time-state.schema.json`),
root:suderra 0640, rewritten every 15 s. A reader treats an absent, unreadable or
non-conforming document, and one whose `updated_at` is more than 120 s from its
own clock, as `unsynced` (`channels.json` `time`).

| `state` | Meaning |
|---|---|
| `synced-nts` | chronyd is synchronized, inside the limits below, and every source it combines is NTS-authenticated |
| `synced-unauthenticated` | synchronized, and a source it combines is not NTS (only a signed site policy can add one, DEC-7.1; none can be selected on this image yet) |
| `unsynced` | everything else, including a clock that only passed the floor |

`suderra-time-state` decides "synchronized", the wait uses the same decision, and
nothing else does: chronyd's leap status is not `Not synchronised`; the reference
is a real source (not reference id 0 and not chrony's `LOCAL`); it has a reference
time; the root distance (root dispersion plus half the root delay, which chrony
grows with the time since the last update) is at most 3 s, which is chrony's own
`maxdistance`; and the clock is within 1 s of what chrony would correct it to and
of its selected source, which is the `makestep` threshold. A clock chrony's
`maxchange` refuses to correct is therefore never reported as trusted.
`offset_ms` is chrony's "Last offset" in milliseconds, positive when the system
clock is ahead of its source.

Both `synced-nts` and `synced-unauthenticated` are enough for root to accept a
statement and for the agent to act on a command; `unsynced` is not
(`clock-unsynced`, retryable). Local control, safe-state and alarms never wait
for the clock.

## The sources

`etc/chrony.conf` pins three servers by host name, because NTS verifies the
server's certificate for the name and an address would be no pin:

| Host | Operator | Source |
|---|---|---|
| `ptbtime1.ptb.de`, `ptbtime4.ptb.de` | PTB (Braunschweig, Berlin) | `https://zeit.ptb.de/files/ptb-ntp-services.json`: NTS-KE tcp/4460, NTP udp/123, TLS 1.3, Let's Encrypt |
| `time.cloudflare.com` | Cloudflare | `https://github.com/cloudflare/cfnts` (NTS-KE default port 4460); Cloudflare's pages do not state the NTP port its server names during NTS-KE, so whether the firewall admits it is observed at hardware bring-up and the two PTB servers carry the clock meanwhile |

Netnod's NTS servers answer NTP on udp/4123, which the firewall does not open
(`https://www.netnod.se/node/204822`), so none is pinned. NTS-KE can also name
another NTP server or port; a server that does is refused by the firewall, and
the contract test refuses a `server` line with `ntsport`, `port` or `key`.

The rules, each a line of that file: only `nts` sources, `authselectmode
require` (a plain source is never selected), `makestep 1.0 1` (the first clock
update after chronyd starts may step the clock, every later one slews),
`maxchange 1000 1 -1` (a later update larger than 1000 s is ignored forever,
because giving up would make the next start a first update, and a first update
steps), `rtcsync`, drift and NTS cookies under `/var/lib/chrony` (the bind of
`/data/suderra/os/chrony`, so a reboot needs no new NTS-KE), no NTP server port,
no UDP command port.

chronyd runs as the `chrony` user with `CAP_SYS_TIME` and nothing else, never as
root (`chrony.service`, modelled on chrony's own `chronyd-restricted.service`).
The rulesets let NTP (udp/123) and NTS-KE (tcp/4460) out for that user and for
no other process.

### Replacing the pinned servers

Edit the three `server` lines of `etc/chrony.conf` and run the contract test. A
replacement must serve NTS-KE on tcp/4460 and NTP on udp/123, with a certificate
a Mozilla root vouches for (the image's CA bundle is the trust store).

## The time floor

`max(build time, last good time)`. The build time is `usr/lib/suderra/build-epoch`,
written by `post-build.sh` from `SOURCE_DATE_EPOCH`; the last good time is
`/data/suderra/os/time/floor`, one decimal number, root-only.

* `floor-apply` (boot, before chronyd) raises the clock to the floor and
  records the floor and the uptime it did so at.
* What is saved is only a time that cannot have come from a wrong clock: the
  synchronized clock itself, or the applied floor plus the uptime since (what
  `fake-hwclock` saves on a board without an RTC), never the wall clock of an RTC
  that may have been reset. Saves happen at the first synchronization of a boot,
  hourly, and at shutdown; a save only raises the floor. A power cut sets a board
  without an RTC back by at most an hour of what it knew.
* An authenticated clock found below the floor means the floor was ahead of the
  real time: the persisted floor is lowered to it and a `clock-below-floor` alarm
  result is recorded. That is the only way a wrong floor heals.
* On a board with an RTC, a boot with the clock more than 15 minutes behind the
  floor (the kernel copies the time to the RTC every 11 minutes) records the same
  alarm: the RTC lost its time. An RTC that is ahead of the real time is not
  caught at boot, because it is above the floor; the first NTS update steps the
  clock back, `logchange 1.0` puts the step in the journal, and the floor is
  lowered only by the rule above.

Results (kind `time-state`, via `suderra-installer result write`), once per
boot each: an alarm `clock-unsynced` when the wait ends unsynchronized, an alarm
`clock-below-floor` as above, and an `ok` when the clock synchronizes after a
`clock-unsynced` alarm.

## The wait

`suderra-chrony-wait.service` makes at most 30 checks 2 s apart (a minute) and
then lets boot go on: the agent, and with it local control, starts after
`time-sync.target`, so the wait is a delay of every boot without a network. Its
exit status is success either way; `TimeoutStartSec=90s` bounds a wedged
`chronyc`, and a unit killed by it fails without failing anything else.

## RTC per board

| Board | RTC | Kernel | Device tree |
|---|---|---|---|
| `revpi-connect4` | PCF2129 on I2C1, address 0x51 | `RTC_DRV_PCF2127=y`, hctosys, systohc | KUNBUS's `revpi-connect4` overlay, merged into the signed FIT's tree |
| `rpi4-cm4` (CM4 IO Board) | PCF85063AT on the VideoCore I2C bus (i2c-10), address 0x51, CR2032 socket (`https://datasheets.raspberrypi.com/cm4io/cm4io-datasheet.pdf`, 2.13) | `RTC_DRV_PCF85063=y`, hctosys, systohc | the stock `bcm2711-rpi-cm4-io.dts` has the node; the bus needs `dtparam=i2c_vc=on` |
| `qemu-x86_64`, x86 IPCs | CMOS clock | `RTC_DRV_CMOS=y` | none |

The kernel symbols are enforced by the `rpi-rtc`, `revpi-rtc` and `x86-rtc`
capabilities of `scripts/ci/check-kernel-config.py`.

**Open: the rpi4-cm4 production image has no RTC.** In production U-Boot hands the
kernel the device tree of the signed FIT, not the one the firmware builds from
`config.txt`, so the `dtparam=i2c_vc=on` of the dev image's `config.txt` never
reaches the kernel there (`board/suderra/aarch64-revpi-connect4/board-boot.conf`
explains why; EI-024, EI-029). A production rpi4-cm4 image needs a
`board-boot.conf` with an overlay that enables the bus, merged by `fdtoverlay`
like the Connect 4's. Until then that board's only clock before its first NTS
synchronization is the floor.

## Operator decisions and known limits

* **The server list** above is a default chosen from operators with published
  NTS-KE and NTP ports; the operator may replace it (one file).
* **`nocerttimecheck` is not set.** chrony offers it for computers that start with
  a wrong clock, and warns that it "has important security implications and
  should be used only as a last resort". Without it, a board without an RTC
  whose image is older than the validity start of its NTS server's certificate
  (the build time is its floor) cannot establish NTS-KE until it has a newer
  floor, for example from a newer image. With it, the certificate time checks
  are off for the first clock update, and a server certificate that chains to a
  trusted root but is expired could set that first time. Turning it on is a
  one-line change and an operator's call.
* **Name resolution.** The pinned servers are host names, and the images ship no
  resolver: `/etc/resolv.conf` is a link to `/run/resolv.conf`, which nothing
  writes (`BR2_PACKAGE_SYSTEMD_RESOLVED` is off in every defconfig and networkd
  does not write it). Until the images resolve names (DEC-11.5), chrony cannot
  reach any of them.
* **Destinations.** The rulesets scope NTP and NTS-KE to the chrony user and to
  the two ports; they do not yet restrict the destination addresses, which
  belongs in the per-UID destination set of the typed site renderer (EI-059).
* **Sites that block udp/123** need a site NTS server (`time_sources` of the
  signed site policy, rendered by the P2 renderer) or lose freshness-dependent
  actuation, as DEC-7.5 accepts.
* **`minsources` stays 1**, so a site that reaches only its own NTS server
  synchronizes; one authenticated server decides the clock.

## Looking at a device

```
cat /run/suderra/time-state
chronyc -h /run/chrony/chronyd.sock tracking
chronyc -h /run/chrony/chronyd.sock -n sources
chronyc -h /run/chrony/chronyd.sock -n authdata    # Mode NTS, cookies > 0
journalctl -u chrony -u suderra-chrony-wait -u suderra-timefloor -u suderra-time-state
cat /data/suderra/os/time/floor
```
