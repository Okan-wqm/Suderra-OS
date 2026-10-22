# The /data volume: size and wear

ADR-048 DEC-24. How a production `/data` gets its size, and how the wear of the
disk it lives on is reported. How it is encrypted, sealed and recovered is in
[data-recovery.md](../security/data-recovery.md).

## Growing to the disk

The production images ship `/data` as the last partition, 2 GiB, empty and
unformatted. The device it is flashed to is larger. On the first boot
`systemd-repart` grows the partition to the end of the disk, and only then does
`suderra-data-unlock` format it as LUKS2: nothing is resized under an existing
volume.

* `usr/lib/repart.d/50-data.conf` is the definition; the unit order is in
  `systemd-repart.service.d/10-suderra.conf` (repart runs before
  `suderra-data.service`; its own unit is ordered for the initrd).
* repart matches an existing partition to a definition by its GPT type alone.
  The rootfs and verity partitions carry the generic Linux type, so `/data` has
  one of its own: the UUIDv5 of
  `https://github.com/Okan-wqm/suderra-os/gpt-partition-type/data` in the URL
  namespace (`dfd38caa-c384-51a7-8a94-2446996318c5`), set in the three production
  layouts (`aarch64-rpi4/genimage-prod.cfg`, `aarch64-revpi-connect4/genimage-prod.cfg`,
  `x86_64/genimage.cfg`). A definition for the generic type would be matched to
  the first rootfs slot, which has no free space behind it, and `/data` would not
  grow.
* Only production images carry the definition and the units (`post-build.sh`):
  on a dev image repart would create the partition in any free space.
* repart finds the disk by following the root filesystem through dm-verity to
  its partition and the whole disk (systemd v256, `src/partition/repart.c`,
  `find_root`). Later boots find no free space and change nothing.
* The backup GPT, which genimage writes at the end of the image, moves to the
  end of the larger device.

`tests/image-contracts/data-growth-contract-test.sh` runs the real
`systemd-repart` on a partition table laid out like the production image on a
disk larger than the image, and checks all of this, including that a second run
changes nothing.

Not verified here: a boot of a production image (no image build fits this
environment) and the root-disk discovery on a real dm-verity root.

The minimum eMMC size of a RevPi production unit is an operator decision
(ADR-048 question 6, default 32 GB): bekliyor: operatör.

## Which partition is /data

`/data` is the partition of the disk under the verified root that carries the data
PARTUUID of `board/suderra/common/gpt-partuuids.conf`, and only that one.
The PARTUUIDs are public, so `suderra-disk-layout.service` proves it before
`suderra-data-unlock` runs: exactly one partition of any disk carries the PARTUUID,
and it is on the same disk as the dm-verity root. `suderra-data-unlock` reaches it
through `/run/suderra-os/disk/data` and never through a `/dev/disk/by-partuuid`
link.

If the proof fails (a USB stick, a second disk or a copy of the image carries a
PARTUUID of the layout), nothing is named, nothing is provisioned or opened, and
`suderra-data-unlock` reports a `data-unmountable` alarm whose detail names the
partitions (`journalctl -u suderra-disk-layout.service`, and
`/run/suderra-os/disk/refusal`). The device stays LOCKED until the other disk is
unplugged and the device rebooted; nothing on either disk was written. A disk that
has no data partition at all gets the same alarm (it is not given a new partition).

A blank partition is told from a foreign one by its own signature only (a file
system or a partition table inside it): the partition entry that every GPT
partition has (PARTLABEL, PARTUUID) says nothing about what was written to it.

## Wear telemetry

`suderra-emmc-wear` (timer: three minutes after boot, then daily) reads the
attributes the kernel exposes for each eMMC card, `life_time` and
`pre_eol_info` (Linux `drivers/mmc/core/mmc.c`; the registers are EXT_CSD[267]
to [269], JEDEC JESD84-B51), and writes `/run/suderra-os/emmc-wear.json`
(root only):

```json
{"_type":"suderra.emmc-wear.v1","supported":true,"worst_state":"warning",
 "devices":[{"device":"mmc0:0001","life_time_est_typ_a":2,"life_time_est_typ_b":9,
             "pre_eol_info":1,"life_used_percent_upper_bound":90,"state":"warning"}]}
```

A card is `urgent` at pre-EOL 0x03 or an exceeded life time, `warning` at pre-EOL
0x02 or 80 % used and beyond, `normal` otherwise, `unknown` when it defines
neither. A warning or urgent card is also logged to the journal. A device
without an eMMC (SD card, NVMe, a virtio disk) gets `"supported":false` and an
empty list, which means nothing to report, not that the disk is healthy; the
wear of an x86 NVMe disk (SMART) belongs to the qualification of the x86 model.

The document is not exposed to the agent and not published yet. Both need
`contracts/suderra-edge` to define it (`mutable-state.json` runtime documents, a
schema) and the telemetry channel of DEC-27: the contract is not changed by this
package, so that is reported as needed.
