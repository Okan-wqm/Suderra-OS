# Results: how what root did reaches the cloud

ADR-048 DEC-27. Root's workers record what they did as typed results, and the
agent publishes them, so an install, an update, a rollback or a lockdown leaves
a record in the cloud even though the technician's SSH session, which used to be
the only place they went, ends at lockdown.

## The path

| Step | Who | Where |
|---|---|---|
| write | root: `suderra-installer` (install, update, site config, verify-current, lifecycle, health gate) and the helpers through `suderra-installer result write` (lockdown, data unlock, time state) | `/data/suderra/os/results/<seq, 16 digits>-<kind>.json`, root only, the newest 256 kept |
| mirror | root, in the same call | `/run/suderra/results/` (root:suderra 0750, files 0640): the one directory the agent reads |
| restore | root, every boot, `suderra-results-mirror.service` | the same directory, from the persistent results |
| publish | the agent, `sens-api-gateway/src/results.rs` | `tenants/{tenant_id}/devices/{device_id}/results`, QoS 1, one document per message, byte for byte what root wrote |

The document, its reasons per kind and the topic are the contract's
(`contracts/suderra-edge/v1/schemas/result.schema.json`, `channels.json`
`result_telemetry`). A result is validated against the schema before it is
written, so an invalid one cannot be produced. Results are unsigned observations:
the cloud stores them as device-reported evidence, never as authority.

## Why there is a restore

`/run` is a tmpfs. A reboot empties the mirror while the results stay on `/data`.
The agent republishes what is in the directory until the broker acknowledged it
and keeps only the highest acknowledged sequence number
(`$DATA/state/results-cursor.json`). A result written just before a reboot that
the broker had not acknowledged (the lockdown result, a rollback, an alarm) would
therefore never be published, and a newer result published first would move the
cursor past it for good.

`suderra-results-mirror.service` runs `suderra-installer result mirror` after
`suderra-data.service` and before `suderra-agent.service`. Nothing requires it,
so a failure never keeps the agent, and the control loop it runs, down; the
ordering is the whole point and
`tests/image-contracts/result-mirror-contract-test.sh` holds it.

The command copies the newest 256 persistent results that are valid documents
whose sequence number and kind agree with their file name; a file that is not
one is logged and skipped. The persistent copy is the truth, so a mirrored file
that differs is replaced, and a second run changes nothing. It takes the lock
every writer of the directory takes. Without `/data` (unmounted, or its layout
not applied) there is nothing persistent to restore, and the volatile results
already under `/run` stay: those are the `volatile-<seq>-<kind>.json` files a
result gets while `/data` is not available, numbered by a per-boot counter and
published once per agent process.

## Which scripts may write which reasons

`result write` refuses a reason the schema does not allow for the kind, and a
refused result records nothing. `scripts/ci/check-result-reasons.py` holds every
`result write` of the image, and the literals passed to the shell functions that
forward to it, to the schema, and
`tests/image-contracts/result-reasons-contract-test.sh` shows it fails for each
class of defect (EI-084: suderra-lockdown reported `state-corrupt`, the
lifecycle store's reason, for an open technician path, and nothing was
recorded; the contract's code for that is `provisioning-mode-active`).

## Not published yet

The eMMC wear document `suderra-emmc-wear` writes
(`/run/suderra-os/emmc-wear.json`, DEC-24) has no schema, no runtime-document
entry and no channel in the contract, so nothing publishes it. That needs a
contract change (a runtime document of the OS, its schema, and a topic or a
field of an existing document), not a change here.

## Not verified here

A boot of an image. The unit order and the agent's first pass after a reboot are
checked by unit tests and by `systemd-analyze verify`, not on a booted device, and
no QEMU scenario reboots a provisioned device and reads `/run/suderra/results`
afterwards: the dev-image harness (`tests/qemu/edge-provisioning-e2e.py`) boots
once, and the production-runtime lane observes one boot through the serial
console. That scenario needs a reboot step in the harness first.
