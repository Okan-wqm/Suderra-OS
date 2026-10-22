# Recovering an encrypted /data

ADR-048 DEC-14.3, DEC-24, EI-078, EI-037. This page is the contract between the
device (`suderra-data-unlock`), the cloud's escrow and the operators who hold
the offline key. The board-independent part is implemented; what waits for an
operator or for another component is listed in
[What is still missing](#what-is-still-missing).

## The failure it answers

A production `/data` is a LUKS2 volume whose key is sealed to the TPM2 (today
to PCR 7). The seal stops opening when the measured state changes: a firmware
or BIOS update, the 2026 Microsoft CA rotation, a Secure Boot key change, or a
replaced TPM. Before this page the passphrase slot was wiped at provisioning
and there was no way back: the device lost its offline queue and its audit
chain, or an operator re-provisioned it by erasing `/data`.

What the device does now when the seal does not open:

* it never reprovisions: a volume that carries data is never formatted, and
  only a volume that never finished provisioning is blanked;
* it never loops: `suderra-data.service` fails once with a `data-unlock` alarm
  (reason `tpm-unseal-failed`), the lifecycle reads LOCKED, and the device
  waits;
* it waits for the recovery key (below).

## What a production volume carries

| Item | Value |
|---|---|
| Keyslot with the `systemd-tpm2` token | the volume key sealed to the TPM2 (`TPM2_SEAL_OPTIONS` in the script: one place, so x86's signed PCR 7 + 11 policy, DEC-14.1, is one change) |
| Keyslot with the `suderra-recovery` token | a random 256-bit recovery key, written as 64 lowercase hex characters; PBKDF2 with 1000 iterations (a 256-bit random key needs no stretching) |
| Other keyslots | none: the ephemeral provisioning slot is removed, and its removal is unlocked by the recovery key, so the recovery slot is proven before anything depends on it |
| LUKS label | `suderra-provisioning` until the last step of provisioning, then `SUDERRA-DATA` (no label: written by an older image, operational) |
| `/data/suderra/os/recovery-escrow.json` | the escrow envelope (root only, mode 0600) |

The recovery key exists in plain text only in a root-only file under `/run`
(tmpfs) while the script runs, and `suderra-data-unlock` removes it however it
ends. It is never written to `/data`, the rootfs or a log.

## The escrow envelope

```json
{
  "_type": "suderra.data-recovery-escrow.v1",
  "volume_uuid": "<LUKS UUID of the volume>",
  "algorithm": "RSA-OAEP-SHA256",
  "recipient_spki_sha256": "<hex SHA-256 of the DER SubjectPublicKeyInfo of the escrow key>",
  "ciphertext": "<base64 of the encrypted key>"
}
```

* The plaintext is the 64 hex characters, without a newline.
* RSA-OAEP, SHA-256 for the digest and for MGF1, empty label. The escrow key
  is an RSA public key of at least 3072 bits, installed in the signed image as
  `/etc/suderra/recovery-escrow.pub.pem` by `package/suderra-keys` from the
  trust roots (`recovery-escrow.pub.pem`, checked by
  `scripts/ci/validate-trust-roots.sh`). RSA-OAEP is what every HSM offers
  (PKCS#11 `CKM_RSA_PKCS_OAEP`, SHA-256 and MGF1-SHA256).
* The device cannot decrypt it. Only the offline HSM can.

Decrypting it offline (a drill with the dev key; production does this inside
the HSM under the custodians' quorum):

```bash
base64 -d <<< "<ciphertext>" > escrow.ct
openssl pkeyutl -decrypt -inkey recovery-escrow.key \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 -in escrow.ct
```

Provisioning refuses to format anything when the key cannot be escrowed
(missing or invalid escrow key, no `openssl`): a volume without an escrowed
recovery key would be lost at the first firmware update.

The envelope on `/data` is the only copy of the escrow until the cloud has
it. A component that delivers it to the cloud (and records the acknowledgement)
is not part of this package, see below.

## The recovery path

```text
TPM seal fails  ->  alarm tpm-unseal-failed, LOCKED, device waits
recovery ingress verifies the signed authority and the physical presence,
  places the decrypted key at /run/suderra-os/data-recovery.key (root, 0600)
suderra-data-recovery.path  ->  suderra-data-recovery.service
  suderra-data-unlock recover
  reboot
```

`suderra-data-unlock recover` (production images only):

1. consumes the key file at once, so a rejected key is never retried by the
   path unit that saw it, and normalizes it (case, separators and newlines are
   ignored; it must be 64 hex characters);
2. checks the key against the recovery slots only, with tokens disabled: a
   volume whose TPM still unseals must not accept a wrong recovery key, and
   the TPM slot is not a recovery key;
3. opens the volume with it and mounts `/data` (no layout, no binds);
4. adds a new recovery slot with a new key and stores its envelope on `/data`:
   the key that people just handled is replaced first;
5. wipes the old TPM2 seal and seals the volume to the TPM2 for the state of
   today (the old seal is wiped first: systemd-cryptenroll does nothing when
   the same PCR set is already enrolled, which is also the case after a TPM was
   replaced and the PCR values are the same);
6. removes the old recovery slots and tokens;
7. releases the volume, records an ok `data-unlock` result whose detail says
   what happened, and the unit reboots, which also proves the new seal.

Any failure releases the volume, records an alarm (`tpm-unseal-failed` for a
key or seal problem, `data-unmountable` for a volume problem), and leaves the
volume openable by the old recovery key. Run it again: it removes the slot a
failed run left. It refuses a volume that is already open, a partition that is
not an operational LUKS volume, and never formats.

A recovery key that was decrypted is burned. After a recovery, the cloud holds
the new envelope once the delivery component sends it; until then the old key
is dead and the new key is escrowed only on the device.

## Operating it

1. A device reports `data-unlock` alarm `tpm-unseal-failed` (the cloud shows it
   as LOCKED with that reason).
2. The operator asks for the recovery: the custodians (2 of 3, DEC-3.11) open
   the escrowed envelope of that device's volume UUID in the HSM.
3. A technician is at the device with the signed recovery authority; the
   recovery ingress verifies it and places the key. The device recovers and
   reboots.
4. The result `data-unlock ok` ("recovered with the escrowed key") appears, and
   the cloud stores the new envelope.

## What is still missing

Nothing here is guessed; each item has an owner outside this package.

| Item | Why it waits |
|---|---|
| Production escrow key | The offline RSA key is generated at the key ceremony (an operator action, ADR-048 question 9: HSM, 2-of-3 custodians, two physical locations). Until `recovery-escrow.pub.pem` is in the production trust roots, no production image can be built. bekliyor: operatör |
| Recovery ingress | Something root-owned must verify a signed recovery authority and the physical presence (RevPi button or console, x86 console; DEC-16, DEC-18.2) and place the key. The signed statement needs a contract definition (a `data-recovery` purpose of `suderra.device-lifecycle.v1`, or its own statement) before it can be verified; the USB ingress (`suderra-installer ingress`, DEC-18.2) is the natural carrier. Until it exists the path is inert on a production device. |
| Delivery of the envelope | The cloud must receive `recovery-escrow.json` (with the activation request, or its own request) and acknowledge it; the activation should wait for that. The envelope and its transport are not in `contracts/suderra-edge/v1`, so they need a contract definition. The cloud side is `apps/sensor-service/src/edge-device/recovery-key-escrow.service.ts`. |
| Result reasons | `data-unlock` allows `data-unmountable`, `io-error` and `tpm-unseal-failed`. The script cannot say "no TPM" or "recovered" with a reason of its own; a `tpm-unavailable` reason and a `recovered` outcome would make the cloud's alarm precise. |
| x86 signed policy | The seal is PCR 7 today. The signed PCR 7 + 11 policy (DEC-14.1) waits for the x86 model; `TPM2_SEAL_OPTIONS` is the one line it changes, and the re-seal after a recovery uses it. |
| Hardware | The recovery runs here against an swtpm in QEMU. A real TPM seal and unseal on a board, and a real firmware change, are hardware checks. |

## Tests

`tests/qemu/data-unlock-vm-test.py` runs the real script in a QEMU guest with
an swtpm, and `tests/qemu/data-unlock-scenarios.sh` drives it:

* provisioning, with the recovery slot, the envelope opened by the test's
  escrow key and the key proven to unlock the volume;
* recovery after PCR 7 changed: the old key is dead, the new envelope's key
  unlocks the volume, the next boot unseals with the new seal, the data is
  intact;
* a wrong key (also while the TPM still unseals), a malformed key and no key
  change nothing and are consumed;
* an escrow failure formats nothing;
* a recovery whose re-seal fails keeps the old key working, and a second run
  cleans up;
* recovery refuses an open volume and never formats a blank or foreign
  partition.

`tests/image-contracts/data-luks-provision-contract-test.sh` states the static
rules (one place for the TPM policy, no key material outside `/run`, the escrow
parameters) and `tests/image-contracts/ci-keyring-contract-test.sh` the escrow
key's presence and strength in the trust roots.
