# TPM resource registry

ADR-048 DEC-21. The OS (the LUKS seal, the rollback-floor mirror, the attestation
key) and the agent (keystore, counters, the mTLS key) share one TPM 2.0. Without
a register they collide on persistent handles and NV indices, and a resource one
side creates can be cleared by the other. This page is that register. The block
below is read by `tests/image-contracts/tpm-registry-contract-test.sh`, which
holds the code to it: a handle, an NV index, a PCR or a device that is not
here does not get into the OS.

The agent's constants (`sens-api-gateway/src/keystore/`) belong to the same
ranges; the aquaculture repository holds them to this page with
`sens-api-gateway/tests/invariants/tpm_registry_constants.rs` (ADR-048 DEC-21,
the agent's side of this work), so the two repositories read one register.

## Registry

```json tpm-registry
{
  "registry_version": 1,
  "limits": {
    "persistent_owner": ["0x81000000", "0x817FFFFF"],
    "persistent_platform": ["0x81800000", "0x81FFFFFF"],
    "nv": ["0x01000000", "0x01FFFFFF"]
  },
  "persistent_handles": [
    {"handle": "0x81000001", "owner": "tcg", "suderra_creates": false,
     "purpose": "SRK of the TCG Provisioning Guidance; systemd-cryptenroll seals under it when it exists and under a transient SRK of the same template otherwise"},
    {"handle": "0x81010001", "owner": "tcg", "suderra_creates": false,
     "purpose": "default handle of the RSA endorsement key; the OS reads the EK through a transient object and persists nothing"},
    {"handle": "0x81010002", "owner": "tcg", "suderra_creates": false,
     "purpose": "default handle of the ECC endorsement key"},
    {"range": ["0x817F0000", "0x817F00FF"], "owner": "os", "phase": "P3",
     "purpose": "OS keys; 0x817F0001 is the attestation key of suderra-attestation"},
    {"range": ["0x817F0100", "0x817F01FF"], "owner": "agent", "phase": "P2",
     "purpose": "objects of the agent's TPM keystore (EDGE-MEDIUM-099)"}
  ],
  "nv_indices": [
    {"range": ["0x01500000", "0x015000FF"], "owner": "agent", "phase": "P2",
     "purpose": "keystore: master secret 0x01500016, counter 0x01500017 (sens-api-gateway/src/keystore/tpm_backed.rs)"},
    {"range": ["0x01500100", "0x015001FF"], "owner": "os", "phase": "P3",
     "purpose": "0x01500100 write-once provisioned bit and 0x01500101 monotonic counter of the lifecycle (DEC-12), 0x01500110 mirror of the rollback floor (DEC-3)"}
  ],
  "pcrs": {
    "luks_seal": {"owner": "os", "pcrs": [7]},
    "debug_only": [16],
    "agent_extends": [],
    "extend_sites": [
      {"file": "scripts/evidence/revpi-connect4-board-checks.sh", "pcrs": [16],
       "purpose": "hardware check on the board: PCR 16 only, reset afterwards"},
      {"file": "tests/qemu/guest/data-unlock-scenarios.sh", "pcrs": [7],
       "purpose": "QEMU test with a software TPM: a firmware update that changes PCR 7"}
    ]
  },
  "devices": {
    "os": ["/dev/tpmrm0"],
    "agent": {"P0": [], "P1": [], "P2": ["/dev/tpmrm0"]},
    "never": ["/dev/tpm0"]
  },
  "forbidden_os_commands": [
    "tpm2_changeauth", "tpm2_changeeps", "tpm2_changepps", "tpm2_clear",
    "tpm2_dictionarylockout", "tpm2_evictcontrol", "tpm2_hierarchycontrol",
    "tpm2_nvdefine", "tpm2_nvundefine", "tpm2_nvwrite", "tpm2_setprimarypolicy",
    "systemd-pcrextend"
  ]
}
```

## What each part says

### Where the numbers come from

Verified against the code the images contain:

* The handle spaces: persistent handles are `0x81000000` to `0x81FFFFFF`, the
  platform's persistent handles start at `0x81800000`, and NV indices are
  `0x01000000` to `0x01FFFFFF`
  (tpm2-tss 4.1.3, `include/tss2/tss2_tpm2_types.h`:
  `TPM2_PERSISTENT_FIRST`, `TPM2_PLATFORM_PERSISTENT`, `TPM2_NV_INDEX_FIRST`,
  `TPM2_NV_INDEX_LAST`). The OS and the agent allocate only in the owner's
  half.
* The SRK handle `0x81000001`, the SRK template (attributes
  `NODA|USERWITHAUTH|FIXEDTPM|FIXEDPARENT|SENSITIVEDATAORIGIN|RESTRICTED|DECRYPT`)
  and the seal object of a LUKS key (a keyed-hash object, `FIXEDTPM|FIXEDPARENT`
  and `NODA` unless a PIN is set, under the SRK, falling back to a transient
  SRK) are systemd 256.17's (`src/shared/tpm2-util.h`, `tpm2-util.c`:
  `TPM2_SRK_HANDLE`, `tpm2_get_srk_template`, `tpm2_get_or_create_srk`,
  `tpm2_seal`). The comment there names the TCG TPM 2.0 Provisioning Guidance
  table "Reserved Handles for TPM Provisioning Fundamental Elements" as the
  source of `0x81000001`.
* `0x81010001` and `0x81010002` are the EK handles of the examples in the
  tpm2-tools 5.7 manual (`tpm2_createek`); `0x01500016` is the NV example of
  `tpm2_nvdefine`, which is where the agent's constants come from.

**Not verified: TCG's own sub-allocations.** The TCG "Registry of Reserved TPM 2.0
Handles and Localities" (v1.1,
`https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf`)
could not be read from the host this page was written on (HTTP 429 from
trustedcomputinggroup.org on every attempt, and the Internet Archive copy is not
reachable). The Suderra blocks (`0x817F0000` to `0x817F01FF`, `0x01500000` to
`0x015001FF`) are therefore chosen inside the owner ranges, around the one
constant the agent already ships, and are not proven free of a TCG
reservation. Before the first hardware provisioning that creates an object
(P2 for the agent's keystore, P3 for the OS) someone must check the blocks
against that registry and the platform manufacturer's. This is an open item,
not a finding closed.

### Hierarchies and authorization

At P1 the OS does not assign or change any hierarchy authorization: the owner,
endorsement and lockout auth are empty, and the OS creates no persistent or
NV object (nothing in a shipped script may: see the forbidden commands). The LUKS
seal is a blob in the LUKS header, bound to the TPM and to PCR 7; deleting it
loses nothing the recovery key does not restore
([data-recovery.md](data-recovery.md)).

DEC-21 puts the random owner and lockout auth at P2, together with the agent's
`/dev/tpmrm0`. What this registry records for that step, as the proposal to
implement and not as something implemented: the lockout auth is generated at
provisioning and discarded; the owner auth is discarded too when every OS
resource can be recreated, because the recovery key (DEC-14.3) already covers the
only resource that holds data, so losing the owner auth means a TPM clear plus a
recovery, not a lost device. Anything the OS must keep an auth for is sealed to
the policy of the LUKS seal.

### Dictionary attack

The OS does not change the dictionary-attack parameters (`tpm2_dictionarylockout`
is forbidden). A LUKS seal carries no PIN and its object has `NODA`, so a failed
unseal (a PCR policy that does not match) does not count toward the lockout.

### PCRs

* PCR 7 is the secure-boot policy; the `/data` seal binds it
  (`TPM2_SEAL_OPTIONS` in `suderra-data-unlock`). On x86 the signed PCR 7 + 11
  policy replaces it (DEC-14.1, deferred with the x86 model); on BCM2711 PCR 7 is
  never extended (EI-037).
* PCR 16 is the resettable debug PCR; only the board's hardware check extends it.
* Nothing in a production image extends a PCR (`systemd-pcrextend` is not
  enabled) and the agent never does. The two files that extend one are test
  code and are listed with their PCR.

### Devices

The OS tools use `/dev/tpmrm0`, the resource-managed device. The agent gets no
TPM device until P2 (EDGE-MEDIUM-099), then `/dev/tpmrm0` only, through the
drop-in of a board profile that has the `tpm` feature. `/dev/tpm0`, the raw
device without the resource manager, is never granted to any unit (the packaged
`suderra-firstboot.service` had it; the line is gone).

## Changing it

An entry is added in the same change as the code that uses it, with an owner and
a phase. A range of another owner may not be reused, an OS or agent range may not
overlap another, and an OS script that needs a forbidden command first changes
this page and the DEC-21 decision.

## Tests

`tests/image-contracts/tpm-registry-contract-test.sh` checks that the JSON block
is well formed and inside the TPM's spaces, that no two ranges overlap, that the
LUKS seal's PCRs are the registry's, that no shipped script runs a forbidden
command or extends a PCR outside the registered sites (with the registered PCRs),
and that no unit of `board/`, `package/` or `userspace/` grants `/dev/tpm0`, the
agent's units grant no TPM device before the phase that allows one, and the
OS's units only the registry's.
