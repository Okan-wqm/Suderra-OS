# Release Evidence

Every release candidate must have one evidence bundle per target:

```text
release-evidence/<version>/<target>/evidence.json
```

`evidence.json` is the canonical release evidence index. It records the target
contract, build source, artifact hashes, signatures, provenance, SBOM/VEX,
reproducibility, security scans, QEMU or hardware acceptance, runtime checks,
approvals, residual risk, and the final release decision.

Use the stdlib-only harness:

```bash
python3 scripts/evidence/release-evidence.py generate \
    --version v1.0.0 \
    --target rpi4

python3 scripts/evidence/release-evidence.py validate \
    release-evidence/v1.0.0/rpi4/evidence.json

python3 scripts/evidence/release-evidence.py validate \
    --require-pass \
    --check-files \
    release-evidence/v1.0.0/rpi4/evidence.json
```

The generator creates a valid but blocked skeleton. A release gate should use
`--require-pass --check-files`; this requires the referenced files to exist
inside the same target bundle and requires all mandatory evidence to be passed.

## Schema

Required top-level fields:

| Field | Purpose |
|---|---|
| `schema_version` | Must be `suderra.release-evidence.v1`. |
| `version`, `target` | Must match the bundle path components. |
| `target_contract` | Snapshot from `ci/build-matrix.yml`. |
| `source` | Repository, tag, commit, clean/dirty state, and CI run ID. |
| `artifacts` | Release artifacts, hashes, byte counts, signatures, and provenance. |
| `sbom`, `vex` | CycloneDX SBOM and OpenVEX status when applicable. |
| `reproducibility` | Independent rebuild comparison and logs. |
| `security_scans` | Reports listed by the build matrix. |
| `qemu` | QEMU boot and application evidence for QEMU targets. |
| `hardware` | Board serial logs and hardware acceptance results. |
| `runtime_checks` | `dm_verity`, `rauc`, `lockdown`, `nmap`, and `systemd_security`. |
| `approvals` | Release-owner or security approvals. |
| `residual_risk` | Accepted or blocking residual risk records. |
| `release_decision` | `blocked`, `approved`, or `approved_with_residual_risk`. |

The script is the authority for strict field validation:

```bash
python3 scripts/evidence/release-evidence.py schema
```

## QEMU Evidence

For a target with `qemu_test: true`, collect at minimum:

- QEMU command line and boot log.
- Kernel and systemd boot completion log.
- Application startup log.
- Exit status from the QEMU acceptance test.

Store logs under the target bundle, for example:

```text
release-evidence/v1.0.0/qemu-x86_64/qemu/boot.log
release-evidence/v1.0.0/qemu-x86_64/qemu/app-startup.log
```

Then set:

```json
"qemu": {
  "required": true,
  "status": "passed",
  "logs": ["qemu/boot.log", "qemu/app-startup.log"],
  "checks": ["boot", "app-startup"]
}
```

## Hardware Evidence

Production hardware targets require at least one representative device record.
The evidence bundle should include:

- Board model, serial number, operator, and test timestamp in the device record.
- Serial console boot log.
- Flash or install transcript, including readback or hash verification when
  applicable.
- `dmsetup table` or equivalent dm-verity proof.
- `rauc status` or bundle verification output when RAUC is in scope.
- Lockdown or secure boot status.
- External `nmap` report.
- `systemd-analyze security` output.

Example structure:

```text
release-evidence/v1.0.0/rpi4/hardware/pi4-serial.log
release-evidence/v1.0.0/rpi4/runtime/dm-verity.txt
release-evidence/v1.0.0/rpi4/runtime/rauc-status.txt
release-evidence/v1.0.0/rpi4/security/nmap.xml
release-evidence/v1.0.0/rpi4/security/systemd-security.txt
```

`--require-pass` requires the aggregate hardware status to be `passed`, at
least one device entry, and all required runtime checks to have passed evidence
files.

## Residual Risk

The default decision is fail-closed:

```json
"release_decision": {
  "status": "blocked",
  "decided_by": null,
  "decided_at": null,
  "rationale": "Evidence has not been reviewed."
}
```

Use `approved` only when there is no accepted residual risk. Use
`approved_with_residual_risk` only when the release owner explicitly accepts
time-bound risk in `residual_risk`:

```json
"residual_risk": {
  "status": "accepted",
  "accepted_by": "release-owner@example.com",
  "accepted_at": "2026-05-13T00:00:00Z",
  "expires_at": "2026-06-13T00:00:00Z",
  "items": [
    {
      "id": "RR-001",
      "severity": "medium",
      "description": "One hardware variant has manual readback evidence only.",
      "mitigation": "Limit rollout to approved serial range until automated readback lands.",
      "owner": "release-owner@example.com",
      "ticket": "SEC-001"
    }
  ]
}
```

Residual risk does not make missing required evidence pass. It records an
explicit release-owner decision after the required evidence has been collected.
