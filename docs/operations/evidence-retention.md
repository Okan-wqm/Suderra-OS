# Enterprise Evidence Retention

Retention policy is governed by `ci/evidence-contract.yml`:
`suderra-enterprise-7y-immutable-evidence`.

## Requirements

- Retain enterprise release evidence for at least 7 years.
- Store evidence in an immutable encrypted archive class.
- Use KMS-managed encryption keys with access logging.
- Preserve custody chain, legal hold state, and restore history.
- Keep release input bindings, release subject graphs, raw scanner data,
  runtime serial/QMP logs, HSM transcripts, station acquisition events,
  governance snapshots, OTA artifact records, and publication manifests.
- Run restore/replay tests for every required replay listed by
  `evidence_contract.py retention-plan`.

## Manifest

Production-candidate gates require:

```text
release-retention/<version>/retention-manifest.json
```

The manifest schema is `suderra.retention-manifest.v1`. It must bind the same
`version`, `source_sha`, `source_run_id`, policy ID, required export set, and
passed restore/replay tests as the release subject graph. Archive object URIs
must refer to immutable encrypted storage, not transient GitHub Actions
artifacts, and restore tests must prove the restored archive digest matches the
retained archive digest.

## Replay Tests

The minimum replay set is:

- release input binding validation
- production runtime suite validation
- HSM signing manifest/session validation
- station acquisition replay
- scanner raw replay
- governance snapshot validation
- publication manifest validation

Restore tests must read from the retained archive, not the CI workspace that
originally produced the release.
