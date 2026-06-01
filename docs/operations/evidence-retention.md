# Enterprise Evidence Retention

Retention policy is governed by `ci/evidence-contract.yml`.

<!-- suderra-generated: retention-policy -->
- Policy ID: `suderra-enterprise-7y-immutable-evidence`
- Minimum years: `7`
- Store class: `immutable-encrypted-evidence-archive`
- Required replay: `release-input-binding, runtime-suite, hsm-signing-manifest, station-acquisition, scanner-raw-replay, governance-snapshot, publication-manifest`
<!-- /suderra-generated -->

## Requirements

- Retain enterprise release evidence for at least the generated minimum above.
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

The minimum replay set is the generated `Required replay` list above.

Restore tests must read from the retained archive, not the CI workspace that
originally produced the release.

## RC Dry-Run Boundary

`rc-evidence-dry-run` emits a retention plan and production gap report only. It
does not create an immutable archive receipt and does not satisfy restore/replay
proof. GitHub Actions artifacts remain transient handoff storage until a real
retention manifest and archive restore proof are produced by the production
evidence path.
