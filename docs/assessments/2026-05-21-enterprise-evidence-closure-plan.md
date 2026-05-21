# 6-Agent Revised Enterprise Evidence Closure Plan

Date: 2026-05-21

This is the current enterprise closure plan after the second six-agent attack
against the evidence architecture. It replaces ad hoc gap lists for the work
below. The active baseline stays non-production: `production_ready=false`
remains closed until every production gate here has executable evidence.

## Implemented In This Pass

- Promotion QEMU input moved to `suderra.qemu-acceptance.v4` with explicit
  termination and `failure_class`; v3 remains archive-only.
- Final release evidence initially moved to `suderra.release-evidence.v4` and preserves
  QEMU execution/check detail instead of relying only on a passed-check list.
- Release ingress schema roles now bind QEMU v4 and release evidence v4.
- Publication proof uses a second-stage
  `suderra.release-publication-proof-manifest.v1` so post-publication proof
  assets do not mutate the signed base publication manifest.
- Build workflow OIDC/attestation permissions are no longer top-level; only
  attesting jobs receive them.
- `SOURCE_DATE_EPOCH` supplied by release workflow is honored by
  `scripts/build-in-docker.sh`.
- `suderra_qemu_x86_64_prod_ab_defconfig` and matrix metadata define a
  non-public production-runtime QEMU A/B lane; it is blocked from release until
  Secure Boot, dm-verity, RAUC, HSM, and runtime negative tests are real.
- Production variant now forces `SUDERRA_SIGNING_MODE=prod` in post-image.
- Machine verification moved to `suderra.machine-verification.v3` for
  promotion evidence. DSSE records must now bind predicate type, builder ID,
  source repository/ref/run ID/run attempt/source SHA, and materials; v2 remains
  archive-only.
- Raw attestation JSON is preserved inside final evidence and second-stage
  publication proof assets so replay can compare the DSSE statement, not only a
  transcript line.
- Strict station registry trust moved to
  `release-governance/<version>/station-registry.json`; final evidence records
  the registry source domain and release-ready validation rejects lab-owned
  station registries.
- Release workflow now downloads governance evidence before strict lab
  validation and binds machine/post-publication verification to the tag target
  source commit rather than the event SHA.
- Production RAUC signing now has a real PKCS#11/HSM path: production scripts
  reject file-backed private keys, require `SUDERRA_RAUC_PKCS11_URI`,
  `SUDERRA_RAUC_SIGNING_CERT`, and validated
  `suderra.hsm-signing-session.v1` evidence before invoking RAUC. This was
  superseded by v2 in the continuation below.
- Security reports now preserve raw scanner/check-run input bytes with digest,
  size cap, and replay binding in final evidence.
- QEMU semantic collection now records Secure Boot state, dm-verity table, RAUC
  status, `/data` encryption state, and anti-rollback floor. The
  `production-runtime` profile rejects evidence until corresponding negative
  behavior checks pass.
- Station registry validation now rejects expired calibration in strict profiles
  and requires operator role metadata.

## Required Next Closure Work

- A real protected station registry publication path is still required:
  branch-protected registry changes, reviewer ownership, calibration lifecycle,
  and operator rotation must feed `release-governance/<version>/station-registry.json`.
- Strict lab evidence must come from station adapters, not hand-authored JSON.
- Real HSM ceremony/runbook and hardware-backed operator process must be added
  around the implemented PKCS#11 signing path before production use.
- Production-runtime QEMU still needs the executable scenario runner that
  performs enrolled OVMF Secure Boot booting, dm-verity tamper, RAUC A/B
  rollback, typed health-gate, `/data` LUKS/swtpm, and edge activation
  transactions. The validator now blocks production-runtime without those
  checks.
- Raw scanner preservation is implemented for CI check-run security reports;
  OS/rootfs scanner raw outputs must follow the same evidence schema when those
  scanners move into release preflight.

## Non-Negotiable Gates

- No broad allowlist or warning suppression may stand in for real evidence.
- Alpha/lab publication crypto closure is allowed only with explicit
  non-production language.
- Production-ready language is blocked until HSM-backed signing and executable
  runtime behavior evidence are both present.
- Every future phase must update operator runbooks, exact commands, expected
  files, failure modes, and recovery steps in the same change set.

## 2026-05-21 Implementation Continuation: Enterprise Evidence Producers

The third implementation pass closed the largest validator/producer mismatch
found by the six-agent review. The system now has first-class producer and
validator surfaces for the evidence that was previously only described as a
future gate.

- Final release evidence moved to `suderra.release-evidence.v5`. The schema now
  preserves `runtime_qemu`, `hsm_signing_sessions`, `station_acquisitions`, and
  `release_image_scan_reports` as top-level evidence, while v4 remains
  archive-only legacy input.
- Production-runtime QEMU now has
  `suderra.qemu-production-runtime-suite.v1` and a scenario runner entrypoint.
  The suite requires signed boot, Secure Boot rejection, cmdline tamper,
  dm-verity tamper, RAUC good/bad/rollback, anti-rollback, and `/data`
  LUKS/swtpm scenarios with per-scenario raw log digests.
- QEMU semantic collection is enabled for QEMU defconfigs regardless of prod/dev
  variant so the non-public `qemu-x86_64-prod-ab` lane can emit production
  runtime facts.
- Production HSM evidence moved to `suderra.hsm-signing-session.v2`.
  Production validation rejects legacy v1, SoftHSM/software-token metadata,
  missing challenge-response data, missing token/key attributes, and missing
  artifact-role bindings.
- `scripts/production-artifacts.sh` no longer treats `pkcs11:` as an
  unimplemented placeholder. Secure Boot, GRUB, UKI sidecars, and image
  sidecars now route PKCS#11 signing through a configured engine/provider path
  and validate HSM v2 evidence before signing.
- RAUC production signing now requires device keyring verification in both
  bundle creation and resigning paths.
- Scanner-native raw replay is implemented as
  `suderra.release-security-report.v2`. It binds reports to subjects, scanner
  DB identity, raw JSON bytes, and recomputed severity counts; check-run
  summaries remain legacy orchestration evidence.
- Station adapter acquisition now has `suderra.station-acquisition.v1`, which
  executes adapter commands and records argv, exit code, stdout/stderr digests,
  station registry digest, artifact digest, and required adapter roles.

Remaining production blockers are operational, not schema placeholders: a real
HSM ceremony, real station adapter plans for the lab, and real QEMU scenario
plans must be run and preserved before any `production_ready=true` change.
