# Release Operations Plan Review

Date: 2026-05-19
Reviewed HEAD: `f3bc2e54b0af76c9aea7842632e61f457c05c3da`

## Verdict

The current release plan is directionally correct, but it is not yet
enterprise-grade. The strongest parts are the fail-closed validators, matrix as
source of truth, release byte binding attempt, governance policy validator, and
strict lab/QEMU schemas. The weak part is operational integration: several
required evidence streams have no trustworthy ingress path, no producer, or no
portable signed bundle after publication.

Do not treat a technical dry run, a successful tag workflow, or a draft GitHub
Release as enterprise release evidence until the P0 findings below are closed.
Residual risk may not waive these gaps because the problem is missing proof, not
accepted product risk.

## Implementation Update

This review records the gaps at the reviewed HEAD above. Subsequent
implementation changed the release path to publish a signed
`release-evidence-<version>.tar.zst` archive, removed loose
`release-evidence-generated/**/*.json` files from GitHub Release publication,
added a validated `release-publication-manifest.json`, and bound the tag
workflow to structured signed-tag preflight metadata.

## Severity Findings

### P0-1: Published release evidence is not a portable signed evidence bundle

Impact: An external reviewer cannot reconstruct or validate the evidence that CI
validated with `--check-files`.

Evidence:

- `.github/workflows/release.yml` assembles `release-evidence-generated/` with
  copied release artifacts, logs, governance snapshots, machine-verification
  logs, QEMU logs, hardware logs, security reports, and `evidence.json`.
- The publish job uploads `signed-release/release-evidence-generated/**/*.json`
  only. Non-JSON files referenced by `evidence.json` are omitted from the GitHub
  Release.
- The evidence tree is generated after release asset signing. The evidence JSON
  and evidence tree are not themselves archived, signed, or attested as a single
  immutable bundle.

Why this is not enterprise-grade:

- `evidence.json` contains relative paths whose referents are absent from the
  public release asset set.
- A 30-day workflow artifact is not a release evidence archive or a 7-year
  retention control.
- The evidence index is mutable in practice unless its complete byte set is
  signed and published.

Required fix:

- Create `release-evidence-<version>.tar.zst` or one archive per target after
  final validation.
- Include the complete generated evidence tree, not only JSON files.
- Add a post-signing publication manifest covering every public release asset,
  signatures, certificates, evidence archives, release notes, and attestations.
- Cosign-sign and attest the evidence archive itself, then publish
  `.tar.zst`, `.tar.zst.sig`, and `.tar.zst.cert`.
- Update `docs/operations/verify-release.md` so customers verify the evidence
  archive before validating `evidence.json --check-files`.

No easy escape: Uploading more loose JSON files is insufficient; the unit of
review must be an immutable signed archive with complete referenced files.

### P0-2: Release-candidate evidence ingress is undefined and likely unusable

Impact: Operators have no controlled path to supply lab, security,
reproducibility, approval, and governance audit evidence to
`Release Preflight`.

Evidence:

- `release-preflight.yml` checks out the source SHA, creates
  `release-inputs/<version>/release-candidate.json`, collects governance, then
  validates local `release-lab-input/`, `release-approvals/`,
  `release-security/`, and `release-reproducibility/`.
- There is no workflow input for a signed evidence bundle, no artifact download
  from a lab/security producer run, and no documented transfer path from the
  technical dry-run skeleton to release-candidate preflight.
- Committing private lab logs, raw security reports, or approvals into the repo
  would be the accidental path, but the docs do not state it and that path is
  operationally wrong.

Why this is not enterprise-grade:

- A release operator cannot tell where to put private evidence or how CI should
  trust it.
- There is no signature, digest manifest, uploader identity, expiry, or source
  binding for externally collected evidence.
- The current dry-run profile creates skeletons but does not provide a
  promotion path to a candidate bundle.

Required fix:

- Add a signed evidence ingress bundle format:
  `release-ingress/<version>/ingress-manifest.json` plus evidence payloads.
- Sign the ingress bundle with an approved lab/security/governance identity.
- Add `Release Preflight` inputs for an ingress artifact run ID or release asset
  URL plus expected digest.
- Validate bundle signature, uploader identity, `version`, `source_sha`,
  `source_run_id`, Buildroot SHA, matrix digest, path safety, non-placeholder
  values, and file digests before validating individual schemas.
- Keep lab/security data out of the repo unless it is intentionally public test
  fixture data.

No easy escape: Telling operators to "populate the directories" is not a
procedure. The plan needs a machine-verifiable ingress contract.

### P0-3: Governance evidence collection requires an audit log that workflows do not provide

Impact: Release-candidate preflight and tag release governance validation should
fail closed in normal GitHub Actions execution.

Evidence:

- `collect-governance.py` writes `audit-log.json` with `status:
  not_collected` unless `SUDERRA_GOVERNANCE_AUDIT_LOG` points to a prepared
  audit snapshot.
- `validate-governance.py` requires `audit-log.json` to have `status:
  collected`, `events_sha256`, and no unapproved governance changes.
- `release-preflight.yml` and `release.yml` call `collect-governance.py`
  without setting `SUDERRA_GOVERNANCE_AUDIT_LOG`.

Why this is not enterprise-grade:

- The docs correctly say governance fails closed when an audit log is not
  collected, but the workflow has no way to collect or inject one.
- The release operator lacks a runbook for lookback window, event filter,
  approver, storage, and signing of the audit snapshot.

Required fix:

- Define `suderra.audit-log-snapshot.v1` completely, including lookback start,
  lookback end, source API, actor filter, event count, redaction policy, and
  SHA-256 of raw events.
- Add a governance evidence producer run using a GitHub App or PAT with the
  required audit permissions.
- Feed that signed snapshot through the release ingress bundle.
- Make the workflow fail with a clear remediation message when the audit bundle
  is absent.

No easy escape: A placeholder audit JSON with `unapproved_governance_changes:
false` is not audit evidence.

### P0-4: Preflight byte binding conflicts with non-deterministic CI trust roots

Impact: The release workflow can rebuild bytes that differ from the preflight
Build run, causing binding validation to fail or forcing operators to weaken the
gate.

Evidence:

- `prepare-ci-keyring.sh` generates ephemeral CI/lab keys and certificates.
- The Build workflow and Release workflow use different storage roots and run
  `prepare-ci-keyring.sh` independently.
- `validate-release-artifact-binding.py` compares staged release image,
  manifest, and payload signature digests against the source Build run.
- USB installer payload manifests and signatures are key-dependent, and target
  images may embed trust-root material.

Why this is not enterprise-grade:

- A byte-for-byte release binding gate cannot depend on freshly generated keys.
- The plan claims meaningful source-run binding but the implementation rebuilds
  with new signing material.

Required fix:

Choose one release model and make it explicit:

1. Promotion model: the tag workflow promotes the exact Build artifacts that
   preflight bound, then signs/attests those bytes without rebuilding images.
2. Rebuild model: the signed ingress bundle contains the exact trust-root/key
   bundle, timestamps, tool versions, and build inputs needed to reproduce the
   preflight bytes; both Build and Release use that same immutable input set.

For alpha, the promotion model is simpler and more auditable. For production,
the rebuild model is acceptable only after HSM-backed signing inputs are
represented by stable public verification material and recorded key ceremony
evidence.

No easy escape: Do not delete digest comparison to make releases pass. Fix the
source of nondeterminism or promote the exact bound bytes.

### P0-5: Production/GA preflight path is internally inconsistent

Impact: A future production release cannot satisfy the documented pre-tag
preflight path without changing code.

Evidence:

- `release-preflight.yml` rejects `profile=release-candidate` for non-prerelease
  SemVer tags.
- `prepare-release-inputs.py` has the same restriction.
- `release.yml` always searches for an artifact named
  `release-preflight-release-candidate-<version>-<source_sha>` for the tag
  being published, including GA tags.
- `release-lifecycle.md` tells operators not to tag until that release-candidate
  preflight artifact exists.

Why this is not enterprise-grade:

- Alpha and production tracks are not represented as separate preflight
  contracts.
- The production path is blocked by a profile naming/version constraint rather
  than by explicit production controls.

Required fix:

- Add a `production-candidate` preflight profile, or allow
  `release-candidate` for GA and derive the tier from SemVer.
- Require production-only controls in the production profile:
  HSM/prod key evidence, signed VEX, dm-verity, secure boot, RAUC, rollback,
  hardware coverage, support-period, release notes, and two-person approval.
- Update artifact names so alpha and production preflight artifacts cannot
  shadow each other.

No easy escape: Calling a GA bundle `release-candidate` while rejecting GA tags
in the preflight generator is not a production plan.

### P0-6: Approval and release-decision input contracts are split-brain

Impact: Preflight can accept an approval file that final release evidence later
rejects, leaving operators with late failures and unclear remediation.

Evidence:

- `validate-release-inputs.py` validates `release-approvals/<version>/<target>.json`
  by checking top-level `status: approved`, `approver`, and `approved_at`.
- `release-evidence.py assemble-release` only populates final `approvals` when
  the approval JSON contains an `approvals` list, and only populates
  `release_decision` when it contains a `release_decision` object.
- `release-evidence.py validate --require-pass` requires a non-empty
  `approvals` list and `release_decision.status` of `approved` or
  `approved_with_residual_risk`.
- The docs do not define the release approval input schema operators must
  write.

Why this is not enterprise-grade:

- A release owner can pass the preflight approval gate but fail final evidence
  assembly.
- Approval identity, role separation, residual-risk decision, and target/global
  scope are not consistently enforced.

Required fix:

- Define `suderra.release-approval.v2` as the single schema consumed by both
  preflight and final evidence assembly.
- Require `approvals[]`, `release_decision`, and optional `residual_risk` in
  preflight validation.
- Enforce at least one release owner for alpha; enforce distinct release owner
  and security/compliance approver for production.
- Make residual-risk expiry, ticket, severity, owner, and target scope
  mandatory when `approved_with_residual_risk` is used.

No easy escape: A top-level `status: approved` is not a release decision.

### P0-7: QEMU v3 release-candidate evidence has a schema but no collector

Impact: The QEMU release-candidate gate cannot be satisfied by the current QEMU
harness alone.

Evidence:

- `validate-qemu-input.py` requires release-candidate guest facts for
  `os_release`, `kernel`, `rootfs`, `network`, `listeners`, `firewall`,
  `firstboot`, and `lockdown`.
- `tests/qemu/qmp-acceptance.py --profile release-candidate` primarily scans
  serial output and fills `guest_facts` with firmware and legacy pass/fail
  data; it does not collect the required semantic guest facts.
- The docs state semantic facts are required, but do not provide an automated
  release-grade collector.

Why this is not enterprise-grade:

- Operators cannot produce compliant QEMU v3 evidence without inventing an
  undocumented procedure.
- Serial-pattern smoke tests are useful, but they do not prove runtime state.

Required fix:

- Add a QEMU v3 collector that executes guest commands through a controlled
  channel and writes `qemu.json`.
- Collect `/etc/os-release`, `uname`, rootfs identity, `systemctl --failed`,
  firstboot idempotence, lockdown transition, `ss -lntup`, and firewall rules.
- Record command output logs with SHA-256 and bind `image_sha256` to the
  preflight Build artifact digest.

No easy escape: Marking semantic checks passed from serial text is not enough.

### P1-1: Security evidence producer is missing

Impact: Security evidence is structurally required but operationally
hand-authored.

Evidence:

- `ci/build-matrix.yml` lists required security scans.
- `validate-release-inputs.py` requires one
  `release-security/<version>/<scan>.json` per scan with tool metadata,
  status, and a non-zero evidence digest.
- No script or workflow produces those files from actual GitHub job outputs,
  SARIF, scan logs, or artifact digests.

Required fix:

- Add `scripts/evidence/collect-security-evidence.py`.
- Inputs: source Build run ID, workflow run IDs for lint/security/Rust jobs,
  SARIF artifacts, scanner JSON, and raw logs.
- Output: signed `release-security/<version>/<scan>.json` plus retained raw
  evidence files under the ingress bundle.
- Fail closed on missing reports, invalid SARIF, truncated logs, critical/high
  findings, skipped jobs, stale tool versions, or source SHA mismatch.

### P1-2: Hardware lab evidence has a validator but no lab collector

Impact: The USB installer and board acceptance path is too manual for repeated
release operation.

Evidence:

- `validate-lab-input.py` requires station identity, fixture identity, device
  identity, full readback hash, board coverage, required checks, RevPi IO check,
  USB negative tests, and write-prevention proof.
- `usb-installer-alpha-validation.md` lists commands and expected evidence, but
  no tool creates a compliant `lab.json` from those logs.

Required fix:

- Add a lab collector CLI that records device identity, UART adapter, storage
  by-id, power supply, firmware, flash transcript, readback, runtime commands,
  and negative-test failure codes.
- The collector must write `lab.json`, copy logs into the bundle, compute
  hashes, and sign the lab bundle.
- Add a dry-run fixture mode so maintainers can test the schema without
  hardware.

### P1-3: Reproducibility evidence is free text

Impact: A fragile text search decides whether reproducibility passed.

Evidence:

- `validate-release-inputs.py` accepts a `.log` if it contains `matched` or
  `passed` and does not contain tokens such as `error`, `failed`, or
  `different digest`.

Required fix:

- Replace the log-only contract with `suderra.reproducibility.v1` JSON.
- Include builder identity, environment, source SHA, Buildroot SHA, matrix
  digest, compared artifact list, expected and actual digests, tool versions,
  and raw log references.
- Keep the raw log as supporting evidence, not as the pass/fail API.

### P1-4: Asset manifests do not cover the final published byte set

Impact: The release has multiple partial manifests but no single complete
public-byte manifest.

Evidence:

- `release-assets.json` is generated before `SHA256SUMS` and before cosign
  signatures/certificates are created.
- `SHA256SUMS` covers non-signature files present at that point, but not the
  generated `.sig` and `.cert` files.
- Evidence archives are not included in either manifest.

Required fix:

- Keep `release-assets.json` for staged pre-signing control if useful.
- Add `release-publication-manifest.json` after all assets, signatures,
  certificates, evidence archives, release notes, and attestations are present.
- Sign and attest the publication manifest.

### P1-5: Governance docs and policy conflict on alpha approvals

Impact: Operators can follow one document and still fail governance validation.

Evidence:

- `docs/dev/branch-protection.md` says alpha `release-publish` may use a single
  release owner approval.
- `ci/github-governance-policy.yml` requires `minimum_reviewers: 2`.
- `validate-governance.py` enforces that policy.

Required fix:

- Make the docs match the policy. If alpha really allows one reviewer, encode a
  tiered governance policy and validate the tier. If not, remove the single
  owner statement.
- For enterprise releases, use two distinct reviewers from the start.

### P1-6: Build logs and warning evidence are not retained as release evidence

Impact: The warning policy can pass in CI, but release evidence does not retain
the logs needed for later audit.

Evidence:

- Build logs are uploaded as workflow artifacts with 30-day retention.
- Final release evidence does not ingest build logs or warning classifier JSON.

Required fix:

- Include warning classifier JSON and relevant build log excerpts in the
  signed evidence ingress or final evidence archive.
- Bind them to `source_run_id`, run attempt, defconfig, and artifact digest.

### P2-1: Customer verification docs do not verify release evidence

Impact: Customers can verify image signatures but not the enterprise release
decision.

Required fix:

- Add evidence archive download and verification to
  `docs/operations/verify-release.md`.
- Provide a single `scripts/verify-release.sh` that checks hash, cosign,
  attestation, evidence archive signature, evidence schema, and target-specific
  paths.

### P2-2: README hardware status can be misread as release support

Impact: The hardware table uses green status markers for platforms that still
have production blockers.

Required fix:

- Split "boots/lab target exists" from "release-supported" and
  "production-supported".

## Code-Doc Mismatches

| Area | Documentation claim | Code/workflow behavior | Required correction |
|---|---|---|---|
| Evidence bundle | Final evidence is uploaded with the signed release bundle. | Publish uploads only evidence JSON globs; evidence tree is not signed as a bundle. | Define and publish signed evidence archives. |
| Evidence ingress | Release-candidate rerun happens after input trees are populated. | No workflow input or artifact ingress populates those trees. | Add signed ingress bundle and workflow input. |
| Governance audit | Governance fails closed if audit log cannot be collected. | Workflows do not provide `SUDERRA_GOVERNANCE_AUDIT_LOG`, so normal collection writes `not_collected`. | Add audit producer/ingress. |
| Byte binding | Release rebuild is bound to preflight Build artifacts. | Build and Release use independently generated CI key material. | Promote exact bytes or bind deterministic key inputs. |
| GA lifecycle | GA must have preflight artifact before tagging. | Preflight release-candidate profile rejects non-prerelease tags. | Add production profile or allow GA candidate preflight. |
| Approvals | Release evidence requires approval and release decision. | Preflight validates only top-level approval fields; final evidence expects nested lists/decision. | Unify approval schema. |
| QEMU v3 | Release-candidate QEMU requires semantic facts. | Current harness does not collect those facts. | Add guest-state collector. |
| Alpha governance | Single owner approval is acceptable for alpha. | Policy requires two environment reviewers. | Align docs or tier policy. |

## Missing Operator Procedures

Release operators still need explicit, copy/pasteable runbooks for:

- Creating and signing the release ingress bundle.
- Exporting GitHub audit logs with the approved token/App and attaching raw
  event digests.
- Producing `release-security/*.json` from actual scan outputs.
- Running the QEMU v3 collector and interpreting failures.
- Running the hardware lab collector, including board serial inventory and
  USB negative-test failure codes.
- Writing approval and release-decision records with role separation.
- Running reproducibility comparison with structured artifact-level output.
- Promoting a technical dry-run to RC without committing private evidence.
- Handling failed RC preflight: which files to update, which evidence to
  regenerate, and when the source Build run must be replaced.
- Handling failed tag workflow after signing but before publish.
- Handling draft release rejection, deletion, supersession, and tag revocation.
- Retaining release evidence for 7 years outside GitHub Actions artifact
  retention.

## Revised Enterprise Plan

### Track 0: Stop-the-line controls

Exit criteria:

- `release-lifecycle.md` states that enterprise release operation is blocked
  until P0 findings are closed.
- Draft/pre-release publication remains internal/lab-only.
- No production-ready or enterprise-ready claim is allowed from technical
  dry-run output.

### Track 1: Portable signed release evidence bundle

Deliverables:

- `scripts/evidence/package-release-evidence.py`
- `release-evidence-<version>.tar.zst`
- `release-evidence-<version>.tar.zst.sig`
- `release-evidence-<version>.tar.zst.cert`
- `release-publication-manifest.json`

Acceptance:

- Downloading only GitHub Release assets is enough to run evidence validation
  with `--check-files`.
- Evidence archive signature verifies with the same OIDC identity as the
  release workflow.
- Publication manifest covers every released byte, including signatures,
  certificates, evidence archive, and release notes.

### Track 2: Signed evidence ingress

Deliverables:

- `suderra.release-ingress.v1` manifest schema.
- Preflight workflow input for ingress artifact run ID or URL plus expected
  digest.
- Ingress validator that expands into `release-lab-input/`,
  `release-security/`, `release-reproducibility/`, `release-approvals/`, and
  `release-governance/`.

Acceptance:

- Release-candidate preflight can run from a clean checkout without committed
  private evidence.
- Tampered, unsigned, wrong-SHA, wrong-run, wrong-version, placeholder, absolute
  path, or path traversal inputs fail closed.

### Track 3: Deterministic byte binding

Deliverables:

- Decision record choosing promotion or rebuild.
- If promotion: release workflow downloads exact preflight-bound Build
  artifacts and stages those bytes.
- If rebuild: immutable key/trust-root/build-input bundle shared by Build and
  Release.

Acceptance:

- USB installer image, payload manifest, payload signature, and target images
  match the preflight binding without disabling digest checks.
- A contract test proves random CI key regeneration cannot pass release binding.

### Track 4: Security evidence producer

Deliverables:

- Collector for actionlint, shellcheck, yamllint, markdownlint, hadolint,
  gitleaks, Rust checks, cargo-deny/audit, trivy, and grype.
- Raw evidence retention under signed ingress.
- SARIF validation and scanner metadata normalization.

Acceptance:

- Every matrix scan has a generated report bound to source SHA, source run ID,
  run attempt, tool version, raw evidence digest, and severity counts.
- Missing/skipped scanners fail preflight.

### Track 5: Governance evidence ingress

Deliverables:

- Audit-log export runbook and schema.
- GitHub App/PAT permission matrix.
- Governance producer workflow or manual collector with signature.

Acceptance:

- Audit snapshot includes lookback window, raw event digest, event count, actor
  filter, and approval review.
- Governance validation can pass in CI without out-of-band undocumented env
  variables.

### Track 6: QEMU v3 release acceptance

Deliverables:

- Guest-state QEMU collector.
- Release-candidate QEMU runbook with required commands and failure triage.
- Contract test for every required QEMU v3 field.

Acceptance:

- `validate-qemu-input.py --require-pass --check-files --profile
  release-candidate` passes using only generated collector output.
- Firstboot idempotence and lockdown transition are real guest checks, not
  inferred serial patterns.

### Track 7: Hardware lab collector

Deliverables:

- Lab collector CLI.
- Fixture mode for CI contract tests.
- Board inventory file for Pi 4, CM4 Lite SD, CM4 eMMC IO board, and RevPi
  Connect 4.

Acceptance:

- Collector output passes `validate-lab-input.py validate-matrix
  --require-pass --check-files`.
- Negative tests include stable `failure_code` and write-prevention proof.
- Every log/check has a digest and is included in signed ingress.

### Track 8: Approval, residual risk, and release decision

Deliverables:

- `suderra.release-approval.v2` schema.
- Validator shared by preflight and final evidence assembly.
- Approval examples for alpha and production.

Acceptance:

- Preflight fails unless final evidence would have non-empty approvals and an
  approved release decision.
- Production requires two distinct approvers.
- Residual risk is time-bound and cannot waive missing required evidence.

### Track 9: Production track

Deliverables:

- `production-candidate` preflight profile.
- Production key/HSM ceremony evidence.
- Signed VEX producer.
- Secure boot, dm-verity, RAUC, rollback, encrypted `/data`, and hardware
  coverage evidence.

Acceptance:

- GA tags can satisfy preflight without using alpha relaxations.
- `production-readiness --tag <version>` and final evidence validation pass
  because controls exist, not because checks were weakened.

## Revised Order Of Execution

1. Close P0-1 through P0-7 before attempting another release-candidate publish.
2. Build QEMU and hardware collectors before expecting operators to produce
   compliant evidence repeatedly.
3. Add security/governance producers before tightening branch/environment gates
   further.
4. Only then run the RC preflight path end to end on a disposable alpha tag.
5. Do not start production-track work until the alpha RC path produces a
   portable signed evidence bundle from a clean checkout.

## 2026-05-19 Implementation Update

Closed locally:

- Release tag binding now requires trusted tag signer fingerprints, emits the
  bound preflight run ID as workflow output, and cross-binds tag metadata,
  release input binding, and ingress manifest metadata before staging bytes.
- Ingress validation can compare against the release input binding and can
  digest the preflight input tree in addition to Build artifact bytes.
- Final release evidence now preserves preflight approval, reproducibility,
  security, QEMU, and lab inputs; `--require-pass --check-files` replays the
  corresponding input validators instead of trusting flattened projections.
- Buildroot effective source ID now binds the applied diff when patches are
  expected; patched release identity without `buildroot_applied_diff_sha256`
  fails.
- Governance collection now requires an explicit governance read token and
  validates release environment deployment policies and required reviewer
  identities.
- Flash acceptance now implies signature verification and validates removable
  status using the resolved top-level by-id disk.

Still blocking enterprise closure:

- Live GitHub admin bootstrap must create the actual branch/ruleset/tag and
  `release-publish` environment controls before release-candidate preflight can
  pass.
- QEMU semantic and hardware lab collector CLIs are still required so operators
  do not hand-author evidence.
- Release OS/rootfs security scanner producer remains separate from source
  scanner CI and must retain scanner DB identity for release-candidate evidence.
