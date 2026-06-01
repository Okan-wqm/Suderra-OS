# Enterprise Release Operator Lifecycle

This runbook describes the operator lifecycle for enterprise release evidence.
Policy remains in these SSOT files:

- `ci/build-matrix.yml`: target, defconfig, artifact, and release catalog.
- `ci/evidence-contract.yml`: evidence, subject graph, signing, runtime, OTA,
  hardware, and retention policy.
- `ci/github-governance-policy.yml`: GitHub branch, check, environment, and
  reviewer governance.

`production_ready=false` remains the expected state until a separate readiness
change proves all production evidence.

## RACI

| Step | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| Freeze source and release inputs | Release operator | Release owner | Build owner | Security owner |
| Evidence ingress | Release operator | Release owner | Lab operator | Security owner |
| Preflight validation | Release operator | Release owner | Build owner | Governance owner |
| Protected signing | Signing operator | Security owner | Release owner | Governance owner |
| Publish or abort | Release owner | Release owner | Security owner | Operators |
| Retention handoff | Evidence custodian | Security owner | Release owner | Governance owner |

## Lifecycle

1. Freeze source at the intended `version`, `source_sha`, and Image Build
   `source_run_id`.
2. For a non-promotable rehearsal, run `rc-evidence-dry-run` and review
   `release-dry-run/<version>/gaps.json`; do not tag from this artifact.
3. Generate the canonical subject plan with
   `scripts/evidence/evidence_contract.py subject-plan`.
4. Ingest `release-inputs`, `release-runtime`, `release-signing`,
   `release-lab-input`, `release-security`, and `release-governance` under the
   same subject identity.
5. Run release input preflight. Production-candidate validation must fail if
   signing manifests, hardware subjects, governance role bindings, or retention
   manifests are missing.
6. Enter the protected signing environment only after preflight passes.
7. Publish only from protected release jobs after publication manifest and
   post-publication verification pass.
8. On abort, preserve failed evidence under retention policy and record the
   superseding run if retried.
9. On supersede, keep the prior subject graph immutable and publish a new
   subject graph for the replacement release.
